#include "storage_info.h"

#include <sys/statfs.h>
#include <unistd.h>
#include <limits.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace pqnas {

/*
================================================================================
Storage Info — Architectural Overview
================================================================================

Purpose
-------
This module provides a Linux-specific "storage introspection" utility that
returns metadata about the filesystem backing a given path:

  - canonicalized root path (realpath)
  - filesystem type (fstype)
  - mountpoint (best match from /proc/self/mountinfo)
  - mount source (device, bind source, etc., as reported by mountinfo)
  - mount super options (comma-separated)
  - whether project quotas appear enabled (prjquota/pquota)

Why this exists
---------------
PQ-NAS needs to make decisions and show UI hints based on filesystem capabilities:
  - Btrfs vs ext4 vs xfs vs zfs (feature availability / warnings)
  - quota support (especially project quota / prjquota)
  - correct mountpoint identification (for status pages and storage manager)
  - safer operational checks (e.g., “this path belongs to mount X”)

Design constraints
------------------
  - No privileged operations: everything is read-only, using statfs() and /proc.
  - Best-effort reporting: we try to return useful information even if some sources
    are unavailable. In particular:
      * if /proc/self/mountinfo cannot be read or parsed, we still return partial
        info (root + fstype via statfs).
  - Linux focus: /proc/self/mountinfo parsing is Linux-specific, and so are the
    magic constants in fstype_from_statfs().

Threat model / security notes
-----------------------------
  - Input paths are resolved with realpath() to remove "..", symlinks, and provide
    canonical paths for mount matching.
  - We do not execute shell commands or parse external utilities, reducing attack
    surface.
  - /proc/self/mountinfo is treated as a trusted kernel-provided view of mounts.

Correctness notes
-----------------
  - Mount selection uses "longest matching mountpoint prefix" so that nested mounts
    (e.g., /srv on /, /srv/pqnas-data on another FS) are handled correctly.
  - mountinfo mountpoint strings may include escape sequences (e.g., \040). This
    implementation currently ignores unescaping, which may cause mismatches when
    mountpoints contain spaces or unusual characters. (Generally rare for server
    mountpoints, but worth noting.)

Future improvements
-------------------
  - Unescape mountinfo mountpoint fields (\040 etc.) before comparing.
  - Option parsing: mountinfo has both "mount options" and "super options"; we only
    store the super options field. If you need full fidelity, store both.
  - Consider detecting quota support more robustly (filesystem-specific checks,
    xfs quota state, ext4 project quota state via ioctl, etc.).
================================================================================
*/


//------------------------------------------------------------------------------
// Path prefix helper
//------------------------------------------------------------------------------

/*
starts_with_path_prefix(path, prefix)
  - Path-aware prefix check:
      "/mnt" matches "/mnt" and "/mnt/xyz"
      but NOT "/mnt2"
  - This is used for mountpoint matching when selecting the best mount for a path.
*/
static bool starts_with_path_prefix(const std::string& path, const std::string& prefix) {
    if (prefix.empty()) return false;
    if (path == prefix) return true;
    if (path.size() < prefix.size()) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    // ensure boundary: "/mnt" matches "/mnt/..." but not "/mnt2"
    if (prefix.back() == '/') return true;
    return path.size() > prefix.size() && path[prefix.size()] == '/';
}


//------------------------------------------------------------------------------
// Canonicalization helper
//------------------------------------------------------------------------------

/*
realpath_str()
  - Canonicalizes a path using realpath(3).
  - Resolves:
      * symlinks
      * ".." segments
      * "." segments
  - Ensures downstream mount matching is stable and not fooled by different
    spellings of the same path.
*/
static std::string realpath_str(const std::string& p, std::string* err) {
    char buf[PATH_MAX];
    if (!realpath(p.c_str(), buf)) {
        if (err) *err = std::string("realpath failed: ") + std::strerror(errno);
        return "";
    }
    return std::string(buf);
}


//------------------------------------------------------------------------------
// Filesystem labeling
//------------------------------------------------------------------------------

/*
fstype_from_statfs()
  - Provides a best-effort human label for a filesystem given statfs::f_type.
  - These are common Linux "magic numbers".
  - Not exhaustive; unknown values are returned as "unknown".
  - Note: This is only used as a fallback label if mountinfo parsing fails or
    if mountinfo yields an empty fstype.
*/
static std::string fstype_from_statfs(long f_type) {
    // Common Linux magic numbers
    // (values are stable; this is a best-effort label)
    switch ((unsigned long)f_type) {
        case 0xEF53: return "ext2/3/4";
        case 0x58465342: return "xfs";
        case 0x9123683E: return "btrfs";
        case 0x2FC12FC1: return "zfs";
        case 0x01021994: return "tmpfs";
        case 0x6969: return "nfs";
        default: break;
    }
    return "unknown";
}


//------------------------------------------------------------------------------
// Mount table parsing (/proc/self/mountinfo)
//------------------------------------------------------------------------------

/*
MountRow is the normalized subset of mountinfo fields PQ-NAS currently cares about.

Terminology:
  - mountpoint: where the filesystem is mounted (e.g., "/srv/pqnas-data")
  - fstype: filesystem type string (e.g., "btrfs", "ext4", "xfs")
  - source: usually a device path or remote source (e.g., "/dev/sda1", "server:/export")
  - options: "super options" field from mountinfo (often includes quota flags)
*/
struct MountRow {
    std::string mountpoint;
    std::string fstype;
    std::string source;
    std::string options; // "super options" field (comma list)
};

/*
find_mount_for_path()
  - Parses /proc/self/mountinfo and finds the best matching mountpoint for `path`.
  - "Best" means: longest mountpoint path that is a prefix of `path`.
    This correctly handles nested mounts.

Behavior:
  - Returns false on I/O or if no mountpoint matches.
  - Writes a best MountRow to out on success.
  - Leaves higher-level caller free to decide whether failure is fatal.
*/
static bool find_mount_for_path(const std::string& path, MountRow* out, std::string* err) {
    std::ifstream f("/proc/self/mountinfo");
    if (!f.good()) {
        if (err) *err = "cannot open /proc/self/mountinfo";
        return false;
    }

    MountRow best;
    bool have = false;

    std::string line;
    while (std::getline(f, line)) {
        // mountinfo format:
        // id parent major:minor root mountpoint options optional_fields... - fstype source super_options
        // We care about mountpoint + fstype + source + super_options.
        auto dash = line.find(" - ");
        if (dash == std::string::npos) continue;

        std::string left = line.substr(0, dash);
        std::string right = line.substr(dash + 3);

        // Parse the left side up to the mountpoint and options.
        // NOTE: mountpoint may contain escape sequences, and fields are space-separated.
        std::istringstream ls(left);
        std::string id, parent, majmin, root, mnt, opts;
        if (!(ls >> id >> parent >> majmin >> root >> mnt >> opts)) continue;

        // Parse the right side: fstype, source, superopts.
        std::istringstream rs(right);
        std::string fstype, source, superopts;
        if (!(rs >> fstype >> source >> superopts)) continue;

        // Some mountpoints may contain escape sequences like \040 (space). We ignore for now.
        // Compare using prefix rules; choose the longest matching mountpoint.
        if (!starts_with_path_prefix(path, mnt)) continue;

        if (!have || mnt.size() > best.mountpoint.size()) {
            best.mountpoint = mnt;
            best.fstype = fstype;
            best.source = source;
            best.options = superopts;
            have = true;
        }
    }

    if (!have) {
        if (err) *err = "no mountpoint matched for path";
        return false;
    }

    if (out) *out = best;
    return true;
}


//------------------------------------------------------------------------------
// Mount options parsing (CSV)
//------------------------------------------------------------------------------

/*
has_opt()
  - Checks a comma-separated option list for an exact option name (case-insensitive).
  - This is used to detect quota flags such as:
      - "prjquota" (common in xfs/ext4 contexts)
      - "pquota"   (older/alternate spelling sometimes used)
  - We do delimiter checks to avoid false positives (e.g., "foo" matching "foobar").
*/
static bool has_opt(const std::string& opts_csv, const char* needle) {
    std::string s = opts_csv;
    // lowercase compare
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    std::string n = needle;
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    // simple contains with delimiter safety
    // match ",prjquota," or at edges
    auto pos = s.find(n);
    while (pos != std::string::npos) {
        bool left_ok = (pos == 0) || (s[pos - 1] == ',');
        bool right_ok = (pos + n.size() == s.size()) || (s[pos + n.size()] == ',');
        if (left_ok && right_ok) return true;
        pos = s.find(n, pos + 1);
    }
    return false;
}


//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

/*
get_storage_info(root_in, out, err)
  - Main entry point used by PQ-NAS to introspect storage for a path.

Algorithm:
  1) Canonicalize input path via realpath().
  2) Call statfs() to obtain a filesystem type magic number (always available on Linux).
  3) Parse /proc/self/mountinfo to identify mountpoint + fstype string + source + super options.
  4) Determine prjquota_enabled by scanning super options for "prjquota" or "pquota".

Error handling strategy:
  - If realpath() or statfs() fails: return false (cannot provide meaningful info).
  - If mountinfo parsing fails: return true but provide partial info:
        * root canonical path
        * fstype via statfs magic label
        * other fields empty
    and set err (if provided) to explain the partial failure.

Why partial success matters:
  - Many parts of the UI/logic can still show useful information (e.g., fstype)
    even if mountpoint/source cannot be resolved (containerized environments, very
    restricted /proc, etc.).

Quota detection limitations:
  - This is a *hint*, not a proof. Some filesystems may support quotas without
    advertising these flags in super options, or may require additional state.
  - For high-stakes enforcement, quotas should be validated using filesystem-
    specific checks and actual quota operations.
*/
bool get_storage_info(const std::string& root_in, StorageInfo* out, std::string* err) {
    if (!out) { if (err) *err = "out is null"; return false; }

    std::string rp = realpath_str(root_in, err);
    if (rp.empty()) return false;

    // statfs label
    struct statfs sfs;
    if (statfs(rp.c_str(), &sfs) != 0) {
        if (err) *err = std::string("statfs failed: ") + std::strerror(errno);
        return false;
    }

    MountRow mr;
    std::string mErr;
    if (!find_mount_for_path(rp, &mr, &mErr)) {
        // Still return partial info using statfs.
        // This is intentionally not fatal to keep UI and diagnostics useful.
        out->root = rp;
        out->fstype = fstype_from_statfs(sfs.f_type);
        out->mountpoint = "";
        out->source = "";
        out->options = "";
        out->prjquota_enabled = false;
        if (err) *err = mErr;
        return true; // partial ok
    }

    out->root = rp;
    out->mountpoint = mr.mountpoint;
    out->source = mr.source;
    out->fstype = mr.fstype.empty() ? fstype_from_statfs(sfs.f_type) : mr.fstype;
    out->options = mr.options;

    // Heuristic: check whether project quotas appear enabled on the mount.
    // Different filesystems/distributions may expose different flags.
    out->prjquota_enabled = has_opt(mr.options, "prjquota") || has_opt(mr.options, "pquota");
    return true;
}

} // namespace pqnas