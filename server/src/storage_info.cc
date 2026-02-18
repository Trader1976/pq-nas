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


static bool starts_with_path_prefix(const std::string& path, const std::string& prefix) {
    if (prefix.empty()) return false;
    if (path == prefix) return true;
    if (path.size() < prefix.size()) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    // ensure boundary: "/mnt" matches "/mnt/..." but not "/mnt2"
    if (prefix.back() == '/') return true;
    return path.size() > prefix.size() && path[prefix.size()] == '/';
}

static std::string realpath_str(const std::string& p, std::string* err) {
    char buf[PATH_MAX];
    if (!realpath(p.c_str(), buf)) {
        if (err) *err = std::string("realpath failed: ") + std::strerror(errno);
        return "";
    }
    return std::string(buf);
}

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

struct MountRow {
    std::string mountpoint;
    std::string fstype;
    std::string source;
    std::string options; // "super options" field (comma list)
};

// Parse /proc/self/mountinfo and find the *best* (longest prefix) mountpoint for `path`.
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

        std::istringstream ls(left);
        std::string id, parent, majmin, root, mnt, opts;
        if (!(ls >> id >> parent >> majmin >> root >> mnt >> opts)) continue;

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
        // still return partial info using statfs
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
    out->prjquota_enabled = has_opt(mr.options, "prjquota") || has_opt(mr.options, "pquota");
    return true;
}

} // namespace pqnas
