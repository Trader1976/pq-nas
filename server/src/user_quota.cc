#include "user_quota.h"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace pqnas {

/*
================================================================================
User Quota + Path Safety — Architectural Overview
================================================================================

This module provides two core capabilities used by PQ-NAS file operations:

  1) Path resolution and containment checks:
       resolve_user_path_strict(user_dir, rel_path) -> absolute path within user_dir

  2) A "v1" quota check model for uploads:
       quota_check_for_upload_v1(...) -> decision + accounting fields

The overarching goals are:
  - Prevent path traversal and unsafe path usage (../, absolute paths, drive letters).
  - Provide a quota enforcement mechanism that works even when the underlying FS
    does not support native quotas (Btrfs qgroups, XFS/ext4 project quota, etc.).
  - Return enough metadata to produce good UI/UX error messages and diagnostics
    ("storage not allocated", "quota exceeded", "invalid path").

Threat model / security properties
----------------------------------
Path handling is a common source of vulnerabilities. This module enforces:
  - Relative paths only (no absolute, no roots, no Windows drive letters)
  - No "." or ".." components (before and after normalization)
  - Lexical containment: the resolved path must remain under user_dir after
    normalization and lexical checks.

Important limitation:
  - Containment is "lexical", not "filesystem realpath-based". This means
    symlinks inside user_dir could still point outside user_dir. Whether that
    matters depends on how the rest of PQ-NAS handles symlinks.
      * If your file APIs allow following symlinks during read/write, you may
        want an additional symlink-safe resolution step (openat2 with RESOLVE_*,
        or a "walk and lstat" approach).
      * If PQ-NAS disallows symlinks for user storage, lexical containment is
        typically sufficient.

Quota model v1
--------------
This is a best-effort "scan-and-sum" quota model:
  - used_bytes = recursive sum of file sizes in user_dir
  - existing_bytes = size of the target file if it already exists
  - would_used = used_bytes - existing_bytes + incoming_bytes

This approximates post-upload usage under typical conditions.

Limitations / tradeoffs:
  - Performance: recursive directory scans can be expensive for large trees.
  - Accuracy: file size sums do not reflect filesystem overhead, sparse files,
    reflinks/dedup (Btrfs), compression, or snapshots.
  - Race conditions: concurrently modified trees can change during scanning.
    (Best-effort checks are common; enforce again at write time if possible.)

Policy semantics
----------------
  - If user.storage_state != "allocated" -> fail with storage_unallocated
  - If quota_bytes == 0 -> deny any positive upload (fail-closed)
  - If would_used_bytes > quota_bytes -> quota_exceeded

Versioning note:
  - Functions are suffixed with _v1 to allow future improvements without
    breaking behavior (e.g., native quotas, incremental accounting, caching).
================================================================================
*/


//------------------------------------------------------------------------------
// Relative path policy gate
//------------------------------------------------------------------------------

/*
is_safe_rel_path()
  - Fast, conservative validation for user-provided relative paths.
  - This is a "policy gate": it rejects many risky patterns early.
  - It complements the stricter resolve_user_path_strict() containment logic.

Checks performed:
  - Non-empty, reasonable max length
  - No embedded NUL
  - No backslashes (Windows-style separators)
  - No drive letters (e.g., "C:")
  - Not absolute according to std::filesystem::path
  - No empty, ".", or ".." path components
*/
static bool is_safe_rel_path(const std::string& rel_in) {
    if (rel_in.empty()) return false;
    if (rel_in.size() > 4096) return false;
    if (rel_in.find('\0') != std::string::npos) return false;

    // Disallow Windows-style drive letters and backslashes
    if (rel_in.find('\\') != std::string::npos) return false;
    if (rel_in.size() >= 2 && std::isalpha((unsigned char)rel_in[0]) && rel_in[1] == ':') return false;

    std::filesystem::path p(rel_in);
    if (p.is_absolute()) return false;

    for (const auto& part : p) {
        const auto s = part.string();
        if (s == "." || s == ".." || s.empty()) return false;
    }
    return true;
}


//------------------------------------------------------------------------------
// Strict path resolution + lexical containment
//------------------------------------------------------------------------------

/*
resolve_user_path_strict(user_dir, rel_path, out_abs, err)
  - Converts a user-provided relative path into an absolute path inside user_dir.
  - Enforces multiple layers of defenses:
      1) policy gate (is_safe_rel_path)
      2) explicit checks for absolute/rooted paths
      3) lexical normalization
      4) containment verification relative to user_dir

Design choice: lexical containment
  - We use lexically_normal() and lexically_relative() to avoid filesystem I/O.
  - This is fast and deterministic.
  - BUT it does not protect against symlink escapes if the caller later follows
    symlinks. See architectural overview for discussion.
*/
bool resolve_user_path_strict(const std::filesystem::path& user_dir,
                             const std::string& rel_path,
                             std::filesystem::path* out_abs,
                             std::string* err) {
    if (err) err->clear();
    if (!out_abs) {
        if (err) *err = "null out_abs";
        return false;
    }

    // basic input checks
    if (rel_path.empty()) {
        if (err) *err = "empty path";
        return false;
    }
    if (!is_safe_rel_path(rel_path)) { // keep your existing policy gate
        if (err) *err = "invalid path";
        return false;
    }

    std::filesystem::path rel(rel_path);

    // Reject absolute/rooted paths explicitly (defense in depth)
    if (rel.is_absolute() || rel.has_root_path()) {
        if (err) *err = "absolute path not allowed";
        return false;
    }

    // Normalize (collapses redundant separators, removes "." segments, etc.)
    rel = rel.lexically_normal();

    // Validate normalized parts (no '.', '..', empty)
    for (const auto& part : rel) {
        const auto s = part.string();
        if (s.empty() || s == "." || s == "..") {
            if (err) *err = "invalid path";
            return false;
        }
    }

    // Compose absolute path under user_dir and normalize.
    const std::filesystem::path abs = (user_dir / rel).lexically_normal();

    // Containment check (purely lexical):
    // Ensure abs is within user_dir by computing its relative path to user_dir.
    const std::filesystem::path root_norm = user_dir.lexically_normal();
    const std::filesystem::path rel_to_root = abs.lexically_relative(root_norm);

    if (rel_to_root.empty()) {
        if (err) *err = "path escapes user root";
        return false;
    }

    // If rel_to_root contains ".." segments, abs escapes user_dir.
    for (const auto& part : rel_to_root) {
        if (part == "..") {
            if (err) *err = "path escapes user root";
            return false;
        }
    }

    *out_abs = abs;
    return true;
}


//------------------------------------------------------------------------------
// Filesystem helpers
//------------------------------------------------------------------------------

/*
file_size_u64_safe()
  - Returns file size for regular files, otherwise 0.
  - Uses error_code overloads to avoid throwing exceptions.
  - Used to account for overwrites:
      existing_bytes = size(target_file) if it already exists
*/
std::uint64_t file_size_u64_safe(const std::filesystem::path& p) {
    std::error_code ec;
    auto st = std::filesystem::status(p, ec);
    if (ec) return 0;
    if (!std::filesystem::is_regular_file(st)) return 0;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return 0;
    return (std::uint64_t)sz;
}

/*
compute_used_bytes_v1()
  - Walks the user directory recursively and sums file sizes.
  - This is the simplest possible quota accounting method.

Tradeoffs:
  - Can be expensive for large trees.
  - Not snapshot-aware (Btrfs snapshots may consume space not reflected here).
  - Does not account for sparse/compressed/reflinked data.
  - Not race-free (files can change during scan), but sufficient for "best-effort"
    preflight checks.
*/
std::uint64_t compute_used_bytes_v1(const std::filesystem::path& user_dir) {
    std::uint64_t total = 0;
    std::error_code ec;

    if (!std::filesystem::exists(user_dir, ec)) return 0;
    ec.clear();

    for (std::filesystem::recursive_directory_iterator it(user_dir, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        if (ec) break;

        std::error_code ec2;
        if (it->is_regular_file(ec2) && !ec2) {
            std::error_code ec3;
            auto sz = it->file_size(ec3);
            if (!ec3) total += (std::uint64_t)sz;
        }
    }
    return total;
}


//------------------------------------------------------------------------------
// Quota check for uploads (v1)
//------------------------------------------------------------------------------

/*
QuotaCheckResult is intended to be UI-friendly:
  - ok: final decision
  - error: machine-readable reason
  - fields: used_bytes, quota_bytes, would_used_bytes, existing_bytes, abs_path, etc.

quota_check_for_upload_v1()
  - Used as a preflight check before accepting uploads.
  - Produces deterministic results for a given snapshot of the filesystem,
    but note the inherent race between check and write (TOCTOU).

Error codes used:
  - "user_missing"
  - "storage_unallocated"
  - "invalid_path"
  - "quota_exceeded"

Semantics:
  - would_used = used - existing + incoming
    This handles overwrites "fairly" by not double-counting existing content.
  - quota_bytes == 0 denies all positive uploads (fail-closed).
*/
QuotaCheckResult quota_check_for_upload_v1(const UsersRegistry& users,
                                           const std::string& fp_hex,
                                           const std::filesystem::path& user_dir,
                                           const std::string& rel_path,
                                           std::uint64_t incoming_bytes) {
    QuotaCheckResult r;
    r.incoming_bytes = incoming_bytes;

    // Load user record
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value()) {
        r.ok = false;
        r.error = "user_missing";
        return r;
    }
    const auto& u = *uopt;

    r.quota_bytes = u.quota_bytes;

    // Gate: user must have storage allocation configured.
    if (u.storage_state != "allocated") {
        r.ok = false;
        r.error = "storage_unallocated";
        return r;
    }

    // Resolve relative path strictly to avoid traversal.
    std::string path_err;
    if (!resolve_user_path_strict(user_dir, rel_path, &r.abs_path, &path_err)) {
        r.ok = false;
        r.error = "invalid_path";
        return r;
    }

    // Best-effort used-bytes computation
    r.used_bytes = compute_used_bytes_v1(user_dir);

    // If overwriting an existing file, subtract it from used before adding incoming.
    r.existing_bytes = file_size_u64_safe(r.abs_path);

    // would_used = used - existing + incoming (best-effort)
    r.would_used_bytes = r.used_bytes;
    if (r.existing_bytes <= r.would_used_bytes) {
        r.would_used_bytes -= r.existing_bytes;
    }
    r.would_used_bytes += incoming_bytes;

    // quota_bytes == 0 => deny any positive incoming (fail-closed)
    // This is an explicit policy choice: "no quota configured" does NOT mean unlimited.
    if (r.quota_bytes == 0) {
        r.ok = (incoming_bytes == 0);
        if (!r.ok) r.error = "quota_exceeded";
        return r;
    }

    if (r.would_used_bytes > r.quota_bytes) {
        r.ok = false;
        r.error = "quota_exceeded";
        return r;
    }

    r.ok = true;
    r.error.clear();
    return r;
}

} // namespace pqnas