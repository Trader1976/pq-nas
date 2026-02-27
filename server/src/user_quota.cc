#include "user_quota.h"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace pqnas {

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

    // Reject absolute paths explicitly (defense in depth)
    if (rel.is_absolute() || rel.has_root_path()) {
        if (err) *err = "absolute path not allowed";
        return false;
    }

    rel = rel.lexically_normal();

    // Validate normalized parts (no '.', '..', empty)
    for (const auto& part : rel) {
        const auto s = part.string();
        if (s.empty() || s == "." || s == "..") {
            if (err) *err = "invalid path";
            return false;
        }
    }

    // Compose
    const std::filesystem::path abs = (user_dir / rel).lexically_normal();

    // Containment check (purely lexical)
    const std::filesystem::path root_norm = user_dir.lexically_normal();
    const std::filesystem::path rel_to_root = abs.lexically_relative(root_norm);

    if (rel_to_root.empty()) {
        if (err) *err = "path escapes user root";
        return false;
    }

    for (const auto& part : rel_to_root) {
        if (part == "..") {
            if (err) *err = "path escapes user root";
            return false;
        }
    }

    *out_abs = abs;
    return true;
}

std::uint64_t file_size_u64_safe(const std::filesystem::path& p) {
    std::error_code ec;
    auto st = std::filesystem::status(p, ec);
    if (ec) return 0;
    if (!std::filesystem::is_regular_file(st)) return 0;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return 0;
    return (std::uint64_t)sz;
}

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

    if (u.storage_state != "allocated") {
        r.ok = false;
        r.error = "storage_unallocated";
        return r;
    }

    std::string path_err;
    if (!resolve_user_path_strict(user_dir, rel_path, &r.abs_path, &path_err)) {
        r.ok = false;
        r.error = "invalid_path";
        return r;
    }

    r.used_bytes = compute_used_bytes_v1(user_dir);
    r.existing_bytes = file_size_u64_safe(r.abs_path);

    // would_used = used - existing + incoming (best-effort)
    r.would_used_bytes = r.used_bytes;
    if (r.existing_bytes <= r.would_used_bytes) {
        r.would_used_bytes -= r.existing_bytes;
    }
    r.would_used_bytes += incoming_bytes;

    // quota_bytes == 0 => deny any positive incoming (fail-closed)
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
