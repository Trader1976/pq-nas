#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

#include "users_registry.h"

namespace pqnas {

    struct QuotaCheckResult {
        bool ok = false;
        std::string error;            // "" or reason like "invalid_path"
        std::filesystem::path abs_path;

        // used_bytes is the effective quota usage used for decisions.
        // live_bytes is the recursive user-root content scan after excluding
        // internal metadata such as .pqnas_activity.
        // extra_used_bytes is externally provided quota usage, currently active Trash.
        std::uint64_t used_bytes = 0;
        std::uint64_t live_bytes = 0;
        std::uint64_t extra_used_bytes = 0;
        std::uint64_t quota_bytes = 0;
        std::uint64_t incoming_bytes = 0;

        std::uint64_t existing_bytes = 0;
        std::uint64_t would_used_bytes = 0;
    };

    // Strict relative-path validation (no traversal). Returns false with err.
    bool resolve_user_path_strict(const std::filesystem::path& user_dir,
                                  const std::string& rel_path,
                                  std::filesystem::path* out_abs,
                                  std::string* err);

    using QuotaExtraUsedBytesProvider =
        std::function<bool(const std::string& scope_type,
                           const std::string& scope_id,
                           std::uint64_t* out_bytes,
                           std::string* err)>;

    // Installs an optional provider for quota-accounted bytes outside the live
    // user directory, for example active Trash payloads.
    void set_quota_extra_used_bytes_provider(QuotaExtraUsedBytesProvider fn);

    // v1 used-bytes: recursive scan of user directory
    std::uint64_t compute_used_bytes_v1(const std::filesystem::path& user_dir);

    // Safe file size helper (0 if missing or not regular)
    std::uint64_t file_size_u64_safe(const std::filesystem::path& p);

    // Main helper: checks storage_state + quota and computes would_used.
    // If overwrite is allowed, it subtracts existing file size (best-effort).
    QuotaCheckResult quota_check_for_upload_v1(const UsersRegistry& users,
                                               const std::string& fp_hex,
                                               const std::filesystem::path& user_dir,
                                               const std::string& rel_path,
                                               std::uint64_t incoming_bytes);

} // namespace pqnas
