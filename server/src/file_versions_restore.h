#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace pqnas {

    class UsersRegistry;
    class FileVersionsIndex;

    struct RestoreVersionResult {
        bool ok = false;
        std::string error;
        std::string message;
        std::string detail;

        std::uint64_t bytes = 0;
        std::uint64_t mtime_epoch = 0;
        std::string sha256_hex;
    };

    struct PreserveCurrentVersionParams {
        std::string scope_type;              // "user" | "workspace"
        std::string scope_id;                // fp or workspace_id
        std::filesystem::path scope_root;    // user root or workspace root
        std::string logical_rel_path;        // normalized relative path
        std::filesystem::path live_abs_path; // current live file before restore/overwrite/delete
        std::string event_kind;              // overwrite_preserve | delete_preserve | restore_preserve
        std::string actor_fp;
        UsersRegistry* users = nullptr;
        FileVersionsIndex* file_versions = nullptr;
    };

    bool preserve_current_file_version(const PreserveCurrentVersionParams& p,
                                       std::string* out_version_id,
                                       std::string* err);

    RestoreVersionResult restore_version_blob_to_path(FileVersionsIndex* vix,
                                                      const std::string& scope_type,
                                                      const std::string& scope_id,
                                                      const std::string& logical_rel_path,
                                                      const std::string& version_id,
                                                      const std::filesystem::path& live_abs_path);

    std::string version_actor_display(const std::string& actor_name_snapshot,
                                      const std::string& actor_fp);

} // namespace pqnas