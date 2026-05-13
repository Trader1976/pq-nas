#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <optional>

struct sqlite3;

namespace pqnas {

class UsersRegistry;

struct FileVersionRec {
    std::string version_id;

    std::string scope_type;        // "user" | "workspace"
    std::string scope_id;          // user fp or workspace_id
    std::string logical_rel_path;  // normalized logical file path inside the scope

    std::string event_kind;        // "overwrite_preserve" | "delete_preserve"
    std::string created_at;        // ISO-8601 UTC
    std::int64_t created_epoch = 0;

    std::string actor_fp;
    std::string actor_name_snapshot;

    std::uint64_t bytes = 0;
    std::string sha256_hex;

    std::string source_physical_path; // live file path at preserve time
    std::string blob_rel_path;        // relative to scope_root
    bool is_deleted_event = false;
};

struct PreserveLiveFileVersionParams {
    std::string scope_type;        // "user" | "workspace"
    std::string scope_id;          // user fp or workspace_id
    std::filesystem::path scope_root;

    std::string logical_rel_path;  // normalized logical path
    std::filesystem::path live_abs_path;

    std::string event_kind;        // "overwrite_preserve" | "delete_preserve"
    std::string actor_fp;

    const UsersRegistry* users = nullptr; // optional, for actor name snapshot
};


struct FileVersionFlagRec {
    std::string version_id;
    std::string scope_type;
    std::string scope_id;
    std::string logical_rel_path;

    std::string actor_fp;
    std::string actor_name_snapshot;
    std::string note;

    std::string created_at;
    std::int64_t created_epoch = 0;
};

struct FileVersionFlagSummary {
    std::uint64_t flag_count = 0;
    bool flagged_by_me = false;
    std::vector<FileVersionFlagRec> flags;
};

struct FileVersionsScopeStats {
    std::uint64_t versions_count = 0;
    std::uint64_t versions_bytes = 0;
};

struct FileVersionsDeleteResult {
    std::uint64_t versions_deleted = 0;
    std::uint64_t bytes_deleted = 0;
    std::uint64_t blobs_missing = 0;
};


class FileVersionsIndex {
public:
    explicit FileVersionsIndex(const std::filesystem::path& db_path);
    ~FileVersionsIndex();

    FileVersionsIndex(const FileVersionsIndex&) = delete;
    FileVersionsIndex& operator=(const FileVersionsIndex&) = delete;
    std::optional<FileVersionRec> get_by_version_id(const std::string& version_id,
                                                    std::string* err);

    bool insert(const FileVersionRec& rec, std::string* err);
    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool preserve_live_file_version(const PreserveLiveFileVersionParams& params,
                                    FileVersionRec* out,
                                    std::string* err);

    std::vector<FileVersionRec> list_versions_for_path(const std::string& scope_type,
                                                       const std::string& scope_id,
                                                       const std::string& logical_rel_path,
                                                       std::size_t limit,
                                                       std::string* err);


    bool flag_version(const std::string& scope_type,
                      const std::string& scope_id,
                      const std::string& logical_rel_path,
                      const std::string& version_id,
                      const std::string& actor_fp,
                      const UsersRegistry* users,
                      const std::string& note,
                      std::string* err);

    bool unflag_version(const std::string& scope_type,
                        const std::string& scope_id,
                        const std::string& logical_rel_path,
                        const std::string& version_id,
                        const std::string& actor_fp,
                        std::string* err);

    FileVersionFlagSummary flags_for_version(const std::string& scope_type,
                                             const std::string& scope_id,
                                             const std::string& logical_rel_path,
                                             const std::string& version_id,
                                             const std::string& viewer_fp,
                                             std::string* err);

    bool scope_stats(const std::string& scope_type,
                     const std::string& scope_id,
                     FileVersionsScopeStats* out,
                     std::string* err);

    bool delete_versions_for_scope_path(const std::string& scope_type,
                                        const std::string& scope_id,
                                        const std::filesystem::path& scope_root,
                                        const std::string& logical_rel_path,
                                        bool recursive,
                                        FileVersionsDeleteResult* out,
                                        std::string* err);

    bool delete_single_version(const std::string& scope_type,
                               const std::string& scope_id,
                               const std::filesystem::path& scope_root,
                               const std::string& logical_rel_path,
                               const std::string& version_id,
                               FileVersionsDeleteResult* out,
                               std::string* err);


    static std::filesystem::path version_blob_abs_path(const std::filesystem::path& scope_root,
                                                       const std::string& blob_rel_path);

    static std::string truncate_fingerprint_for_display(const std::string& fp);
    static std::string resolve_actor_display_name(const UsersRegistry* users,
                                                  const std::string& actor_fp,
                                                  const std::string& actor_name_snapshot);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
};

} // namespace pqnas