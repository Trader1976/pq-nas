#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct TrashItemRec {
    std::string trash_id;

    std::string scope_type;   // "user" | "workspace"
    std::string scope_id;     // fp_hex | workspace_id

    std::string deleted_by_fp;
    std::string origin_app;   // "filemgr" | "photogallery" | ...

    std::string item_type;    // "file" | "dir"
    std::string original_rel_path;

    std::string storage_root;         // concrete data/landing root where trash lives
    std::string trash_rel_path;       // relative path under storage_root/.pqnas/trash/...
    std::string payload_physical_path;

    std::string source_pool;
    std::string source_tier_state;    // "landing" | "migrating" | "capacity" | ""

    std::uint64_t size_bytes = 0;
    std::uint64_t file_count = 0;

    std::int64_t deleted_epoch = 0;
    std::int64_t purge_after_epoch = 0;

    std::string restore_status;       // "trashed" | "restored" | "purged"
    std::int64_t status_updated_epoch = 0;
};

class TrashIndex {
public:
    explicit TrashIndex(const std::filesystem::path& db_path);
    ~TrashIndex();

    TrashIndex(const TrashIndex&) = delete;
    TrashIndex& operator=(const TrashIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool insert(const TrashItemRec& rec, std::string* err);

    std::optional<TrashItemRec> get(const std::string& trash_id,
                                    std::string* err);

    std::vector<TrashItemRec> list_scope(const std::string& scope_type,
                                         const std::string& scope_id,
                                         bool include_inactive,
                                         std::size_t limit,
                                         std::string* err);

    std::vector<TrashItemRec> list_expired(std::int64_t now_epoch,
                                           std::size_t limit,
                                           std::string* err);

    bool set_restore_status(const std::string& trash_id,
                            const std::string& restore_status,
                            std::int64_t status_updated_epoch,
                            std::string* err);

    bool erase(const std::string& trash_id,
               std::string* err);

    bool sum_active_scope_bytes(const std::string& scope_type,
                                const std::string& scope_id,
                                std::uint64_t* out_bytes,
                                std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
};

} // namespace pqnas