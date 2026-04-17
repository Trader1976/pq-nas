#pragma once

#include "trash_index.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <functional>

namespace pqnas {

class TrashService {
public:
    explicit TrashService(TrashIndex* index);

    struct MoveToTrashParams {
        std::string scope_type;       // "user" | "workspace"
        std::string scope_id;         // fp_hex | workspace_id
        std::string deleted_by_fp;
        std::string origin_app;       // "filemgr" | "photogallery" | ...

        std::string item_type;        // "file" | "dir"
        std::string original_rel_path;

        std::filesystem::path payload_abs_path; // current live source path
        std::filesystem::path storage_root;     // concrete data/landing root where trash should live

        std::string source_pool;
        std::string source_tier_state;

        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;

        std::int64_t deleted_epoch = 0;         // 0 => now
        std::int64_t retention_seconds = 0;     // 0 => default
    };

    struct MoveToTrashResult {
        std::string trash_id;
        std::filesystem::path trash_root;
        std::filesystem::path payload_abs_path;
        std::string trash_rel_path;

        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
    };

    struct RestoreParams {
        std::string trash_id;
        std::filesystem::path restore_abs_path;
        std::filesystem::path restore_root_abs;
        bool rename_if_conflict = false;
    };

    struct RestoreResult {
        std::string trash_id;
        std::string item_type;
        std::filesystem::path restored_abs_path;
        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
        bool renamed = false;
    };

    struct PurgeParams {
        std::string trash_id;
    };

    struct PurgeResult {
        std::string trash_id;
        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
    };

    bool move_to_trash(const MoveToTrashParams& p,
                       MoveToTrashResult* out,
                       std::string* err);

    bool restore_from_trash(const RestoreParams& p,
                            RestoreResult* out,
                            std::string* err);

    bool purge_from_trash(const PurgeParams& p,
                          PurgeResult* out,
                          std::string* err);

    using RestoreReindexFn = std::function<bool(
        const TrashItemRec&,
        const std::filesystem::path& restored_abs_path,
        const std::string& restored_rel_path,
        std::string* err)>;

    using RestoreUnindexFn = std::function<void(
        const TrashItemRec&,
        const std::string& restored_rel_path)>;

    void set_restore_reindexer(RestoreReindexFn fn);
    void set_restore_unindexer(RestoreUnindexFn fn);



    static bool infer_storage_root_for_logical_path(const std::filesystem::path& payload_abs_path,
                                                    const std::string& logical_rel_path,
                                                    std::filesystem::path* out_storage_root,
                                                    std::string* err);

    static bool scan_payload_tree(const std::filesystem::path& abs_path,
                                  std::uint64_t* out_file_count,
                                  std::uint64_t* out_size_bytes,
                                  std::string* err);

private:
    TrashIndex* index_ = nullptr;
    RestoreReindexFn restore_reindexer_;
    RestoreUnindexFn restore_unindexer_;
};

} // namespace pqnas