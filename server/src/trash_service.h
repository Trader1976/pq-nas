#pragma once

#include "trash_index.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <functional>

namespace pqnas {

// TrashService is the operational layer above TrashIndex.
//
// Architectural role:
// - TrashIndex persists trash metadata and lifecycle state in sqlite.
// - TrashService coordinates real filesystem actions (move to trash, restore, purge)
//   with those metadata updates.
// - Routes and other higher-level code call this service when they want trash behavior
//   with correct sequencing, rollback handling, and race-safe state transitions.
//
// Separation of concerns:
// - This class does not own authentication/authorization. Routes do that first.
// - This class does not own background scheduling. main.cpp does that.
// - This class does not own concrete live-file indexing policy; instead, optional
//   callbacks are injected for restore reindex/unindex behavior.
class TrashService {
public:
    // The service depends on a TrashIndex instance owned elsewhere.
    //
    // TrashService assumes the index outlives the service and remains usable for the
    // lifetime of any trash operations performed through this object.
    explicit TrashService(TrashIndex* index);

    // Parameters needed to convert one live file/directory into a trash entry.
    //
    // High-level meaning:
    // - scope_type / scope_id define who owns the trash item logically
    // - payload_abs_path is the current live filesystem source
    // - storage_root tells TrashService where the internal .pqnas/trash tree for this
    //   payload should live
    // - original_rel_path preserves the logical location used later for restore
    //
    // Notes:
    // - size_bytes/file_count may be provided by the caller to avoid rescanning.
    // - deleted_epoch and retention_seconds are optional overrides; if omitted, the
    //   service computes them at move time using its default retention policy.
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

    // Result returned after a successful move-to-trash operation.
    //
    // This gives callers the stable trash_id plus the final trash placement and metrics
    // that were actually recorded.
    struct MoveToTrashResult {
        std::string trash_id;
        std::filesystem::path trash_root;
        std::filesystem::path payload_abs_path;
        std::string trash_rel_path;

        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
    };

    // Parameters for restoring one trash entry.
    //
    // restore_abs_path:
    // - requested live target path
    //
    // restore_root_abs:
    // - logical live root used to recompute the restored relative path for metadata/audit
    //
    // rename_if_conflict:
    // - if true, restore may choose a non-destructive conflict name instead of failing
    struct RestoreParams {
        std::string trash_id;
        std::filesystem::path restore_abs_path;
        std::filesystem::path restore_root_abs;
        bool rename_if_conflict = false;
    };

    // Result returned after a successful restore.
    //
    // renamed=true indicates the payload could not be restored to the exact requested
    // path and was instead restored to a generated conflict-safe path.
    struct RestoreResult {
        std::string trash_id;
        std::string item_type;
        std::filesystem::path restored_abs_path;
        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
        bool renamed = false;
    };

    // Parameters for permanently purging one trash entry.
    struct PurgeParams {
        std::string trash_id;
    };

    // Result returned after a successful purge.
    //
    // The service returns the recorded metrics so routes/audit callers do not need to
    // re-fetch the row again after purge completes.
    struct PurgeResult {
        std::string trash_id;
        std::uint64_t size_bytes = 0;
        std::uint64_t file_count = 0;
    };

    // Moves a live payload into the internal trash tree and writes its metadata row.
    //
    // Expected behavior:
    // - validates parameters
    // - chooses deterministic trash location
    // - computes metrics if caller did not provide them
    // - physically moves payload
    // - inserts TrashIndex row
    // - rolls the move back if metadata insert fails
    bool move_to_trash(const MoveToTrashParams& p,
                       MoveToTrashResult* out,
                       std::string* err);

    // Restores a trashed payload back into a live tree.
    //
    // Expected behavior:
    // - claims the row via a race-safe state transition
    // - moves payload out of trash
    // - optionally rebuilds live metadata via restore_reindexer_
    // - finalizes state to "restored"
    // - attempts rollback on failure
    bool restore_from_trash(const RestoreParams& p,
                            RestoreResult* out,
                            std::string* err);

    // Permanently removes a trashed payload from disk and marks its row as purged.
    //
    // Expected behavior:
    // - claims the row via a race-safe state transition
    // - removes payload from disk
    // - finalizes state to "purged"
    // - attempts to roll state back to "trashed" if deletion fails
    bool purge_from_trash(const PurgeParams& p,
                          PurgeResult* out,
                          std::string* err);

    // Optional callback invoked after a payload has been physically restored but before
    // the trash row is finalized as "restored".
    //
    // Purpose:
    // - lets main.cpp or another integrator rebuild live metadata/index state without
    //   making TrashService depend directly on those indexing subsystems
    //
    // Return contract:
    // - true  => reindex succeeded
    // - false => restore should be rolled back
    using RestoreReindexFn = std::function<bool(
        const TrashItemRec&,
        const std::filesystem::path& restored_abs_path,
        const std::string& restored_rel_path,
        std::string* err)>;

    // Optional rollback callback used if restore_reindexer_ already created live metadata
    // but the final restore state transition fails later.
    //
    // This gives the integrator a chance to erase any newly recreated live metadata so
    // disk state and index state do not drift apart.
    using RestoreUnindexFn = std::function<void(
        const TrashItemRec&,
        const std::string& restored_rel_path)>;

    // Installs the restore metadata rebuild callback.
    void set_restore_reindexer(RestoreReindexFn fn);

    // Installs the restore metadata rollback callback.
    void set_restore_unindexer(RestoreUnindexFn fn);

    // Infers the storage root by walking upward from a concrete payload path using the
    // number of path components present in the logical relative path.
    //
    // Useful when callers know:
    // - absolute live payload path
    // - logical relative path
    //
    // but do not already have:
    // - concrete storage root needed to place the internal trash tree
    static bool infer_storage_root_for_logical_path(const std::filesystem::path& payload_abs_path,
                                                    const std::string& logical_rel_path,
                                                    std::filesystem::path* out_storage_root,
                                                    std::string* err);

    // Computes file count and byte size for either a single file or a whole directory tree.
    //
    // This is used when delete/trash callers did not already compute metrics and the
    // service must discover them before writing the trash row.
    static bool scan_payload_tree(const std::filesystem::path& abs_path,
                                  std::uint64_t* out_file_count,
                                  std::uint64_t* out_size_bytes,
                                  std::string* err);

private:
    // Shared metadata store used by all trash operations.
    TrashIndex* index_ = nullptr;

    // Optional integration hooks for rebuilding/removing live metadata around restore.
    RestoreReindexFn restore_reindexer_;
    RestoreUnindexFn restore_unindexer_;
};

} // namespace pqnas