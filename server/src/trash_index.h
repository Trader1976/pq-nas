#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

// In-memory representation of one trash table row.
//
// Architectural role:
// - This struct is the stable metadata envelope for one trashed item.
// - It is shared across the index layer, service layer, route layer, and background
//   cleanup worker, so it intentionally contains both user-facing metadata and
//   operational metadata needed to restore/purge safely.
//
// Design notes:
// - One row represents one logical trash entry, not an individual file inside a
//   directory tree. For directories, size/file_count summarize the whole subtree.
// - The struct stores both logical identity (scope, original_rel_path) and concrete
//   storage placement (storage_root, trash_rel_path, payload_physical_path).
// - restore_status is the lifecycle state used to coordinate manual restore/purge
//   operations and background retention cleanup.
struct TrashItemRec {
    // Stable per-entry identifier generated at move-to-trash time.
    std::string trash_id;

    // Logical owner scope of the trash entry.
    // scope_type decides how scope_id should be interpreted.
    std::string scope_type;   // "user" | "workspace"
    std::string scope_id;     // fp_hex | workspace_id

    // Actor/application metadata captured at delete time for auditability and UX.
    std::string deleted_by_fp;
    std::string origin_app;   // "filemgr" | "photogallery" | ...

    // Item classification and original logical location before trashing.
    std::string item_type;    // "file" | "dir"
    std::string original_rel_path;

    // Physical trash placement.
    //
    // storage_root:
    // - Concrete storage tree root the payload belonged to when it was deleted.
    // - Used to reconstruct the trash root consistently across user/workspace flows.
    //
    // trash_rel_path:
    // - Relative path below the storage root's internal .pqnas/trash area.
    //
    // payload_physical_path:
    // - Fully resolved payload location at the moment it was moved to trash.
    // - This is what restore/purge operations act on directly.
    std::string storage_root;         // concrete data/landing root where trash lives
    std::string trash_rel_path;       // relative path under storage_root/.pqnas/trash/...
    std::string payload_physical_path;

    // Optional source placement hints captured from the live file metadata layer.
    // These are useful during restore and for audit/reporting.
    std::string source_pool;
    std::string source_tier_state;    // "landing" | "migrating" | "capacity" | ""

    // Precomputed subtree/file size stats captured at delete time.
    // This avoids rescanning the trash payload for common listing/reporting flows.
    std::uint64_t size_bytes = 0;
    std::uint64_t file_count = 0;

    // Retention and lifecycle timestamps.
    //
    // deleted_epoch:
    // - Time when the item was moved to trash.
    //
    // purge_after_epoch:
    // - Retention deadline calculated at delete time.
    // - Background cleanup workers compare this against "now" to find expired items.
    std::int64_t deleted_epoch = 0;
    std::int64_t purge_after_epoch = 0;

    // Lifecycle state of the trash entry.
    //
    // Steady states:
    // - "trashed"  : active trash entry visible in normal trash UI
    // - "restored" : payload moved back to live location
    // - "purged"   : payload physically removed from trash
    //
    // Service code may also use transient coordination states (for example
    // "restoring" or "purging") to avoid races between manual operations and
    // background cleanup.
    std::string restore_status;       // "trashed" | "restored" | "purged"
    std::int64_t status_updated_epoch = 0;
};

// TrashIndex is the persistence boundary for trash metadata.
//
// Architectural responsibilities:
// - Own and manage the sqlite database connection for trash metadata.
// - Provide simple CRUD/query operations for trash rows.
// - Expose query shapes that match higher-level workflows:
//   * get one row by id
//   * list rows for one scope
//   * list expired rows for retention cleanup
//   * update lifecycle state
//
// Concurrency model:
// - One TrashIndex instance is shared across request handlers and background workers.
// - A single sqlite connection is protected by mu_ so callers do not need to manage
//   sqlite threading concerns directly.
//
// Separation of concerns:
// - TrashIndex stores metadata only.
// - It does not move, restore, or delete filesystem payloads.
// - TrashService sits above this layer and coordinates filesystem work with these
//   metadata updates.
class TrashIndex {
public:
    explicit TrashIndex(const std::filesystem::path& db_path);
    ~TrashIndex();

    TrashIndex(const TrashIndex&) = delete;
    TrashIndex& operator=(const TrashIndex&) = delete;

    // Opens the sqlite database and applies connection-level settings.
    // Safe to call multiple times; later calls are no-ops once db_ is open.
    bool open(std::string* err);

    // Creates tables/indexes if they do not already exist.
    bool init_schema(std::string* err);

    // Inserts a new trash row after the payload has already been moved into the
    // trash area by the service layer.
    bool insert(const TrashItemRec& rec, std::string* err);

    // Returns one trash row by stable trash_id.
    std::optional<TrashItemRec> get(const std::string& trash_id,
                                    std::string* err);

    // Lists rows for a single user/workspace scope.
    //
    // include_inactive=false:
    // - normal trash-bin view
    // - only active "trashed" rows
    //
    // include_inactive=true:
    // - includes restored/purged history as well
    std::vector<TrashItemRec> list_scope(const std::string& scope_type,
                                         const std::string& scope_id,
                                         bool include_inactive,
                                         std::size_t limit,
                                         std::string* err);

    // Returns expired active trash rows for the background cleanup worker.
    //
    // Intended semantics:
    // - only rows still eligible for purge
    // - ordered by earliest expiry first
    // - limited so one cleanup pass can stay bounded
    std::vector<TrashItemRec> list_expired(std::int64_t now_epoch,
                                           std::size_t limit,
                                           std::string* err);

    // Unconditional lifecycle status update.
    // Useful for simple status transitions where the caller does not need an
    // atomic "only if currently X" guard.
    bool set_restore_status(const std::string& trash_id,
                            const std::string& restore_status,
                            std::int64_t status_updated_epoch,
                            std::string* err);

    // Compare-and-set lifecycle status update.
    //
    // This is the race-safe primitive used by service flows that must claim a row
    // before touching the filesystem, for example:
    //   trashed -> restoring
    //   trashed -> purging
    //
    // If the current state is no longer expected_status, the update fails and the
    // caller can treat the row as already handled elsewhere.
    bool set_restore_status_if_current(const std::string& trash_id,
                                       const std::string& expected_status,
                                       const std::string& restore_status,
                                       std::int64_t status_updated_epoch,
                                       std::string* err);

    // Permanently removes the metadata row itself.
    //
    // Normal trash lifecycle generally prefers state transitions to "purged" so
    // audit/history information remains available. This exists for cases where the
    // row must be deleted outright.
    bool erase(const std::string& trash_id,
               std::string* err);

    // Returns the summed size of active trash for one scope.
    // Restored and purged rows are intentionally excluded.
    bool sum_active_scope_bytes(const std::string& scope_type,
                                const std::string& scope_id,
                                std::uint64_t* out_bytes,
                                std::string* err);

private:
    // On-disk sqlite location.
    std::filesystem::path db_path_;

    // Single shared sqlite connection owned by this index instance.
    sqlite3* db_ = nullptr;

    // Serializes all access to db_.
    //
    // This keeps the concurrency model straightforward: one sqlite connection,
    // one mutex, shared safely by HTTP handlers and background workers.
    mutable std::mutex mu_;
};

} // namespace pqnas