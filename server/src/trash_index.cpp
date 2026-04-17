#include "trash_index.h"

#include <sqlite3.h>

namespace pqnas {
namespace {

// Executes a schema/setup SQL string against the single TrashIndex database handle.
//
// Architectural notes:
// - This helper is intentionally tiny and only used for one-shot statements such as
//   PRAGMAs and schema creation.
// - Query/CRUD paths use prepared statements instead so callers can bind values safely.
// - Errors are normalized into a std::string so upper layers do not need to know
//   sqlite3 error ownership rules.
static bool exec_sql(sqlite3* db, const char* sql, std::string* err) {
    if (err) err->clear();
    char* msg = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &msg);
    if (rc != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db);
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);
    return true;
}

// Reads a TEXT column from the current sqlite row and converts null -> empty string.
//
// Keeping this mapping centralized avoids repeating the same reinterpret_cast/null
// handling in every row decoder and makes the row-to-struct conversion below easier
// to audit.
static std::string col_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

// Converts the current sqlite row into the in-memory TrashItemRec model.
//
// This function is the single authoritative mapping between database column order
// and TrashItemRec fields. The SELECT statements in this file deliberately keep the
// same column order so that all readers can share this decoder safely.
static TrashItemRec row_to_trash_item(sqlite3_stmt* stmt) {
    TrashItemRec rec;
    rec.trash_id             = col_text(stmt, 0);
    rec.scope_type           = col_text(stmt, 1);
    rec.scope_id             = col_text(stmt, 2);
    rec.deleted_by_fp        = col_text(stmt, 3);
    rec.origin_app           = col_text(stmt, 4);
    rec.item_type            = col_text(stmt, 5);
    rec.original_rel_path    = col_text(stmt, 6);
    rec.storage_root         = col_text(stmt, 7);
    rec.trash_rel_path       = col_text(stmt, 8);
    rec.payload_physical_path= col_text(stmt, 9);
    rec.source_pool          = col_text(stmt, 10);
    rec.source_tier_state    = col_text(stmt, 11);
    rec.size_bytes           = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 12));
    rec.file_count           = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 13));
    rec.deleted_epoch        = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 14));
    rec.purge_after_epoch    = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 15));
    rec.restore_status       = col_text(stmt, 16);
    rec.status_updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 17));
    return rec;
}

} // namespace

// TrashIndex owns one sqlite connection used by all trash readers/writers in this process.
//
// The implementation serializes access with mu_ because the same TrashIndex instance is
// shared by HTTP request handlers and the background auto-purge worker. That keeps the
// concurrency model simple: one connection, one mutex, predictable statement lifetime.
TrashIndex::TrashIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

// Closes the sqlite connection on destruction.
//
// We lock here for the same reason as normal operations: the object may be shutting down
// while background work is stopping, and we do not want sqlite3_close() racing with an
// in-flight statement on the shared connection.
TrashIndex::~TrashIndex() {
    std::lock_guard<std::mutex> lk(mu_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// Opens the sqlite database and applies connection-level settings.
//
// Architectural notes:
// - The parent directory is created here so callers only need to supply a path.
// - WAL mode is used so reads and writes can coexist better under normal service load.
// - synchronous=NORMAL is a pragmatic durability/performance balance for this metadata:
//   trash state must be reliable, but this is not the primary file payload store.
// - open() is idempotent for the lifetime of the object.
bool TrashIndex::open(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (db_) return true;

    std::error_code ec;
    std::filesystem::create_directories(db_path_.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    const int rc = sqlite3_open(db_path_.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    if (!exec_sql(db_, "PRAGMA journal_mode=WAL;", err)) return false;
    if (!exec_sql(db_, "PRAGMA synchronous=NORMAL;", err)) return false;

    return true;
}

    // Creates the trash schema if it does not already exist.
    //
    // Table design:
    // - One row represents one logical trash entry.
    // - The row stores both user-facing metadata (original path, item type, scope)
    //   and operational metadata needed to restore/purge safely (physical payload path,
    //   pool/tier hints, retention timestamps, lifecycle status).
    //
    // Lifecycle model:
    // - restore_status starts as "trashed"
    // - service code may move it through transient states such as "restoring"/"purging"
    // - final steady states are "restored" and "purged"
    //
    // Index design:
    // - idx_trash_scope_deleted supports trash listing UIs per scope ordered by newest first
    // - idx_trash_scope_status_deleted supports active-only trash views
    // - idx_trash_expiry supports background retention scanning ordered by earliest expiry
    bool TrashIndex::init_schema(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS trash_items (
    trash_id              TEXT PRIMARY KEY,
    scope_type            TEXT NOT NULL,
    scope_id              TEXT NOT NULL,
    deleted_by_fp         TEXT NOT NULL,
    origin_app            TEXT NOT NULL DEFAULT '',
    item_type             TEXT NOT NULL,
    original_rel_path     TEXT NOT NULL,
    storage_root          TEXT NOT NULL,
    trash_rel_path        TEXT NOT NULL,
    payload_physical_path TEXT NOT NULL,
    source_pool           TEXT NOT NULL DEFAULT '',
    source_tier_state     TEXT NOT NULL DEFAULT '',
    size_bytes            INTEGER NOT NULL DEFAULT 0,
    file_count            INTEGER NOT NULL DEFAULT 0,
    deleted_epoch         INTEGER NOT NULL,
    purge_after_epoch     INTEGER NOT NULL,
    restore_status        TEXT NOT NULL DEFAULT 'trashed',
    status_updated_epoch  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_trash_scope_deleted
ON trash_items(scope_type, scope_id, deleted_epoch DESC, trash_id DESC);

CREATE INDEX IF NOT EXISTS idx_trash_scope_status_deleted
ON trash_items(scope_type, scope_id, restore_status, deleted_epoch DESC, trash_id DESC);

CREATE INDEX IF NOT EXISTS idx_trash_expiry
ON trash_items(restore_status, purge_after_epoch ASC, trash_id ASC);
)SQL";

    return exec_sql(db_, kSchema, err);
}

// Inserts a brand-new trash row after the payload has already been moved into the trash area.
//
// Important architectural convention:
// - move_to_trash() in TrashService performs the filesystem move first, then inserts the row.
// - If this insert fails, TrashService is responsible for rolling the payload back.
// - TrashIndex only persists metadata; it does not attempt to repair filesystem state.
bool TrashIndex::insert(const TrashItemRec& rec, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "INSERT INTO trash_items ("
        "  trash_id, scope_type, scope_id, deleted_by_fp, origin_app, item_type, "
        "  original_rel_path, storage_root, trash_rel_path, payload_physical_path, "
        "  source_pool, source_tier_state, size_bytes, file_count, "
        "  deleted_epoch, purge_after_epoch, restore_status, status_updated_epoch"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18"
        ")";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt,  1, rec.trash_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  2, rec.scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  3, rec.scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  4, rec.deleted_by_fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  5, rec.origin_app.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  6, rec.item_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  7, rec.original_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  8, rec.storage_root.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,  9, rec.trash_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, rec.payload_physical_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, rec.source_pool.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, rec.source_tier_state.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 13, static_cast<sqlite3_int64>(rec.size_bytes));
    sqlite3_bind_int64(stmt, 14, static_cast<sqlite3_int64>(rec.file_count));
    sqlite3_bind_int64(stmt, 15, static_cast<sqlite3_int64>(rec.deleted_epoch));
    sqlite3_bind_int64(stmt, 16, static_cast<sqlite3_int64>(rec.purge_after_epoch));
    sqlite3_bind_text(stmt, 17, rec.restore_status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 18, static_cast<sqlite3_int64>(rec.status_updated_epoch));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

// Fetches exactly one trash row by its stable trash_id.
//
// This is the read path used by restore/purge flows before they attempt a state transition.
// Returning std::optional cleanly distinguishes "not found" from "query failed".
std::optional<TrashItemRec> TrashIndex::get(const std::string& trash_id,
                                                std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    static const char* kSql =
        "SELECT "
        "  trash_id, scope_type, scope_id, deleted_by_fp, origin_app, item_type, "
        "  original_rel_path, storage_root, trash_rel_path, payload_physical_path, "
        "  source_pool, source_tier_state, size_bytes, file_count, "
        "  deleted_epoch, purge_after_epoch, restore_status, status_updated_epoch "
        "FROM trash_items "
        "WHERE trash_id = ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, trash_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    if (rc != SQLITE_ROW) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    TrashItemRec rec = row_to_trash_item(stmt);
    sqlite3_finalize(stmt);
    return rec;
}

// Lists trash rows for one scope (user or workspace).
//
// include_inactive=false is the normal trash-bin view and only returns currently trashed items.
// include_inactive=true is used for richer admin/history style views where restored/purged rows
// are also useful.
//
// Ordering is newest deleted first so UI flows naturally show the latest trash operations at top.
std::vector<TrashItemRec> TrashIndex::list_scope(const std::string& scope_type,
                                                     const std::string& scope_id,
                                                     bool include_inactive,
                                                     std::size_t limit,
                                                     std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();

    std::vector<TrashItemRec> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    const char* kSqlActive =
        "SELECT "
        "  trash_id, scope_type, scope_id, deleted_by_fp, origin_app, item_type, "
        "  original_rel_path, storage_root, trash_rel_path, payload_physical_path, "
        "  source_pool, source_tier_state, size_bytes, file_count, "
        "  deleted_epoch, purge_after_epoch, restore_status, status_updated_epoch "
        "FROM trash_items "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND restore_status = 'trashed' "
        "ORDER BY deleted_epoch DESC, trash_id DESC "
        "LIMIT ?3";

    const char* kSqlAll =
        "SELECT "
        "  trash_id, scope_type, scope_id, deleted_by_fp, origin_app, item_type, "
        "  original_rel_path, storage_root, trash_rel_path, payload_physical_path, "
        "  source_pool, source_tier_state, size_bytes, file_count, "
        "  deleted_epoch, purge_after_epoch, restore_status, status_updated_epoch "
        "FROM trash_items "
        "WHERE scope_type = ?1 AND scope_id = ?2 "
        "ORDER BY deleted_epoch DESC, trash_id DESC "
        "LIMIT ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_,
                                           include_inactive ? kSqlAll : kSqlActive,
                                           -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }
        out.push_back(row_to_trash_item(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

// Returns expired trash candidates for the background cleanup worker.
//
// This is intentionally limited and ordered by earliest purge_after_epoch first so the worker can:
// - process items in stable retention order
// - cap the amount of work done in a single pass
// - continue cleanly on the next cycle if there are many expired rows
//
// Only rows still in steady active state ("trashed") are returned. Transient rows such as
// "restoring" or "purging" are intentionally skipped so the worker does not interfere with
// in-flight manual operations.
std::vector<TrashItemRec> TrashIndex::list_expired(std::int64_t now_epoch,
                                                       std::size_t limit,
                                                       std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();

    std::vector<TrashItemRec> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT "
        "  trash_id, scope_type, scope_id, deleted_by_fp, origin_app, item_type, "
        "  original_rel_path, storage_root, trash_rel_path, payload_physical_path, "
        "  source_pool, source_tier_state, size_bytes, file_count, "
        "  deleted_epoch, purge_after_epoch, restore_status, status_updated_epoch "
        "FROM trash_items "
        "WHERE restore_status = 'trashed' AND purge_after_epoch <= ?1 "
        "ORDER BY purge_after_epoch ASC, trash_id ASC "
        "LIMIT ?2";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now_epoch));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }
        out.push_back(row_to_trash_item(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

// Unconditionally sets restore_status for the given row.
//
// This is still useful for simple lifecycle updates, but restore/purge flows that must defend
// against races should prefer set_restore_status_if_current() below.
bool TrashIndex::set_restore_status(const std::string& trash_id,
                                        const std::string& restore_status,
                                        std::int64_t status_updated_epoch,
                                        std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE trash_items "
        "SET restore_status = ?1, status_updated_epoch = ?2 "
        "WHERE trash_id = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, restore_status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(status_updated_epoch));
    sqlite3_bind_text(stmt, 3, trash_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "set_restore_status_no_match";
        return false;
    }

    return true;
}
    // Compare-and-set style state transition used by race-sensitive service flows.
    //
    // This is the key building block that lets restore/purge/background-worker code safely claim
    // a trash row before touching the filesystem:
    //   trashed  -> restoring
    //   trashed  -> purging
    //   restoring -> restored / trashed
    //   purging   -> purged   / trashed
    //
    // If another actor changed the row first, sqlite changes() will be 0 and callers can treat
    // that as "no longer active" instead of risking double-acting on the payload.
    bool TrashIndex::set_restore_status_if_current(const std::string& trash_id,
                                                   const std::string& expected_status,
                                                   const std::string& restore_status,
                                                   std::int64_t status_updated_epoch,
                                                   std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE trash_items "
        "SET restore_status = ?1, status_updated_epoch = ?2 "
        "WHERE trash_id = ?3 AND restore_status = ?4";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, restore_status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(status_updated_epoch));
    sqlite3_bind_text(stmt, 3, trash_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, expected_status.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "set_restore_status_if_current_no_match";
        return false;
    }

    return true;
}

// Hard-deletes the metadata row itself.
//
// This is separate from purge lifecycle handling. In normal trash operation, the system prefers
// to mark rows as "purged" rather than delete history immediately. erase() exists for cases where
// the row itself must be removed entirely.
bool TrashIndex::erase(const std::string& trash_id,
                           std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "DELETE FROM trash_items WHERE trash_id = ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, trash_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "erase_no_match";
        return false;
    }

    return true;
}

// Sums bytes for currently active trash within one scope.
//
// This is useful for UI or quota-style reporting where only still-trashed items should count.
// Restored and purged rows are intentionally excluded.
bool TrashIndex::sum_active_scope_bytes(const std::string& scope_type,
                                            const std::string& scope_id,
                                            std::uint64_t* out_bytes,
                                            std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (err) err->clear();
    if (out_bytes) *out_bytes = 0;

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }
    if (!out_bytes) {
        if (err) *err = "null out_bytes";
        return false;
    }

    static const char* kSql =
        "SELECT COALESCE(SUM(size_bytes), 0) "
        "FROM trash_items "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND restore_status = 'trashed'";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    *out_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return true;
}
} // namespace pqnas