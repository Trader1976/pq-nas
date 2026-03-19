#include "file_location_index.h"

#include <sqlite3.h>
#include <map>
#include <vector>

namespace pqnas {

/*
Architecture notes
==================

Purpose
-------
FileLocationIndex is the metadata authority for the PQ-NAS logical file layer.

It maps:
- user fingerprint (fp)
- logical path seen by the API/UI
to:
- current physical path on disk
- current storage pool
- current tiering state
- size / mtime / version metadata

This is the core bridge between:
- logical namespace operations (PUT / MOVE / DELETE / LIST / STAT)
- physical filesystem layout
- background tiering / migration workflows

Why this exists
---------------
PQ-NAS no longer treats the visible filesystem tree as the sole source of truth.
Files may live in:
- landing pool
- capacity pool
- future multiple pools / roots

A user-visible logical path must therefore be decoupled from the file's current
physical location.

file_locations is the authoritative table for that mapping.

What this file is responsible for
---------------------------------
This class provides small, focused metadata operations such as:
- exact lookup of a logical file
- subtree listing for logical directories
- state transitions for tiering (landing -> migrating -> capacity)
- metadata rename for file or subtree moves
- metadata erase for delete operations
- existence probes used by path-conflict checks
- summary reporting for tier-state accounting

What this file is NOT responsible for
-------------------------------------
This class does not:
- perform authorization
- normalize user input paths
- manipulate favorites
- enforce request-level locking
- perform physical filesystem rename/copy/delete itself
- infer all business rules for the API

Those responsibilities stay in request handlers, resolvers, and higher-level
storage orchestration code.

Transaction philosophy
----------------------
Most methods here are intentionally small single-statement metadata operations.
That keeps them predictable and easy to reason about.

The notable exception is rename_subtree(), which performs a multi-row rewrite
inside an explicit transaction because subtree renames must be all-or-nothing.

Assumptions and current limitations
-----------------------------------
1. Primary key
   file_locations is keyed by:
     (fp, logical_rel_path)

   This enforces at most one current metadata row per logical file path.

2. Files, not explicit directory rows
   In the current design, directories usually exist implicitly via descendant
   files rather than as first-class rows of their own.

   Example:
     docs/a.txt
     docs/sub/b.txt
   implies logical dirs:
     docs
     docs/sub

   Many dir operations therefore work by scanning subtree file rows.

3. Mirrored physical layout assumption for subtree rename
   rename_subtree() currently reconstructs new physical paths by replacing the
   trailing logical suffix under the same physical root.

   This is valid for the current mirrored layout model, but should be revisited
   if future tiering allows subtree contents to span unrelated roots.

4. SQLite connection model
   One sqlite3* handle is owned by this object and used synchronously in the
   server process. This matches the current process-local lock and request model.

5. Error style
   Methods return bool / optional / vectors and write diagnostic detail into
   std::string* err when provided. Callers decide whether a no-match is expected
   or an internal error.

Schema summary
--------------
file_locations columns:
- fp               : user fingerprint namespace
- logical_rel_path : canonical logical file path
- current_pool     : pool id where the file currently resides
- physical_path    : actual current on-disk location
- tier_state       : landing / migrating / capacity
- size_bytes       : last known file size
- mtime_epoch      : last known file mtime
- created_epoch    : metadata creation time
- updated_epoch    : last metadata update time
- version          : monotonic metadata version

Design note on version
----------------------
version is incremented on metadata-changing operations to support:
- debugging
- stale-state detection
- future optimistic concurrency if desired

Reserved namespace handling
---------------------------
Reserved logical names such as ".pqnas" are mainly filtered/enforced higher in
the stack. list_immediate_children() also hard-filters ".pqnas" as a backend
safety net so internal control paths do not leak back into normal file listings.
*/

namespace {

/*
exec_sql()
----------
Small helper for one-shot SQL statements such as PRAGMA setup and schema init.
Used only for statements that do not require parameter binding.
*/
static bool exec_sql(sqlite3* db, const char* sql, std::string* err) {
    if (err) err->clear();
    char* msg = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &msg);
    if (rc != SQLITE_OK) {
        if (err) {
            *err = msg ? msg : sqlite3_errmsg(db);
        }
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);
    return true;
}

} // namespace

FileLocationIndex::FileLocationIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

FileLocationIndex::~FileLocationIndex() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

/*
erase()
-------
Remove one exact logical file row.

This is intentionally strict:
- success requires exactly one row to be deleted
- zero affected rows is treated as a no-match error

That strictness is useful for delete handlers because it prevents "delete looked
successful" when metadata did not actually contain the expected row.
*/
bool FileLocationIndex::erase(const std::string& fp,
                              const std::string& logical_rel_path,
                              std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "DELETE FROM file_locations WHERE fp = ?1 AND logical_rel_path = ?2";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

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

/*
open()
------
Open the SQLite database and apply connection-local pragmas.

Current choices:
- WAL journal mode
- synchronous=NORMAL

This balances durability and performance reasonably well for PQ-NAS metadata.
If stricter durability is needed later, synchronous can be raised.
*/
bool FileLocationIndex::open(std::string* err) {
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

/*
init_schema()
-------------
Create the metadata table and supporting index if they do not already exist.
*/
bool FileLocationIndex::init_schema(std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS file_locations (
    fp                TEXT NOT NULL,
    logical_rel_path  TEXT NOT NULL,
    current_pool      TEXT NOT NULL,
    physical_path     TEXT NOT NULL,
    tier_state        TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    mtime_epoch       INTEGER NOT NULL DEFAULT 0,
    created_epoch     INTEGER NOT NULL,
    updated_epoch     INTEGER NOT NULL,
    version           INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (fp, logical_rel_path)
);

CREATE INDEX IF NOT EXISTS idx_file_locations_pool_state
ON file_locations(current_pool, tier_state);
)SQL";

    return exec_sql(db_, kSchema, err);
}

/*
get()
-----
Exact metadata lookup for one logical file path.

Important:
- absence of a row returns std::nullopt without error
- actual SQLite failure reports via err
*/
std::optional<FileLocationRecord> FileLocationIndex::get(const std::string& fp,
                                                         const std::string& logical_rel_path,
                                                         std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    static const char* kSql =
        "SELECT fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "size_bytes, mtime_epoch, created_epoch, updated_epoch, version "
        "FROM file_locations "
        "WHERE fp = ?1 AND logical_rel_path = ?2";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

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

    FileLocationRecord rec;
    rec.fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    rec.current_pool = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    rec.physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    rec.tier_state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
    rec.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
    rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
    rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));
    rec.version = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));

    sqlite3_finalize(stmt);
    return rec;
}

/*
upsert_landing_file()
---------------------
Insert or update the metadata row for a file written into the landing area.

This is used by PUT when tiering is enabled.

Conflict behavior:
- same logical path updates current_pool / physical_path / tier_state / size / mtime
- created_epoch is preserved from the original row
- version increments on update

This supports overwrite semantics while keeping logical identity stable.
*/
bool FileLocationIndex::upsert_landing_file(const FileLocationRecord& rec, std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "INSERT INTO file_locations ("
        "  fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "  size_bytes, mtime_epoch, created_epoch, updated_epoch, version"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10"
        ") "
        "ON CONFLICT(fp, logical_rel_path) DO UPDATE SET "
        "  current_pool = excluded.current_pool, "
        "  physical_path = excluded.physical_path, "
        "  tier_state = excluded.tier_state, "
        "  size_bytes = excluded.size_bytes, "
        "  mtime_epoch = excluded.mtime_epoch, "
        "  updated_epoch = excluded.updated_epoch, "
        "  version = file_locations.version + 1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.current_pool.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.physical_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.tier_state.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(rec.size_bytes));
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(rec.mtime_epoch));
    sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(rec.updated_epoch));
    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(rec.version));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

/*
mark_landing_again()
--------------------
Revert a row from migrating back to landing, but only if the caller still
matches the expected source physical path.

This is a guarded state transition used when migration work needs to be undone
or retried safely.
*/
bool FileLocationIndex::mark_landing_again(const std::string& fp,
                                           const std::string& logical_rel_path,
                                           const std::string& expected_src_physical_path,
                                           std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE file_locations "
        "SET tier_state = 'landing', "
        "    updated_epoch = strftime('%s','now'), "
        "    version = version + 1 "
        "WHERE fp = ?1 "
        "  AND logical_rel_path = ?2 "
        "  AND physical_path = ?3 "
        "  AND tier_state = 'migrating'";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, expected_src_physical_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

/*
switch_to_capacity()
--------------------
Complete a migration by atomically switching one row from:
- tier_state = migrating
- old physical path = expected_src_physical_path
to:
- new pool
- new physical path
- tier_state = capacity

The WHERE clause is intentionally strict so stale workers cannot update the row
after another actor has already changed it.
*/
bool FileLocationIndex::switch_to_capacity(const std::string& fp,
                                           const std::string& logical_rel_path,
                                           const std::string& expected_src_physical_path,
                                           const std::string& new_pool,
                                           const std::string& new_physical_path,
                                           std::int64_t new_mtime_epoch,
                                           std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE file_locations "
        "SET current_pool = ?1, "
        "    physical_path = ?2, "
        "    tier_state = 'capacity', "
        "    mtime_epoch = ?3, "
        "    updated_epoch = ?4, "
        "    version = version + 1 "
        "WHERE fp = ?5 "
        "  AND logical_rel_path = ?6 "
        "  AND physical_path = ?7 "
        "  AND tier_state = 'migrating'";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    const std::int64_t now_ts = new_mtime_epoch;

    sqlite3_bind_text(stmt, 1, new_pool.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, new_physical_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(new_mtime_epoch));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now_ts));
    sqlite3_bind_text(stmt, 5, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, expected_src_physical_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "switch_to_capacity_no_match";
        return false;
    }

    return true;
}

/*
list_landing_candidates()
-------------------------
Return rows currently in landing state, oldest updated first.

Used by background migration selection. Ordering by updated_epoch gives a simple
FIFO-like policy suitable for a first implementation.
*/
std::vector<FileLocationRecord> FileLocationIndex::list_landing_candidates(std::size_t limit,
                                                                           std::string* err) {
    if (err) err->clear();

    std::vector<FileLocationRecord> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "size_bytes, mtime_epoch, created_epoch, updated_epoch, version "
        "FROM file_locations "
        "WHERE tier_state = 'landing' "
        "ORDER BY updated_epoch ASC, logical_rel_path ASC "
        "LIMIT ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        FileLocationRecord rec;
        rec.fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.current_pool = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.tier_state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        rec.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
        rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
        rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));
        rec.version = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));

        out.push_back(std::move(rec));
    }

    sqlite3_finalize(stmt);
    return out;
}

/*
mark_migrating()
----------------
Claim a landing row for migration by switching it to migrating, but only if the
expected source physical path still matches and the row is still in landing.

This is a lightweight compare-and-swap style state transition.
*/
bool FileLocationIndex::mark_migrating(const std::string& fp,
                                       const std::string& logical_rel_path,
                                       const std::string& expected_src_physical_path,
                                       std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE file_locations "
        "SET tier_state = 'migrating', "
        "    updated_epoch = strftime('%s','now'), "
        "    version = version + 1 "
        "WHERE fp = ?1 "
        "  AND logical_rel_path = ?2 "
        "  AND physical_path = ?3 "
        "  AND tier_state = 'landing'";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, expected_src_physical_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "mark_migrating_no_match";
        return false;
    }

    return true;
}

/*
list_stuck_migrating_candidates()
---------------------------------
Return rows that have remained in migrating state up to a cutoff time.

Used by recovery / repair logic to detect migrations that likely died mid-flight.
*/
std::vector<FileLocationRecord> FileLocationIndex::list_stuck_migrating_candidates(std::int64_t older_than_epoch,
                                                                                   std::string* err) {
    if (err) err->clear();

    std::vector<FileLocationRecord> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "size_bytes, mtime_epoch, created_epoch, updated_epoch, version "
        "FROM file_locations "
        "WHERE tier_state = 'migrating' "
        "  AND updated_epoch <= ?1 "
        "ORDER BY updated_epoch ASC, logical_rel_path ASC";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(older_than_epoch));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        FileLocationRecord rec;
        rec.fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.current_pool = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.tier_state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        rec.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
        rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
        rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));
        rec.version = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));

        out.push_back(std::move(rec));
    }

    sqlite3_finalize(stmt);
    return out;
}

/*
list_immediate_children()
-------------------------
Build a synthetic directory listing from file rows.

Because directories are usually implicit rather than explicit rows, this method
scans all rows for one fp and collapses them into immediate children of dir_rel.

Rules:
- exact descendant without further slash => file child
- deeper descendant => first segment becomes dir child
- metadata "wins" for exact file rows
- reserved top-level child ".pqnas" is hidden here as a backend safety net
*/
std::vector<LogicalListItem> FileLocationIndex::list_immediate_children(const std::string& fp,
                                                                        const std::string& dir_rel,
                                                                        std::string* err) {
    if (err) err->clear();

    std::vector<LogicalListItem> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT logical_rel_path, size_bytes, mtime_epoch "
        "FROM file_locations "
        "WHERE fp = ?1 "
        "ORDER BY logical_rel_path ASC";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);

    const std::string prefix = dir_rel.empty() ? "" : (dir_rel + "/");
    std::map<std::string, LogicalListItem> by_name;

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        const char* rel_c = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const std::string rel = rel_c ? rel_c : "";
        if (rel.empty()) continue;

        if (!prefix.empty()) {
            if (rel.rfind(prefix, 0) != 0) continue;
        }

        const std::string rest = prefix.empty() ? rel : rel.substr(prefix.size());
        if (rest.empty()) continue;

        const auto slash = rest.find('/');
        const std::string first_name = (slash == std::string::npos) ? rest : rest.substr(0, slash);

        // Backend hard-filter for reserved namespace.
        if (first_name == ".pqnas") {
            continue;
        }

        if (slash == std::string::npos) {
            LogicalListItem it;
            it.name = rest;
            it.type = "file";
            it.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
            it.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 2));
            by_name[it.name] = std::move(it);
        } else {
            auto pos = by_name.find(first_name);
            if (pos == by_name.end()) {
                LogicalListItem it;
                it.name = first_name;
                it.type = "dir";
                it.size_bytes = 0;
                it.mtime_epoch = 0;
                by_name.emplace(it.name, std::move(it));
            }
        }
    }

    sqlite3_finalize(stmt);

    out.reserve(by_name.size());
    for (auto& kv : by_name) out.push_back(std::move(kv.second));
    return out;
}

/*
rename_one()
------------
Rename one exact logical file row and its physical path together.

Strictness:
- success requires exactly one matching row
- no-match is returned as rename_one_no_match

This is the metadata companion of a successful physical file move.
*/
bool FileLocationIndex::rename_one(const std::string& fp,
                                   const std::string& old_logical_rel_path,
                                   const std::string& new_logical_rel_path,
                                   const std::string& old_physical_path,
                                   const std::string& new_physical_path,
                                   std::int64_t new_mtime_epoch,
                                   std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE file_locations "
        "SET logical_rel_path = ?1, "
        "    physical_path = ?2, "
        "    mtime_epoch = ?3, "
        "    updated_epoch = ?4, "
        "    version = version + 1 "
        "WHERE fp = ?5 "
        "  AND logical_rel_path = ?6 "
        "  AND physical_path = ?7";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, new_physical_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(new_mtime_epoch));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(new_mtime_epoch));
    sqlite3_bind_text(stmt, 5, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, old_logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, old_physical_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "rename_one_no_match";
        return false;
    }

    return true;
}

/*
rename_subtree()
----------------
Rewrite all metadata rows under one logical prefix to a new logical prefix.

This is used for directory moves where directories are represented implicitly by
descendant file rows.

Important properties:
- runs inside BEGIN IMMEDIATE transaction
- collects source rows first
- refuses destination subtree conflicts
- reinserts rewritten rows with incremented version
- deletes original rows only after each rewritten row is inserted

Why reinsert instead of UPDATE PK directly?
-------------------------------------------
The primary key includes logical_rel_path. Reinsert + delete is easier to reason
about for subtree moves and keeps destination conflict handling explicit.

Current limitation:
- physical path rewrite assumes mirrored physical layout under a shared root
- mixed-root subtree moves are therefore rejected higher in the stack
*/
bool FileLocationIndex::rename_subtree(const std::string& fp,
                                       const std::string& old_logical_prefix,
                                       const std::string& new_logical_prefix,
                                       std::int64_t new_mtime_epoch,
                                       std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (old_logical_prefix.empty() || new_logical_prefix.empty()) {
        if (err) *err = "empty prefix";
        return false;
    }

    if (old_logical_prefix == new_logical_prefix) {
        if (err) *err = "same prefix";
        return false;
    }

    char* msg = nullptr;
    const int rc_begin = sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, &msg);
    if (rc_begin != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);

    auto rollback_and_fail = [&](const std::string& e) -> bool {
        if (err) *err = e;
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    };

    struct Row {
        std::string logical_rel_path;
        std::string physical_path;
        std::string current_pool;
        std::string tier_state;
        std::uint64_t size_bytes = 0;
        std::int64_t created_epoch = 0;
        std::int64_t version = 1;
    };

    // -------------------------------------------------------------------------
    // 1) Collect source rows to rename
    // -------------------------------------------------------------------------
    static const char* kSelectSrc =
        "SELECT logical_rel_path, physical_path, current_pool, tier_state, "
        "       size_bytes, created_epoch, version "
        "FROM file_locations "
        "WHERE fp = ?1 AND (logical_rel_path = ?2 OR logical_rel_path LIKE ?3) "
        "ORDER BY length(logical_rel_path) DESC, logical_rel_path DESC";

    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(db_, kSelectSrc, -1, &sel, nullptr) != SQLITE_OK) {
        return rollback_and_fail(sqlite3_errmsg(db_));
    }

    const std::string src_like = old_logical_prefix + "/%";
    sqlite3_bind_text(sel, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(sel, 2, old_logical_prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(sel, 3, src_like.c_str(), -1, SQLITE_TRANSIENT);

    std::vector<Row> rows;

    while (true) {
        const int rc = sqlite3_step(sel);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            std::string e = sqlite3_errmsg(db_);
            sqlite3_finalize(sel);
            return rollback_and_fail(e);
        }

        Row r;
        r.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
        r.physical_path    = reinterpret_cast<const char*>(sqlite3_column_text(sel, 1));
        r.current_pool     = reinterpret_cast<const char*>(sqlite3_column_text(sel, 2));
        r.tier_state       = reinterpret_cast<const char*>(sqlite3_column_text(sel, 3));
        r.size_bytes       = static_cast<std::uint64_t>(sqlite3_column_int64(sel, 4));
        r.created_epoch    = static_cast<std::int64_t>(sqlite3_column_int64(sel, 5));
        r.version          = static_cast<std::int64_t>(sqlite3_column_int64(sel, 6));
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(sel);

    if (rows.empty()) {
        const int rc_commit = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &msg);
        if (rc_commit != SQLITE_OK) {
            if (err) *err = msg ? msg : sqlite3_errmsg(db_);
            if (msg) sqlite3_free(msg);
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        if (msg) sqlite3_free(msg);
        return true;
    }

    // -------------------------------------------------------------------------
    // 2) Refuse destination conflicts
    // -------------------------------------------------------------------------
    static const char* kCheckDst =
        "SELECT 1 "
        "FROM file_locations "
        "WHERE fp = ?1 AND (logical_rel_path = ?2 OR logical_rel_path LIKE ?3) "
        "LIMIT 1";

    sqlite3_stmt* chk = nullptr;
    if (sqlite3_prepare_v2(db_, kCheckDst, -1, &chk, nullptr) != SQLITE_OK) {
        return rollback_and_fail(sqlite3_errmsg(db_));
    }

    const std::string dst_like = new_logical_prefix + "/%";
    sqlite3_bind_text(chk, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(chk, 2, new_logical_prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(chk, 3, dst_like.c_str(), -1, SQLITE_TRANSIENT);

    {
        const int rc = sqlite3_step(chk);
        if (rc == SQLITE_ROW) {
            sqlite3_finalize(chk);
            return rollback_and_fail("destination_subtree_exists");
        }
        if (rc != SQLITE_DONE) {
            std::string e = sqlite3_errmsg(db_);
            sqlite3_finalize(chk);
            return rollback_and_fail(e);
        }
    }
    sqlite3_finalize(chk);

    // -------------------------------------------------------------------------
    // 3) Insert rewritten rows
    // -------------------------------------------------------------------------
    static const char* kInsert =
        "INSERT INTO file_locations ("
        "  fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "  size_bytes, mtime_epoch, created_epoch, updated_epoch, version"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10"
        ")";

    sqlite3_stmt* ins = nullptr;
    if (sqlite3_prepare_v2(db_, kInsert, -1, &ins, nullptr) != SQLITE_OK) {
        return rollback_and_fail(sqlite3_errmsg(db_));
    }

    static const char* kDeleteSrcOne =
        "DELETE FROM file_locations "
        "WHERE fp = ?1 AND logical_rel_path = ?2 AND physical_path = ?3";

    sqlite3_stmt* del_src = nullptr;
    if (sqlite3_prepare_v2(db_, kDeleteSrcOne, -1, &del_src, nullptr) != SQLITE_OK) {
        sqlite3_finalize(ins);
        return rollback_and_fail(sqlite3_errmsg(db_));
    }

    for (const auto& row : rows) {
        std::string suffix;
        if (row.logical_rel_path == old_logical_prefix) {
            suffix.clear();
        } else if (row.logical_rel_path.rfind(old_logical_prefix + "/", 0) == 0) {
            suffix = row.logical_rel_path.substr(old_logical_prefix.size());
        } else {
            sqlite3_finalize(ins);
            sqlite3_finalize(del_src);
            return rollback_and_fail("source_subtree_mismatch");
        }

        const std::string new_logical = new_logical_prefix + suffix;

        // Current implementation still assumes mirrored physical layout.
        std::filesystem::path old_phys(row.physical_path);
        std::filesystem::path root = old_phys;
        for (const auto& _ : std::filesystem::path(row.logical_rel_path)) {
            (void)_;
            root = root.parent_path();
        }
        const std::filesystem::path new_phys = root / std::filesystem::path(new_logical);

        sqlite3_reset(ins);
        sqlite3_clear_bindings(ins);

        sqlite3_bind_text(ins, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, new_logical.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 3, row.current_pool.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 4, new_phys.string().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 5, row.tier_state.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins, 6, static_cast<sqlite3_int64>(row.size_bytes));
        sqlite3_bind_int64(ins, 7, static_cast<sqlite3_int64>(new_mtime_epoch));
        sqlite3_bind_int64(ins, 8, static_cast<sqlite3_int64>(row.created_epoch));
        sqlite3_bind_int64(ins, 9, static_cast<sqlite3_int64>(new_mtime_epoch));
        sqlite3_bind_int64(ins, 10, static_cast<sqlite3_int64>(row.version + 1));

        if (sqlite3_step(ins) != SQLITE_DONE) {
            std::string e = sqlite3_errmsg(db_);
            sqlite3_finalize(ins);
            sqlite3_finalize(del_src);
            return rollback_and_fail(e);
        }

        sqlite3_reset(del_src);
        sqlite3_clear_bindings(del_src);

        sqlite3_bind_text(del_src, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(del_src, 2, row.logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(del_src, 3, row.physical_path.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(del_src) != SQLITE_DONE) {
            std::string e = sqlite3_errmsg(db_);
            sqlite3_finalize(ins);
            sqlite3_finalize(del_src);
            return rollback_and_fail(e);
        }
    }

    sqlite3_finalize(ins);
    sqlite3_finalize(del_src);

    const int rc_commit = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &msg);
    if (rc_commit != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    if (msg) sqlite3_free(msg);

    return true;
}

/*
list_subtree_records()
----------------------
Return all file rows exactly at logical_prefix or beneath logical_prefix/.

This is the core metadata primitive for:
- directory move
- directory delete
- metadata-backed logical directory resolution
*/
std::vector<FileLocationRecord> FileLocationIndex::list_subtree_records(const std::string& fp,
                                                                        const std::string& logical_prefix,
                                                                        std::string* err) {
    if (err) err->clear();

    std::vector<FileLocationRecord> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT fp, logical_rel_path, current_pool, physical_path, tier_state, "
        "size_bytes, mtime_epoch, created_epoch, updated_epoch, version "
        "FROM file_locations "
        "WHERE fp = ?1 AND (logical_rel_path = ?2 OR logical_rel_path LIKE ?3) "
        "ORDER BY logical_rel_path ASC";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    const std::string like_pat = logical_prefix + "/%";
    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, like_pat.c_str(), -1, SQLITE_TRANSIENT);

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        FileLocationRecord rec;
        rec.fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.current_pool = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.tier_state = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
        rec.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
        rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
        rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));
        rec.version = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));

        out.push_back(std::move(rec));
    }

    sqlite3_finalize(stmt);
    return out;
}

/*
logical_dir_exists()
--------------------
A logical directory exists if there is at least one descendant row under
logical_prefix/.

Used for reverse namespace conflict checks such as:
- reject PUT "docs" if "docs/a.txt" already exists
*/
bool FileLocationIndex::logical_dir_exists(const std::string& fp,
                                           const std::string& logical_prefix,
                                           std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "SELECT 1 "
        "FROM file_locations "
        "WHERE fp = ?1 AND logical_rel_path LIKE ?2 "
        "LIMIT 1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    const std::string like_pat = logical_prefix + "/%";
    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, like_pat.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    const bool found = (rc == SQLITE_ROW);

    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return found;
}

/*
rename_logical_prefix()
-----------------------
Older helper that rewrites logical_rel_path prefixes in place.

This updates only logical paths, not physical_path. That means it is less
appropriate for the current metadata + physical move model than rename_subtree(),
which rewrites both and is what newer handlers use.

Kept for compatibility with any remaining callers.
*/
bool FileLocationIndex::rename_logical_prefix(const std::string& fp,
                                              const std::string& from_prefix,
                                              const std::string& to_prefix,
                                              std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (from_prefix.empty() || to_prefix.empty()) {
        if (err) *err = "empty prefix";
        return false;
    }

    char* msg = nullptr;
    const int rc_begin = sqlite3_exec(db_, "BEGIN IMMEDIATE TRANSACTION;", nullptr, nullptr, &msg);
    if (rc_begin != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);

    auto rollback = [&]() {
        char* rmsg = nullptr;
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &rmsg);
        if (rmsg) sqlite3_free(rmsg);
    };

    // Rename exact directory row if one exists.
    {
        static const char* kSqlExact =
            "UPDATE file_locations "
            "SET logical_rel_path = ?1, "
            "    updated_epoch = strftime('%s','now'), "
            "    version = version + 1 "
            "WHERE fp = ?2 AND logical_rel_path = ?3";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSqlExact, -1, &stmt, nullptr) != SQLITE_OK) {
            if (err) *err = sqlite3_errmsg(db_);
            rollback();
            return false;
        }

        sqlite3_bind_text(stmt, 1, to_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, fp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, from_prefix.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            rollback();
            return false;
        }
        sqlite3_finalize(stmt);
    }

    // Rename subtree rows under from_prefix/
    {
        static const char* kSqlSubtree =
            "UPDATE file_locations "
            "SET logical_rel_path = ?1 || substr(logical_rel_path, length(?2) + 1), "
            "    updated_epoch = strftime('%s','now'), "
            "    version = version + 1 "
            "WHERE fp = ?3 "
            "  AND logical_rel_path LIKE (?2 || '/%')";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSqlSubtree, -1, &stmt, nullptr) != SQLITE_OK) {
            if (err) *err = sqlite3_errmsg(db_);
            rollback();
            return false;
        }

        sqlite3_bind_text(stmt, 1, to_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, from_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, fp.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            rollback();
            return false;
        }
        sqlite3_finalize(stmt);
    }

    const int rc_commit = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &msg);
    if (rc_commit != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        rollback();
        return false;
    }
    if (msg) sqlite3_free(msg);

    return true;
}

/*
get_tier_summary()
------------------
Aggregate counts and bytes by tier_state for observability / admin reporting.
*/
bool FileLocationIndex::get_tier_summary(FileLocationTierSummary* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    *out = FileLocationTierSummary{};

    static const char* kSql =
        "SELECT tier_state, COUNT(*), COALESCE(SUM(size_bytes), 0) "
        "FROM file_locations "
        "GROUP BY tier_state";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            return false;
        }

        const char* state_c = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const std::string state = state_c ? state_c : "";
        const std::uint64_t files = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 1));
        const std::uint64_t bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 2));

        if (state == "landing") {
            out->landing_files = files;
            out->landing_bytes = bytes;
        } else if (state == "migrating") {
            out->migrating_files = files;
            out->migrating_bytes = bytes;
        } else if (state == "capacity") {
            out->capacity_files = files;
            out->capacity_bytes = bytes;
        }

        out->total_files += files;
        out->total_bytes += bytes;
    }

    sqlite3_finalize(stmt);
    return true;
}

/*
logical_file_exists_exact()
---------------------------
Probe for one exact logical file row.

Used by ancestor-file conflict checks such as:
- reject PUT "a/b.txt" when exact file "a" already exists
*/
bool FileLocationIndex::logical_file_exists_exact(const std::string& fp,
                                                  const std::string& logical_rel_path,
                                                  std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "SELECT 1 "
        "FROM file_locations "
        "WHERE fp = ?1 AND logical_rel_path = ?2 "
        "LIMIT 1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    const bool found = (rc == SQLITE_ROW);

    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return found;
}

/*
erase_subtree()
---------------
Remove all metadata rows exactly at logical_prefix or beneath logical_prefix/.

This is the metadata companion of a successful directory delete.
Unlike erase(), zero affected rows is not treated as an error because callers
may use subtree erase in cases where a logical directory existed only implicitly.
*/
bool FileLocationIndex::erase_subtree(const std::string& fp,
                                      const std::string& logical_prefix,
                                      std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "DELETE FROM file_locations "
        "WHERE fp = ?1 AND (logical_rel_path = ?2 OR logical_rel_path LIKE ?3)";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    const std::string like_pat = logical_prefix + "/%";
    sqlite3_bind_text(stmt, 1, fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, logical_prefix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, like_pat.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

} // namespace pqnas