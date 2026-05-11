#include "file_locks.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <sqlite3.h>

namespace pqnas {
namespace {

void set_err(std::string* err, const std::string& msg) {
    if (err) *err = msg;
}

bool exec_sql(sqlite3* db, const char* sql, std::string* err) {
    char* raw = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &raw);
    if (rc == SQLITE_OK) return true;

    std::string msg = raw ? raw : sqlite3_errmsg(db);
    sqlite3_free(raw);
    set_err(err, msg);
    return false;
}

bool bind_text(sqlite3_stmt* st, int idx, const std::string& v) {
    return sqlite3_bind_text(st, idx, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

std::string col_text(sqlite3_stmt* st, int idx) {
    const unsigned char* p = sqlite3_column_text(st, idx);
    return p ? reinterpret_cast<const char*>(p) : std::string{};
}

bool open_db(const std::filesystem::path& db_path, sqlite3** out, std::string* err) {
    if (!out) {
        set_err(err, "missing output db pointer");
        return false;
    }
    *out = nullptr;

    std::error_code ec;
    const auto parent = db_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            set_err(err, "failed to create file locks db directory: " + ec.message());
            return false;
        }
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.string().c_str(), &db) != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "sqlite open failed";
        if (db) sqlite3_close(db);
        set_err(err, msg);
        return false;
    }

    sqlite3_busy_timeout(db, 5000);
    *out = db;
    return true;
}

} // namespace

bool file_lock_is_live(const FileLockRec& rec, std::int64_t now_epoch) {
    return rec.expires_at_epoch <= 0 || now_epoch <= 0 || rec.expires_at_epoch > now_epoch;
}

FileLocksStore::FileLocksStore(std::filesystem::path db_path)
    : db_path_(std::move(db_path)) {}

bool FileLocksStore::init(std::string* err) const {
    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    bool ok = true;
    ok = ok && exec_sql(db, "PRAGMA journal_mode=WAL;", err);
    ok = ok && exec_sql(db, "PRAGMA synchronous=NORMAL;", err);
    ok = ok && exec_sql(db,
        "CREATE TABLE IF NOT EXISTS file_locks ("
        "  scope_type TEXT NOT NULL,"
        "  scope_id TEXT NOT NULL,"
        "  logical_rel_path TEXT NOT NULL,"
        "  item_kind TEXT NOT NULL DEFAULT 'unknown',"
        "  locked_by_fp TEXT NOT NULL DEFAULT '',"
        "  note TEXT NOT NULL DEFAULT '',"
        "  created_at_epoch INTEGER NOT NULL DEFAULT 0,"
        "  updated_at_epoch INTEGER NOT NULL DEFAULT 0,"
        "  expires_at_epoch INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(scope_type, scope_id, logical_rel_path)"
        ");",
        err);

    sqlite3_close(db);
    return ok;
}

std::optional<FileLockRec> FileLocksStore::get_lock(const std::string& scope_type,
                                                    const std::string& scope_id,
                                                    const std::string& logical_rel_path,
                                                    std::string* err) const {
    if (!init(err)) return std::nullopt;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return std::nullopt;

    const char* sql =
        "SELECT scope_type, scope_id, logical_rel_path, item_kind, locked_by_fp, note, "
        "       created_at_epoch, updated_at_epoch, expires_at_epoch "
        "FROM file_locks "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3 "
        "LIMIT 1;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return std::nullopt;
    }

    bind_text(st, 1, scope_type);
    bind_text(st, 2, scope_id);
    bind_text(st, 3, logical_rel_path);

    std::optional<FileLockRec> out;
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        FileLockRec r;
        r.scope_type = col_text(st, 0);
        r.scope_id = col_text(st, 1);
        r.logical_rel_path = col_text(st, 2);
        r.item_kind = col_text(st, 3);
        r.locked_by_fp = col_text(st, 4);
        r.note = col_text(st, 5);
        r.created_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 6));
        r.updated_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 7));
        r.expires_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 8));
        out = std::move(r);
    } else if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}

std::optional<FileLockRec> FileLocksStore::find_live_conflict(
    const std::string& scope_type,
    const std::string& scope_id,
    const std::string& logical_rel_path,
    std::int64_t now_epoch,
    std::string* err) const {
    if (!init(err)) return std::nullopt;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return std::nullopt;

    const char* sql =
        "SELECT scope_type, scope_id, logical_rel_path, item_kind, locked_by_fp, note, "
        "       created_at_epoch, updated_at_epoch, expires_at_epoch "
        "FROM file_locks "
        "WHERE scope_type = ?1 "
        "  AND scope_id = ?2 "
        "  AND ("
        "       logical_rel_path = ?3 "
        "       OR (?3 = '' AND logical_rel_path <> '') "
        "       OR (?3 <> '' AND substr(logical_rel_path, 1, length(?3) + 1) = (?3 || '/')) "
        "       OR (logical_rel_path <> '' AND substr(?3, 1, length(logical_rel_path) + 1) = (logical_rel_path || '/')) "
        "  ) "
        "  AND (expires_at_epoch <= 0 OR ?4 <= 0 OR expires_at_epoch > ?4) "
        "ORDER BY "
        "  CASE "
        "    WHEN logical_rel_path = ?3 THEN 0 "
        "    WHEN logical_rel_path <> '' AND substr(?3, 1, length(logical_rel_path) + 1) = (logical_rel_path || '/') THEN 1 "
        "    ELSE 2 "
        "  END, "
        "  length(logical_rel_path) DESC "
        "LIMIT 1;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return std::nullopt;
    }

    bool ok = true;
    ok = ok && bind_text(st, 1, scope_type);
    ok = ok && bind_text(st, 2, scope_id);
    ok = ok && bind_text(st, 3, logical_rel_path);
    ok = ok && sqlite3_bind_int64(st, 4, now_epoch) == SQLITE_OK;

    if (!ok) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return std::nullopt;
    }

    std::optional<FileLockRec> out;
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        FileLockRec r;
        r.scope_type = col_text(st, 0);
        r.scope_id = col_text(st, 1);
        r.logical_rel_path = col_text(st, 2);
        r.item_kind = col_text(st, 3);
        r.locked_by_fp = col_text(st, 4);
        r.note = col_text(st, 5);
        r.created_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 6));
        r.updated_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 7));
        r.expires_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 8));
        out = std::move(r);
    } else if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}


std::vector<FileLockRec> FileLocksStore::list_locks_for_scope(const std::string& scope_type,
                                                              const std::string& scope_id,
                                                              std::string* err) const {
    if (!init(err)) return {};

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return {};

    const char* sql =
        "SELECT scope_type, scope_id, logical_rel_path, item_kind, locked_by_fp, note, "
        "       created_at_epoch, updated_at_epoch, expires_at_epoch "
        "FROM file_locks "
        "WHERE scope_type = ?1 AND scope_id = ?2 "
        "ORDER BY logical_rel_path ASC;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return {};
    }

    bool ok = true;
    ok = ok && bind_text(st, 1, scope_type);
    ok = ok && bind_text(st, 2, scope_id);

    if (!ok) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return {};
    }

    std::vector<FileLockRec> out;

    int rc = SQLITE_DONE;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        FileLockRec r;
        r.scope_type = col_text(st, 0);
        r.scope_id = col_text(st, 1);
        r.logical_rel_path = col_text(st, 2);
        r.item_kind = col_text(st, 3);
        r.locked_by_fp = col_text(st, 4);
        r.note = col_text(st, 5);
        r.created_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 6));
        r.updated_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 7));
        r.expires_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 8));
        out.push_back(std::move(r));
    }

    if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
        out.clear();
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}

bool FileLocksStore::upsert_lock(const FileLockRec& rec, std::string* err) const {
    if (!init(err)) return false;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    const char* sql =
        "INSERT INTO file_locks ("
        "  scope_type, scope_id, logical_rel_path, item_kind, locked_by_fp, note, "
        "  created_at_epoch, updated_at_epoch, expires_at_epoch"
        ") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) "
        "ON CONFLICT(scope_type, scope_id, logical_rel_path) DO UPDATE SET "
        "  item_kind = excluded.item_kind,"
        "  locked_by_fp = excluded.locked_by_fp,"
        "  note = excluded.note,"
        "  updated_at_epoch = excluded.updated_at_epoch,"
        "  expires_at_epoch = excluded.expires_at_epoch;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }

    bool ok = true;
    ok = ok && bind_text(st, 1, rec.scope_type);
    ok = ok && bind_text(st, 2, rec.scope_id);
    ok = ok && bind_text(st, 3, rec.logical_rel_path);
    ok = ok && bind_text(st, 4, rec.item_kind);
    ok = ok && bind_text(st, 5, rec.locked_by_fp);
    ok = ok && bind_text(st, 6, rec.note);
    ok = ok && sqlite3_bind_int64(st, 7, rec.created_at_epoch) == SQLITE_OK;
    ok = ok && sqlite3_bind_int64(st, 8, rec.updated_at_epoch) == SQLITE_OK;
    ok = ok && sqlite3_bind_int64(st, 9, rec.expires_at_epoch) == SQLITE_OK;

    if (!ok) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

bool FileLocksStore::delete_lock(const std::string& scope_type,
                                 const std::string& scope_id,
                                 const std::string& logical_rel_path,
                                 std::string* err) const {
    if (!init(err)) return false;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    const char* sql =
        "DELETE FROM file_locks "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }

    bool ok = true;
    ok = ok && bind_text(st, 1, scope_type);
    ok = ok && bind_text(st, 2, scope_id);
    ok = ok && bind_text(st, 3, logical_rel_path);

    if (!ok) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

bool FileLocksStore::delete_expired(std::int64_t now_epoch, std::string* err) const {
    if (now_epoch <= 0) return true;
    if (!init(err)) return false;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    const char* sql =
        "DELETE FROM file_locks "
        "WHERE expires_at_epoch > 0 AND expires_at_epoch <= ?1;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }

    if (sqlite3_bind_int64(st, 1, now_epoch) != SQLITE_OK) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

} // namespace pqnas
