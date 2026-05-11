#include "file_annotations.h"

#include <filesystem>
#include <string>
#include <system_error>

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
            set_err(err, "failed to create annotation db directory: " + ec.message());
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

FileAnnotationsStore::FileAnnotationsStore(std::filesystem::path db_path)
    : db_path_(std::move(db_path)) {}

bool FileAnnotationsStore::init(std::string* err) const {
    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    bool ok = true;
    ok = ok && exec_sql(db, "PRAGMA journal_mode=WAL;", err);
    ok = ok && exec_sql(db, "PRAGMA synchronous=NORMAL;", err);
    ok = ok && exec_sql(db,
        "CREATE TABLE IF NOT EXISTS file_notes ("
        "  scope_type TEXT NOT NULL,"
        "  scope_id TEXT NOT NULL,"
        "  logical_rel_path TEXT NOT NULL,"
        "  item_kind TEXT NOT NULL DEFAULT 'unknown',"
        "  description TEXT NOT NULL DEFAULT '',"
        "  updated_by_fp TEXT NOT NULL DEFAULT '',"
        "  created_at_epoch INTEGER NOT NULL DEFAULT 0,"
        "  updated_at_epoch INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(scope_type, scope_id, logical_rel_path)"
        ");",
        err);

    sqlite3_close(db);
    return ok;
}

std::optional<FileNoteRec> FileAnnotationsStore::get_note(const std::string& scope_type,
                                                          const std::string& scope_id,
                                                          const std::string& logical_rel_path,
                                                          std::string* err) const {
    if (!init(err)) return std::nullopt;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return std::nullopt;

    const char* sql =
        "SELECT scope_type, scope_id, logical_rel_path, item_kind, description, "
        "       updated_by_fp, created_at_epoch, updated_at_epoch "
        "FROM file_notes "
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

    std::optional<FileNoteRec> out;
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        FileNoteRec r;
        r.scope_type = col_text(st, 0);
        r.scope_id = col_text(st, 1);
        r.logical_rel_path = col_text(st, 2);
        r.item_kind = col_text(st, 3);
        r.description = col_text(st, 4);
        r.updated_by_fp = col_text(st, 5);
        r.created_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 6));
        r.updated_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 7));
        out = std::move(r);
    } else if (rc != SQLITE_DONE) {
        set_err(err, sqlite3_errmsg(db));
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}

bool FileAnnotationsStore::upsert_note(const FileNoteRec& rec, std::string* err) const {
    if (!init(err)) return false;

    sqlite3* db = nullptr;
    if (!open_db(db_path_, &db, err)) return false;

    const char* sql =
        "INSERT INTO file_notes ("
        "  scope_type, scope_id, logical_rel_path, item_kind, description, "
        "  updated_by_fp, created_at_epoch, updated_at_epoch"
        ") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) "
        "ON CONFLICT(scope_type, scope_id, logical_rel_path) DO UPDATE SET "
        "  item_kind = excluded.item_kind,"
        "  description = excluded.description,"
        "  updated_by_fp = excluded.updated_by_fp,"
        "  updated_at_epoch = excluded.updated_at_epoch;";

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
    ok = ok && bind_text(st, 5, rec.description);
    ok = ok && bind_text(st, 6, rec.updated_by_fp);
    ok = ok && sqlite3_bind_int64(st, 7, rec.created_at_epoch) == SQLITE_OK;
    ok = ok && sqlite3_bind_int64(st, 8, rec.updated_at_epoch) == SQLITE_OK;

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

} // namespace pqnas
