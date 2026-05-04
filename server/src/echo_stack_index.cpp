#include "echo_stack_index.h"

#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <sstream>

namespace pqnas {
namespace {

static std::string col_text(sqlite3_stmt* st, int idx) {
    const unsigned char* p = sqlite3_column_text(st, idx);
    return p ? reinterpret_cast<const char*>(p) : std::string();
}

static void bind_text(sqlite3_stmt* st, int idx, const std::string& s) {
    sqlite3_bind_text(st, idx, s.c_str(), -1, SQLITE_TRANSIENT);
}

static EchoStackItemRec row_to_rec(sqlite3_stmt* st) {
    EchoStackItemRec r;
    r.id                = col_text(st, 0);
    r.owner_fp          = col_text(st, 1);
    r.url               = col_text(st, 2);
    r.final_url         = col_text(st, 3);
    r.title             = col_text(st, 4);
    r.description       = col_text(st, 5);
    r.site_name         = col_text(st, 6);
    r.favicon_url       = col_text(st, 7);
    r.preview_image_url = col_text(st, 8);
    r.tags_text         = col_text(st, 9);
    r.collection        = col_text(st, 10);
    r.notes             = col_text(st, 11);
    r.read_state        = col_text(st, 12);
    r.favorite          = sqlite3_column_int(st, 13) != 0;
    r.archive_status    = col_text(st, 14);
    r.archive_error     = col_text(st, 15);
    r.archive_rel_dir   = col_text(st, 16);
    r.archive_bytes     = static_cast<std::uint64_t>(sqlite3_column_int64(st, 17));
    r.created_epoch     = static_cast<std::int64_t>(sqlite3_column_int64(st, 18));
    r.updated_epoch     = static_cast<std::int64_t>(sqlite3_column_int64(st, 19));
    r.archived_epoch    = static_cast<std::int64_t>(sqlite3_column_int64(st, 20));
    return r;
}

static const char* kSelectCols =
    "id, owner_fp, url, final_url, title, description, site_name, "
    "favicon_url, preview_image_url, tags_text, collection, notes, "
    "read_state, favorite, archive_status, archive_error, archive_rel_dir, "
    "archive_bytes, created_epoch, updated_epoch, archived_epoch";

} // namespace

EchoStackIndex::EchoStackIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

EchoStackIndex::~EchoStackIndex() {
    std::lock_guard<std::mutex> lk(mu_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool EchoStackIndex::open(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (db_) return true;

    std::error_code ec;
    std::filesystem::create_directories(db_path_.parent_path(), ec);
    if (ec) {
        if (err) *err = "failed to create db directory: " + ec.message();
        return false;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path_.string().c_str(), &db) != SQLITE_OK) {
        if (err) *err = db ? sqlite3_errmsg(db) : "sqlite open failed";
        if (db) sqlite3_close(db);
        return false;
    }

    db_ = db;

    char* emsg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &emsg);
    if (emsg) sqlite3_free(emsg);

    emsg = nullptr;
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, &emsg);
    if (emsg) sqlite3_free(emsg);

    return true;
}

bool EchoStackIndex::init_schema(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = R"SQL(
CREATE TABLE IF NOT EXISTS echo_stack_items (
    id                TEXT PRIMARY KEY,
    owner_fp          TEXT NOT NULL,

    url               TEXT NOT NULL,
    final_url         TEXT NOT NULL DEFAULT '',
    title             TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    site_name         TEXT NOT NULL DEFAULT '',
    favicon_url       TEXT NOT NULL DEFAULT '',
    preview_image_url TEXT NOT NULL DEFAULT '',

    tags_text         TEXT NOT NULL DEFAULT '',
    collection        TEXT NOT NULL DEFAULT '',
    notes             TEXT NOT NULL DEFAULT '',

    read_state        TEXT NOT NULL DEFAULT 'unread',
    favorite          INTEGER NOT NULL DEFAULT 0,

    archive_status    TEXT NOT NULL DEFAULT 'none',
    archive_error     TEXT NOT NULL DEFAULT '',
    archive_rel_dir   TEXT NOT NULL DEFAULT '',
    archive_bytes     INTEGER NOT NULL DEFAULT 0,

    created_epoch     INTEGER NOT NULL DEFAULT 0,
    updated_epoch     INTEGER NOT NULL DEFAULT 0,
    archived_epoch    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_echo_stack_owner_created
ON echo_stack_items(owner_fp, created_epoch DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_echo_stack_owner_collection
ON echo_stack_items(owner_fp, collection, created_epoch DESC);

CREATE INDEX IF NOT EXISTS idx_echo_stack_owner_favorite
ON echo_stack_items(owner_fp, favorite, created_epoch DESC);

CREATE INDEX IF NOT EXISTS idx_echo_stack_owner_archive
ON echo_stack_items(owner_fp, archive_status, created_epoch DESC);
)SQL";

    char* emsg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &emsg) != SQLITE_OK) {
        if (err) *err = emsg ? emsg : "schema init failed";
        if (emsg) sqlite3_free(emsg);
        return false;
    }
    if (emsg) sqlite3_free(emsg);
    return true;
}

bool EchoStackIndex::insert(const EchoStackItemRec& rec, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql =
        "INSERT INTO echo_stack_items ("
        "id, owner_fp, url, final_url, title, description, site_name, "
        "favicon_url, preview_image_url, tags_text, collection, notes, "
        "read_state, favorite, archive_status, archive_error, archive_rel_dir, "
        "archive_bytes, created_epoch, updated_epoch, archived_epoch"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, rec.id);
    bind_text(st, 2, rec.owner_fp);
    bind_text(st, 3, rec.url);
    bind_text(st, 4, rec.final_url);
    bind_text(st, 5, rec.title);
    bind_text(st, 6, rec.description);
    bind_text(st, 7, rec.site_name);
    bind_text(st, 8, rec.favicon_url);
    bind_text(st, 9, rec.preview_image_url);
    bind_text(st, 10, rec.tags_text);
    bind_text(st, 11, rec.collection);
    bind_text(st, 12, rec.notes);
    bind_text(st, 13, rec.read_state);
    sqlite3_bind_int(st, 14, rec.favorite ? 1 : 0);
    bind_text(st, 15, rec.archive_status);
    bind_text(st, 16, rec.archive_error);
    bind_text(st, 17, rec.archive_rel_dir);
    sqlite3_bind_int64(st, 18, static_cast<sqlite3_int64>(rec.archive_bytes));
    sqlite3_bind_int64(st, 19, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_int64(st, 20, static_cast<sqlite3_int64>(rec.updated_epoch));
    sqlite3_bind_int64(st, 21, static_cast<sqlite3_int64>(rec.archived_epoch));

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

std::optional<EchoStackItemRec> EchoStackIndex::get_owner_item(const std::string& owner_fp,
                                                               const std::string& id,
                                                               std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kSelectCols +
        " FROM echo_stack_items WHERE owner_fp=?1 AND id=?2 LIMIT 1";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    bind_text(st, 1, owner_fp);
    bind_text(st, 2, id);

    std::optional<EchoStackItemRec> out;
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        out = row_to_rec(st);
    } else if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
    }

    sqlite3_finalize(st);
    return out;
}

std::vector<EchoStackItemRec> EchoStackIndex::list_owner(const std::string& owner_fp,
                                                         const std::string& query,
                                                         std::size_t limit,
                                                         std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<EchoStackItemRec> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    const std::string sql = std::string("SELECT ") + kSelectCols + R"SQL(
FROM echo_stack_items
WHERE owner_fp=?1
  AND (
    ?2 = ''
    OR title LIKE ?3
    OR url LIKE ?3
    OR description LIKE ?3
    OR notes LIKE ?3
    OR tags_text LIKE ?3
    OR collection LIKE ?3
  )
ORDER BY created_epoch DESC, id DESC
LIMIT ?4
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    const std::string pat = "%" + query + "%";

    bind_text(st, 1, owner_fp);
    bind_text(st, 2, query);
    bind_text(st, 3, pat);
    sqlite3_bind_int64(st, 4, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            out.push_back(row_to_rec(st));
            continue;
        }
        if (rc == SQLITE_DONE) break;
        if (err) *err = sqlite3_errmsg(db_);
        break;
    }

    sqlite3_finalize(st);
    return out;
}

bool EchoStackIndex::update_mutable(const EchoStackItemRec& rec, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql =
        "UPDATE echo_stack_items SET "
        "url=?1, final_url=?2, title=?3, description=?4, site_name=?5, "
        "favicon_url=?6, preview_image_url=?7, tags_text=?8, collection=?9, "
        "notes=?10, read_state=?11, favorite=?12, updated_epoch=?13 "
        "WHERE owner_fp=?14 AND id=?15";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, rec.url);
    bind_text(st, 2, rec.final_url);
    bind_text(st, 3, rec.title);
    bind_text(st, 4, rec.description);
    bind_text(st, 5, rec.site_name);
    bind_text(st, 6, rec.favicon_url);
    bind_text(st, 7, rec.preview_image_url);
    bind_text(st, 8, rec.tags_text);
    bind_text(st, 9, rec.collection);
    bind_text(st, 10, rec.notes);
    bind_text(st, 11, rec.read_state);
    sqlite3_bind_int(st, 12, rec.favorite ? 1 : 0);
    sqlite3_bind_int64(st, 13, static_cast<sqlite3_int64>(rec.updated_epoch));
    bind_text(st, 14, rec.owner_fp);
    bind_text(st, 15, rec.id);

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    const bool changed = sqlite3_changes(db_) > 0;
    sqlite3_finalize(st);

    if (!changed && err) *err = "not_found";
    return changed;
}

bool EchoStackIndex::delete_owner_item(const std::string& owner_fp,
                                       const std::string& id,
                                       std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = "DELETE FROM echo_stack_items WHERE owner_fp=?1 AND id=?2";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, owner_fp);
    bind_text(st, 2, id);

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    const bool changed = sqlite3_changes(db_) > 0;
    sqlite3_finalize(st);

    if (!changed && err) *err = "not_found";
    return changed;
}

} // namespace pqnas
