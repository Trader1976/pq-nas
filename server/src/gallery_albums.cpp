#include "gallery_albums.h"

#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <string>

namespace pqnas {

namespace {

GalleryAlbumsIndex* g_gallery_albums_index = nullptr;

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

static std::string col_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* p = sqlite3_column_text(stmt, col);
    return p ? reinterpret_cast<const char*>(p) : "";
}

static bool column_exists_local(sqlite3* db,
                                    const char* table_name,
                                    const char* column_name,
                                    bool* out_exists,
                                    std::string* err) {
    if (out_exists) *out_exists = false;
    if (err) err->clear();

    if (!db || !table_name || !column_name || !out_exists) {
        if (err) *err = "invalid column_exists args";
        return false;
    }

    const std::string sql = std::string("PRAGMA table_info(") + table_name + ")";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db);
        return false;
    }

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db);
            sqlite3_finalize(stmt);
            return false;
        }

        // PRAGMA table_info columns:
        // 0 cid, 1 name, 2 type, ...
        if (col_text(stmt, 1) == column_name) {
            *out_exists = true;
            break;
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

static bool is_valid_scope_type_local(const std::string& s) {
    return s == "user" || s == "workspace";
}

static std::string trim_album_text_local(std::string s, std::size_t max_len) {
    while (!s.empty() && static_cast<unsigned char>(s.front()) <= 32) s.erase(s.begin());
    while (!s.empty() && static_cast<unsigned char>(s.back()) <= 32) s.pop_back();

    if (s.size() > max_len) s.resize(max_len);
    return s;
}

static GalleryAlbumRec row_to_album_local(sqlite3_stmt* stmt) {
    GalleryAlbumRec rec;
    rec.album_id = col_text(stmt, 0);
    rec.scope_type = col_text(stmt, 1);
    rec.scope_id = col_text(stmt, 2);
    rec.name = col_text(stmt, 3);
    rec.description = col_text(stmt, 4);
    rec.cover_logical_rel_path = col_text(stmt, 5);
    rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
    rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
    rec.item_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 8));
    return rec;
}

static GalleryAlbumItemRec row_to_item_local(sqlite3_stmt* stmt) {
    GalleryAlbumItemRec rec;
    rec.album_id = col_text(stmt, 0);
    rec.scope_type = col_text(stmt, 1);
    rec.scope_id = col_text(stmt, 2);
    rec.logical_rel_path = col_text(stmt, 3);
    rec.added_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 4));
    rec.sort_order = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 5));
    return rec;
}

} // namespace

GalleryAlbumsIndex::GalleryAlbumsIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

GalleryAlbumsIndex::~GalleryAlbumsIndex() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool GalleryAlbumsIndex::open(std::string* err) {
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
        if (err) *err = db_ ? sqlite3_errmsg(db_) : "sqlite open failed";
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    if (!exec_sql(db_, "PRAGMA journal_mode=WAL;", err)) return false;
    if (!exec_sql(db_, "PRAGMA synchronous=NORMAL;", err)) return false;
    if (!exec_sql(db_, "PRAGMA foreign_keys=ON;", err)) return false;

    return true;
}

bool GalleryAlbumsIndex::init_schema(std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS gallery_albums (
    album_id      TEXT NOT NULL,
    scope_type    TEXT NOT NULL,
    scope_id      TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    cover_logical_rel_path TEXT NOT NULL DEFAULT '',
    created_epoch INTEGER NOT NULL,
    updated_epoch INTEGER NOT NULL,

    PRIMARY KEY (scope_type, scope_id, album_id)
);

CREATE TABLE IF NOT EXISTS gallery_album_items (
    album_id         TEXT NOT NULL,
    scope_type       TEXT NOT NULL,
    scope_id         TEXT NOT NULL,
    logical_rel_path TEXT NOT NULL,
    added_epoch      INTEGER NOT NULL,
    sort_order       INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (scope_type, scope_id, album_id, logical_rel_path),

    FOREIGN KEY (scope_type, scope_id, album_id)
        REFERENCES gallery_albums(scope_type, scope_id, album_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_gallery_albums_scope_updated
ON gallery_albums(scope_type, scope_id, updated_epoch DESC);

CREATE INDEX IF NOT EXISTS idx_gallery_album_items_album_sort
ON gallery_album_items(scope_type, scope_id, album_id, sort_order, added_epoch);
)SQL";

    if (!exec_sql(db_, kSchema, err)) return false;

    bool has_cover = false;
    if (!column_exists_local(db_, "gallery_albums", "cover_logical_rel_path", &has_cover, err)) {
        return false;
    }

    if (!has_cover) {
        if (!exec_sql(db_,
                      "ALTER TABLE gallery_albums "
                      "ADD COLUMN cover_logical_rel_path TEXT NOT NULL DEFAULT '';",
                      err)) {
            return false;
                      }
    }

    return true;
}

bool GalleryAlbumsIndex::create_album(const GalleryAlbumRec& rec_in, std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }
    if (!is_valid_scope_type_local(rec_in.scope_type)) {
        if (err) *err = "invalid scope_type";
        return false;
    }
    if (rec_in.scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return false;
    }
    if (rec_in.album_id.empty()) {
        if (err) *err = "empty album_id";
        return false;
    }

    const std::string name = trim_album_text_local(rec_in.name, 120);
    const std::string desc = trim_album_text_local(rec_in.description, 2000);
    if (name.empty()) {
        if (err) *err = "empty album name";
        return false;
    }

    static const char* kSql =
        "INSERT INTO gallery_albums ("
        "  album_id, scope_type, scope_id, name, description, created_epoch, updated_epoch"
        ") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec_in.album_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec_in.scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec_in.scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, desc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(rec_in.created_epoch));
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(rec_in.updated_epoch));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

std::optional<GalleryAlbumRec> GalleryAlbumsIndex::get_album(const std::string& scope_type,
                                                             const std::string& scope_id,
                                                             const std::string& album_id,
                                                             std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    static const char* kSql =
        "SELECT a.album_id, a.scope_type, a.scope_id, a.name, a.description, "
        "       COALESCE(NULLIF(a.cover_logical_rel_path, ''), "
        "           (SELECT ai.logical_rel_path "
        "            FROM gallery_album_items ai "
        "            WHERE ai.scope_type = a.scope_type "
        "              AND ai.scope_id = a.scope_id "
        "              AND ai.album_id = a.album_id "
        "            ORDER BY ai.sort_order ASC, ai.added_epoch ASC, ai.logical_rel_path ASC "
        "            LIMIT 1), "
        "           '') AS cover_logical_rel_path, "
        "       a.created_epoch, a.updated_epoch, "
        "       COUNT(i.logical_rel_path) AS item_count "
        "FROM gallery_albums a "
        "LEFT JOIN gallery_album_items i "
        "  ON i.scope_type = a.scope_type "
        " AND i.scope_id = a.scope_id "
        " AND i.album_id = a.album_id "
        "WHERE a.scope_type = ?1 AND a.scope_id = ?2 AND a.album_id = ?3 "
        "GROUP BY a.album_id, a.scope_type, a.scope_id, a.name, a.description, "
        "         a.cover_logical_rel_path, a.created_epoch, a.updated_epoch";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, album_id.c_str(), -1, SQLITE_TRANSIENT);

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

    GalleryAlbumRec rec = row_to_album_local(stmt);
    sqlite3_finalize(stmt);
    return rec;
}

std::vector<GalleryAlbumRec> GalleryAlbumsIndex::list_albums(const std::string& scope_type,
                                                             const std::string& scope_id,
                                                             std::size_t limit,
                                                             std::string* err) {
    if (err) err->clear();
    std::vector<GalleryAlbumRec> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT a.album_id, a.scope_type, a.scope_id, a.name, a.description, "
        "       COALESCE(NULLIF(a.cover_logical_rel_path, ''), "
        "           (SELECT ai.logical_rel_path "
        "            FROM gallery_album_items ai "
        "            WHERE ai.scope_type = a.scope_type "
        "              AND ai.scope_id = a.scope_id "
        "              AND ai.album_id = a.album_id "
        "            ORDER BY ai.sort_order ASC, ai.added_epoch ASC, ai.logical_rel_path ASC "
        "            LIMIT 1), "
        "           '') AS cover_logical_rel_path, "
        "       a.created_epoch, a.updated_epoch, "
        "       COUNT(i.logical_rel_path) AS item_count "
        "FROM gallery_albums a "
        "LEFT JOIN gallery_album_items i "
        "  ON i.scope_type = a.scope_type "
        " AND i.scope_id = a.scope_id "
        " AND i.album_id = a.album_id "
        "WHERE a.scope_type = ?1 AND a.scope_id = ?2 "
        "GROUP BY a.album_id, a.scope_type, a.scope_id, a.name, a.description, "
        "         a.cover_logical_rel_path, a.created_epoch, a.updated_epoch "
        "ORDER BY a.updated_epoch DESC, a.created_epoch DESC "
        "LIMIT ?3";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(limit ? limit : 500));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            return {};
        }
        out.push_back(row_to_album_local(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

bool GalleryAlbumsIndex::rename_album(const std::string& scope_type,
                                      const std::string& scope_id,
                                      const std::string& album_id,
                                      const std::string& name_in,
                                      const std::string& description_in,
                                      std::int64_t now_epoch,
                                      std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const std::string name = trim_album_text_local(name_in, 120);
    const std::string desc = trim_album_text_local(description_in, 2000);
    if (name.empty()) {
        if (err) *err = "empty album name";
        return false;
    }

    static const char* kSql =
        "UPDATE gallery_albums "
        "SET name = ?1, description = ?2, updated_epoch = ?3 "
        "WHERE scope_type = ?4 AND scope_id = ?5 AND album_id = ?6";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, desc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(now_epoch));
    sqlite3_bind_text(stmt, 4, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, album_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed <= 0) {
        if (err) *err = "album not found";
        return false;
    }

    return true;
}

bool GalleryAlbumsIndex::set_album_cover(const std::string& scope_type,
                                         const std::string& scope_id,
                                         const std::string& album_id,
                                         const std::string& logical_rel_path,
                                         std::int64_t now_epoch,
                                         std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (!is_valid_scope_type_local(scope_type)) {
        if (err) *err = "invalid scope_type";
        return false;
    }
    if (scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return false;
    }
    if (album_id.empty()) {
        if (err) *err = "empty album_id";
        return false;
    }
    if (logical_rel_path.size() > 4096) {
        if (err) *err = "cover path too long";
        return false;
    }

    const bool clear_cover = logical_rel_path.empty();

    const char* kClearSql =
        "UPDATE gallery_albums "
        "SET cover_logical_rel_path = '', updated_epoch = ?1 "
        "WHERE scope_type = ?2 AND scope_id = ?3 AND album_id = ?4";

    const char* kSetSql =
        "UPDATE gallery_albums "
        "SET cover_logical_rel_path = ?1, updated_epoch = ?2 "
        "WHERE scope_type = ?3 AND scope_id = ?4 AND album_id = ?5 "
        "  AND EXISTS ("
        "    SELECT 1 FROM gallery_album_items i "
        "    WHERE i.scope_type = gallery_albums.scope_type "
        "      AND i.scope_id = gallery_albums.scope_id "
        "      AND i.album_id = gallery_albums.album_id "
        "      AND i.logical_rel_path = ?1"
        "  )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, clear_cover ? kClearSql : kSetSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    if (clear_cover) {
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now_epoch));
        sqlite3_bind_text(stmt, 2, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, album_id.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 1, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(now_epoch));
        sqlite3_bind_text(stmt, 3, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, album_id.c_str(), -1, SQLITE_TRANSIENT);
    }

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed <= 0) {
        if (err) {
            *err = clear_cover
                ? "album not found"
                : "album not found or cover path is not in album";
        }
        return false;
    }

    return true;
}

    bool GalleryAlbumsIndex::delete_album(const std::string& scope_type,
                                          const std::string& scope_id,
                                          const std::string& album_id,
                                          std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "DELETE FROM gallery_albums "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND album_id = ?3";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, album_id.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool GalleryAlbumsIndex::add_items(const std::string& scope_type,
                                   const std::string& scope_id,
                                   const std::string& album_id,
                                   const std::vector<std::string>& logical_rel_paths,
                                   std::int64_t now_epoch,
                                   std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (logical_rel_paths.empty()) return true;

    char* msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &msg) != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);

    auto rollback = [&]() {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    };

    static const char* kInsert =
        "INSERT OR IGNORE INTO gallery_album_items ("
        "  album_id, scope_type, scope_id, logical_rel_path, added_epoch, sort_order"
        ") VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

    sqlite3_stmt* ins = nullptr;
    if (sqlite3_prepare_v2(db_, kInsert, -1, &ins, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    std::int64_t order = now_epoch;

    for (const std::string& path : logical_rel_paths) {
        if (path.empty()) continue;

        sqlite3_reset(ins);
        sqlite3_clear_bindings(ins);

        sqlite3_bind_text(ins, 1, album_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 3, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 4, path.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins, 5, static_cast<sqlite3_int64>(now_epoch));
        sqlite3_bind_int64(ins, 6, static_cast<sqlite3_int64>(order++));

        const int rc = sqlite3_step(ins);
        if (rc != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(ins);
            rollback();
            return false;
        }
    }

    sqlite3_finalize(ins);

    static const char* kTouch =
        "UPDATE gallery_albums "
        "SET updated_epoch = ?1 "
        "WHERE scope_type = ?2 AND scope_id = ?3 AND album_id = ?4";

    sqlite3_stmt* touch = nullptr;
    if (sqlite3_prepare_v2(db_, kTouch, -1, &touch, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    sqlite3_bind_int64(touch, 1, static_cast<sqlite3_int64>(now_epoch));
    sqlite3_bind_text(touch, 2, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(touch, 3, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(touch, 4, album_id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(touch) != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(touch);
        rollback();
        return false;
    }

    sqlite3_finalize(touch);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &msg) != SQLITE_OK) {
        if (err) *err = msg ? msg : sqlite3_errmsg(db_);
        if (msg) sqlite3_free(msg);
        rollback();
        return false;
    }
    if (msg) sqlite3_free(msg);

    return true;
}

std::vector<GalleryAlbumItemRec> GalleryAlbumsIndex::list_items(const std::string& scope_type,
                                                                const std::string& scope_id,
                                                                const std::string& album_id,
                                                                std::size_t limit,
                                                                std::string* err) {
    if (err) err->clear();
    std::vector<GalleryAlbumItemRec> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    static const char* kSql =
        "SELECT album_id, scope_type, scope_id, logical_rel_path, added_epoch, sort_order "
        "FROM gallery_album_items "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND album_id = ?3 "
        "ORDER BY sort_order ASC, added_epoch ASC, logical_rel_path ASC "
        "LIMIT ?4";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, album_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(limit ? limit : 2000));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            return {};
        }
        out.push_back(row_to_item_local(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

bool GalleryAlbumsIndex::remove_items(const std::string& scope_type,
                                      const std::string& scope_id,
                                      const std::string& album_id,
                                      const std::vector<std::string>& logical_rel_paths,
                                      std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (logical_rel_paths.empty()) return true;

    static const char* kDeleteSql =
        "DELETE FROM gallery_album_items "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND album_id = ?3 AND logical_rel_path = ?4";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kDeleteSql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    static const char* kClearCoverSql =
        "UPDATE gallery_albums "
        "SET cover_logical_rel_path = '', updated_epoch = CAST(strftime('%s','now') AS INTEGER) "
        "WHERE scope_type = ?1 "
        "  AND scope_id = ?2 "
        "  AND album_id = ?3 "
        "  AND cover_logical_rel_path = ?4";

    sqlite3_stmt* clear_cover = nullptr;
    if (sqlite3_prepare_v2(db_, kClearCoverSql, -1, &clear_cover, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    for (const std::string& path : logical_rel_paths) {
        if (path.empty()) continue;

        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, album_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, path.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            sqlite3_finalize(clear_cover);
            return false;
        }

        sqlite3_reset(clear_cover);
        sqlite3_clear_bindings(clear_cover);

        sqlite3_bind_text(clear_cover, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(clear_cover, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(clear_cover, 3, album_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(clear_cover, 4, path.c_str(), -1, SQLITE_TRANSIENT);

        const int rc_cover = sqlite3_step(clear_cover);
        if (rc_cover != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            sqlite3_finalize(clear_cover);
            return false;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_finalize(clear_cover);
    return true;
}

void set_gallery_albums_index(GalleryAlbumsIndex* idx) {
    g_gallery_albums_index = idx;
}

GalleryAlbumsIndex* get_gallery_albums_index() {
    return g_gallery_albums_index;
}

} // namespace pqnas