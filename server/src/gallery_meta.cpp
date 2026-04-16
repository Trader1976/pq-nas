#include "gallery_meta.h"

#include <sqlite3.h>

#include <algorithm>
#include <string>

namespace pqnas {

namespace {
    

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

static bool begin_tx(sqlite3* db, std::string* err) {
    return exec_sql(db, "BEGIN IMMEDIATE;", err);
}

static bool commit_tx(sqlite3* db, std::string* err) {
    return exec_sql(db, "COMMIT;", err);
}

static void rollback_tx(sqlite3* db) {
    sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
}

static bool is_valid_scope_type_local(const std::string& s) {
    return s == "user" || s == "workspace";
}

static std::string normalize_item_type_local(const std::string& s) {
    if (s == "dir") return "dir";
    return "file";
}

static int clamp_rating_local(int r) {
    return std::max(0, std::min(5, r));
}

static GalleryMetaRec row_to_rec_local(sqlite3_stmt* stmt) {
    GalleryMetaRec rec;
    rec.scope_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    rec.scope_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    rec.item_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    rec.rating = static_cast<int>(sqlite3_column_int(stmt, 4));
    rec.tags_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    rec.notes_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 7));
    rec.mtime_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));
    rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));
    rec.updated_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 10));
    rec.rating = clamp_rating_local(rec.rating);
    rec.item_type = normalize_item_type_local(rec.item_type);
    return rec;
}

} // namespace



GalleryMetaIndex::GalleryMetaIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

GalleryMetaIndex::~GalleryMetaIndex() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool GalleryMetaIndex::open(std::string* err) {
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

bool GalleryMetaIndex::init_schema(std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS gallery_meta (
    scope_type       TEXT NOT NULL,
    scope_id         TEXT NOT NULL,
    logical_rel_path TEXT NOT NULL,
    item_type        TEXT NOT NULL DEFAULT 'file',

    rating           INTEGER NOT NULL DEFAULT 0,
    tags_text        TEXT NOT NULL DEFAULT '',
    notes_text       TEXT NOT NULL DEFAULT '',

    size_bytes       INTEGER NOT NULL DEFAULT 0,
    mtime_epoch      INTEGER NOT NULL DEFAULT 0,
    created_epoch    INTEGER NOT NULL,
    updated_epoch    INTEGER NOT NULL,

    PRIMARY KEY (scope_type, scope_id, logical_rel_path)
);

CREATE INDEX IF NOT EXISTS idx_gallery_meta_scope_path
ON gallery_meta(scope_type, scope_id, logical_rel_path);

CREATE INDEX IF NOT EXISTS idx_gallery_meta_scope_rating
ON gallery_meta(scope_type, scope_id, rating);
)SQL";

    return exec_sql(db_, kSchema, err);
}

std::optional<GalleryMetaRec> GalleryMetaIndex::get(const std::string& scope_type,
                                                    const std::string& scope_id,
                                                    const std::string& logical_rel_path,
                                                    std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }
    if (!is_valid_scope_type_local(scope_type)) {
        if (err) *err = "invalid scope_type";
        return std::nullopt;
    }
    if (scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return std::nullopt;
    }
    if (logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return std::nullopt;
    }

    static const char* kSql =
        "SELECT scope_type, scope_id, logical_rel_path, item_type, "
        "       rating, tags_text, notes_text, size_bytes, mtime_epoch, "
        "       created_epoch, updated_epoch "
        "FROM gallery_meta "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

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

    GalleryMetaRec rec = row_to_rec_local(stmt);
    sqlite3_finalize(stmt);
    return rec;
}

bool GalleryMetaIndex::upsert(const GalleryMetaRec& rec_in, std::string* err) {
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
    if (rec_in.logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }

    const GalleryMetaRec rec{
        rec_in.scope_type,
        rec_in.scope_id,
        rec_in.logical_rel_path,
        normalize_item_type_local(rec_in.item_type),
        clamp_rating_local(rec_in.rating),
        rec_in.tags_text,
        rec_in.notes_text,
        rec_in.size_bytes,
        rec_in.mtime_epoch,
        rec_in.created_epoch,
        rec_in.updated_epoch
    };

    static const char* kSql =
        "INSERT INTO gallery_meta ("
        "  scope_type, scope_id, logical_rel_path, item_type, "
        "  rating, tags_text, notes_text, size_bytes, mtime_epoch, created_epoch, updated_epoch"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, "
        "  ?5, ?6, ?7, ?8, ?9, ?10, ?11"
        ") "
        "ON CONFLICT(scope_type, scope_id, logical_rel_path) DO UPDATE SET "
        "  item_type = excluded.item_type, "
        "  rating = excluded.rating, "
        "  tags_text = excluded.tags_text, "
        "  notes_text = excluded.notes_text, "
        "  size_bytes = excluded.size_bytes, "
        "  mtime_epoch = excluded.mtime_epoch, "
        "  updated_epoch = excluded.updated_epoch";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.item_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, rec.rating);
    sqlite3_bind_text(stmt, 6, rec.tags_text.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rec.notes_text.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(rec.size_bytes));
    sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(rec.mtime_epoch));
    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_int64(stmt, 11, static_cast<sqlite3_int64>(rec.updated_epoch));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool GalleryMetaIndex::patch(const std::string& scope_type,
                             const std::string& scope_id,
                             const std::string& logical_rel_path,
                             const std::optional<int>& rating,
                             const std::optional<std::string>& tags_text,
                             const std::optional<std::string>& notes_text,
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
    if (logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }
    if (now_epoch < 0) {
        if (err) *err = "invalid now_epoch";
        return false;
    }

    std::string gerr;
    auto existing = get(scope_type, scope_id, logical_rel_path, &gerr);
    if (!gerr.empty()) {
        if (err) *err = gerr;
        return false;
    }

    GalleryMetaRec rec;
    if (existing.has_value()) {
        rec = *existing;
    } else {
        rec.scope_type = scope_type;
        rec.scope_id = scope_id;
        rec.logical_rel_path = logical_rel_path;
        rec.item_type = "file";
        rec.rating = 0;
        rec.tags_text.clear();
        rec.notes_text.clear();
        rec.size_bytes = 0;
        rec.mtime_epoch = 0;
        rec.created_epoch = now_epoch;
        rec.updated_epoch = now_epoch;
    }

    if (rating.has_value()) rec.rating = clamp_rating_local(*rating);
    if (tags_text.has_value()) rec.tags_text = *tags_text;
    if (notes_text.has_value()) rec.notes_text = *notes_text;
    rec.updated_epoch = now_epoch;

    return upsert(rec, err);
}

bool GalleryMetaIndex::touch_file_facts(const std::string& scope_type,
                                        const std::string& scope_id,
                                        const std::string& logical_rel_path,
                                        std::uint64_t size_bytes,
                                        std::int64_t mtime_epoch,
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
    if (logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }

    static const char* kSql =
        "UPDATE gallery_meta "
        "SET item_type = 'file', "
        "    size_bytes = ?4, "
        "    mtime_epoch = ?5, "
        "    updated_epoch = ?6 "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(size_bytes));
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(mtime_epoch));
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(now_epoch));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool GalleryMetaIndex::rename_one(const std::string& scope_type,
                                  const std::string& scope_id,
                                  const std::string& from_rel,
                                  const std::string& to_rel,
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
    if (from_rel.empty() || to_rel.empty()) {
        if (err) *err = "empty path";
        return false;
    }
    if (from_rel == to_rel) return true;

    static const char* kSql =
        "UPDATE gallery_meta "
        "SET logical_rel_path = ?4, "
        "    updated_epoch = ?5 "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_rel.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, to_rel.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now_epoch));

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool GalleryMetaIndex::rename_subtree(const std::string& scope_type,
                                      const std::string& scope_id,
                                      const std::string& from_prefix,
                                      const std::string& to_prefix,
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
    if (from_prefix.empty() || to_prefix.empty()) {
        if (err) *err = "empty prefix";
        return false;
    }
    if (from_prefix == to_prefix) return true;

    std::string tx_err;
    if (!begin_tx(db_, &tx_err)) {
        if (err) *err = tx_err;
        return false;
    }

    auto fail = [&](const std::string& e) -> bool {
        if (err) *err = e;
        rollback_tx(db_);
        return false;
    };

    // Refuse exact destination conflict.
    {
        static const char* kSql =
            "SELECT 1 "
            "FROM gallery_meta "
            "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3 "
            "LIMIT 1";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return fail(sqlite3_errmsg(db_));
        }

        sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, to_prefix.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_ROW) return fail("destination_exact_exists");
        if (rc != SQLITE_DONE) return fail(sqlite3_errmsg(db_));
    }

    // Refuse subtree destination conflict.
    {
        static const char* kSql =
            "SELECT 1 "
            "FROM gallery_meta "
            "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path LIKE (?3 || '/%') "
            "LIMIT 1";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return fail(sqlite3_errmsg(db_));
        }

        sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, to_prefix.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_ROW) return fail("destination_subtree_exists");
        if (rc != SQLITE_DONE) return fail(sqlite3_errmsg(db_));
    }

    // Rename exact row if present.
    {
        static const char* kSql =
            "UPDATE gallery_meta "
            "SET logical_rel_path = ?1, "
            "    updated_epoch = ?4 "
            "WHERE scope_type = ?2 AND scope_id = ?3 AND logical_rel_path = ?5";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return fail(sqlite3_errmsg(db_));
        }

        sqlite3_bind_text(stmt, 1, to_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now_epoch));
        sqlite3_bind_text(stmt, 5, from_prefix.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) return fail(sqlite3_errmsg(db_));
    }

    // Rename descendants below from_prefix/.
    {
        static const char* kSql =
            "UPDATE gallery_meta "
            "SET logical_rel_path = ?1 || substr(logical_rel_path, length(?2) + 1), "
            "    updated_epoch = ?5 "
            "WHERE scope_type = ?3 "
            "  AND scope_id = ?4 "
            "  AND logical_rel_path LIKE (?2 || '/%')";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return fail(sqlite3_errmsg(db_));
        }

        sqlite3_bind_text(stmt, 1, to_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, from_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, scope_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now_epoch));

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) return fail(sqlite3_errmsg(db_));
    }

    std::string commit_err;
    if (!commit_tx(db_, &commit_err)) {
        return fail(commit_err);
    }

    return true;
}

bool GalleryMetaIndex::erase(const std::string& scope_type,
                             const std::string& scope_id,
                             const std::string& logical_rel_path,
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
    if (logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }

    static const char* kSql =
        "DELETE FROM gallery_meta "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool GalleryMetaIndex::erase_subtree(const std::string& scope_type,
                                     const std::string& scope_id,
                                     const std::string& logical_prefix,
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

    if (logical_prefix.empty()) {
        static const char* kSqlAll =
            "DELETE FROM gallery_meta "
            "WHERE scope_type = ?1 AND scope_id = ?2";

        sqlite3_stmt* stmt = nullptr;
        const int rc_prep = sqlite3_prepare_v2(db_, kSqlAll, -1, &stmt, nullptr);
        if (rc_prep != SQLITE_OK) {
            if (err) *err = sqlite3_errmsg(db_);
            return false;
        }

        sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            if (err) *err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            return false;
        }

        sqlite3_finalize(stmt);
        return true;
    }

    static const char* kSql =
        "DELETE FROM gallery_meta "
        "WHERE scope_type = ?1 AND scope_id = ?2 "
        "  AND (logical_rel_path = ?3 OR logical_rel_path LIKE (?3 || '/%'))";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, logical_prefix.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

std::vector<GalleryMetaRec> GalleryMetaIndex::list_under_prefix(const std::string& scope_type,
                                                                const std::string& scope_id,
                                                                const std::string& logical_prefix,
                                                                std::size_t limit,
                                                                std::string* err) {
    if (err) err->clear();

    std::vector<GalleryMetaRec> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }
    if (!is_valid_scope_type_local(scope_type)) {
        if (err) *err = "invalid scope_type";
        return out;
    }
    if (scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return out;
    }

    const bool all_scope = logical_prefix.empty();

    const char* kSqlAll =
        "SELECT scope_type, scope_id, logical_rel_path, item_type, "
        "       rating, tags_text, notes_text, size_bytes, mtime_epoch, "
        "       created_epoch, updated_epoch "
        "FROM gallery_meta "
        "WHERE scope_type = ?1 AND scope_id = ?2 "
        "ORDER BY logical_rel_path ASC "
        "LIMIT ?3";

    const char* kSqlPrefix =
        "SELECT scope_type, scope_id, logical_rel_path, item_type, "
        "       rating, tags_text, notes_text, size_bytes, mtime_epoch, "
        "       created_epoch, updated_epoch "
        "FROM gallery_meta "
        "WHERE scope_type = ?1 AND scope_id = ?2 "
        "  AND (logical_rel_path = ?3 OR logical_rel_path LIKE (?3 || '/%')) "
        "ORDER BY logical_rel_path ASC "
        "LIMIT ?4";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, all_scope ? kSqlAll : kSqlPrefix, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);

    const sqlite3_int64 limit_i64 =
        (limit == 0) ? static_cast<sqlite3_int64>(-1)
                     : static_cast<sqlite3_int64>(limit);

    if (all_scope) {
        sqlite3_bind_int64(stmt, 3, limit_i64);
    } else {
        sqlite3_bind_text(stmt, 3, logical_prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, limit_i64);
    }

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;

        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        out.push_back(row_to_rec_local(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

} // namespace pqnas