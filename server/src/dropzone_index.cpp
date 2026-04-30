#include "dropzone_index.h"

#include <sqlite3.h>

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

static std::string col_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

static DropZoneRec row_to_dropzone(sqlite3_stmt* stmt) {
    DropZoneRec rec;

    rec.id               = col_text(stmt, 0);
    rec.token_hash       = col_text(stmt, 1);
    rec.owner_fp         = col_text(stmt, 2);
    rec.name             = col_text(stmt, 3);
    rec.destination_path = col_text(stmt, 4);
    rec.password_hash    = col_text(stmt, 5);

    rec.created_epoch    = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
    rec.expires_epoch    = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 7));
    rec.last_used_epoch  = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 8));

    rec.max_file_bytes   = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 9));
    rec.max_total_bytes  = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 10));
    rec.bytes_uploaded   = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 11));
    rec.upload_count     = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 12));

    rec.disabled         = sqlite3_column_int(stmt, 13) != 0;

    return rec;
}

static const char* kSelectDropZoneColumns =
    "SELECT "
    "  id, token_hash, owner_fp, name, destination_path, password_hash, "
    "  created_epoch, expires_epoch, last_used_epoch, "
    "  max_file_bytes, max_total_bytes, bytes_uploaded, upload_count, disabled "
    "FROM drop_zones ";

} // namespace

DropZoneIndex::DropZoneIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

DropZoneIndex::~DropZoneIndex() {
    std::lock_guard<std::mutex> lk(mu_);

    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool DropZoneIndex::open(std::string* err) {
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
    if (!exec_sql(db_, "PRAGMA busy_timeout=5000;", err)) return false;

    return true;
}

bool DropZoneIndex::init_schema(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS drop_zones (
    id                TEXT PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE,

    owner_fp          TEXT NOT NULL,

    name              TEXT NOT NULL,
    destination_path  TEXT NOT NULL,

    password_hash     TEXT NOT NULL DEFAULT '',

    created_epoch     INTEGER NOT NULL,
    expires_epoch     INTEGER NOT NULL,
    last_used_epoch   INTEGER NOT NULL DEFAULT 0,

    max_file_bytes    INTEGER NOT NULL DEFAULT 0,
    max_total_bytes   INTEGER NOT NULL DEFAULT 0,
    bytes_uploaded    INTEGER NOT NULL DEFAULT 0,
    upload_count      INTEGER NOT NULL DEFAULT 0,

    disabled          INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_drop_zones_owner_created
ON drop_zones(owner_fp, created_epoch DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_drop_zones_owner_disabled_created
ON drop_zones(owner_fp, disabled, created_epoch DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_drop_zones_expiry
ON drop_zones(disabled, expires_epoch ASC, id ASC);

CREATE TABLE IF NOT EXISTS drop_zone_uploads (
    id                 TEXT PRIMARY KEY,
    drop_zone_id       TEXT NOT NULL,

    original_filename  TEXT NOT NULL,
    stored_filename    TEXT NOT NULL,
    stored_path        TEXT NOT NULL,

    size_bytes         INTEGER NOT NULL DEFAULT 0,
    sha256             TEXT NOT NULL DEFAULT '',

    uploader_name      TEXT NOT NULL DEFAULT '',
    uploader_message   TEXT NOT NULL DEFAULT '',

    remote_ip          TEXT NOT NULL DEFAULT '',
    user_agent         TEXT NOT NULL DEFAULT '',

    created_epoch      INTEGER NOT NULL,
    scan_status        TEXT NOT NULL DEFAULT 'not_scanned',

    FOREIGN KEY(drop_zone_id) REFERENCES drop_zones(id)
);

CREATE INDEX IF NOT EXISTS idx_drop_zone_uploads_zone_created
ON drop_zone_uploads(drop_zone_id, created_epoch DESC, id DESC);
)SQL";

    return exec_sql(db_, kSchema, err);
}

bool DropZoneIndex::insert(const DropZoneRec& rec, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "INSERT INTO drop_zones ("
        "  id, token_hash, owner_fp, name, destination_path, password_hash, "
        "  created_epoch, expires_epoch, last_used_epoch, "
        "  max_file_bytes, max_total_bytes, bytes_uploaded, upload_count, disabled"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14"
        ")";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.owner_fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.destination_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, rec.password_hash.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_int64(stmt, 8, static_cast<sqlite3_int64>(rec.expires_epoch));
    sqlite3_bind_int64(stmt, 9, static_cast<sqlite3_int64>(rec.last_used_epoch));

    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(rec.max_file_bytes));
    sqlite3_bind_int64(stmt, 11, static_cast<sqlite3_int64>(rec.max_total_bytes));
    sqlite3_bind_int64(stmt, 12, static_cast<sqlite3_int64>(rec.bytes_uploaded));
    sqlite3_bind_int64(stmt, 13, static_cast<sqlite3_int64>(rec.upload_count));
    sqlite3_bind_int(stmt, 14, rec.disabled ? 1 : 0);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

std::optional<DropZoneRec> DropZoneIndex::get_by_id(const std::string& id, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    const std::string sql = std::string(kSelectDropZoneColumns) + "WHERE id = ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

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

    DropZoneRec rec = row_to_dropzone(stmt);
    sqlite3_finalize(stmt);
    return rec;
}

std::optional<DropZoneRec> DropZoneIndex::get_by_token_hash(const std::string& token_hash, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    const std::string sql = std::string(kSelectDropZoneColumns) + "WHERE token_hash = ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);

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

    DropZoneRec rec = row_to_dropzone(stmt);
    sqlite3_finalize(stmt);
    return rec;
}

std::vector<DropZoneRec> DropZoneIndex::list_owner(const std::string& owner_fp,
                                                   bool include_disabled,
                                                   std::size_t limit,
                                                   std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    std::vector<DropZoneRec> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    const std::string sql = std::string(kSelectDropZoneColumns) +
        (include_disabled
            ? "WHERE owner_fp = ?1 ORDER BY created_epoch DESC, id DESC LIMIT ?2"
            : "WHERE owner_fp = ?1 AND disabled = 0 ORDER BY created_epoch DESC, id DESC LIMIT ?2");

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, owner_fp.c_str(), -1, SQLITE_TRANSIENT);
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

        out.push_back(row_to_dropzone(stmt));
    }

    sqlite3_finalize(stmt);
    return out;
}

bool DropZoneIndex::set_disabled(const std::string& id,
                                 const std::string& owner_fp,
                                 bool disabled,
                                 std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "UPDATE drop_zones "
        "SET disabled = ?1 "
        "WHERE id = ?2 AND owner_fp = ?3";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_int(stmt, 1, disabled ? 1 : 0);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, owner_fp.c_str(), -1, SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "set_disabled_no_match";
        return false;
    }

    return true;
}
bool DropZoneIndex::record_upload(const DropZoneUploadRec& rec, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (!exec_sql(db_, "BEGIN IMMEDIATE;", err)) {
        return false;
    }

    auto rollback = [&]() {
        std::string ignored;
        (void)exec_sql(db_, "ROLLBACK;", &ignored);
    };

    static const char* kInsert =
        "INSERT INTO drop_zone_uploads ("
        "  id, drop_zone_id, original_filename, stored_filename, stored_path, "
        "  size_bytes, sha256, uploader_name, uploader_message, "
        "  remote_ip, user_agent, created_epoch, scan_status"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13"
        ")";

    sqlite3_stmt* stmt = nullptr;
    int rc_prep = sqlite3_prepare_v2(db_, kInsert, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.drop_zone_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.original_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.stored_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.stored_path.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(rec.size_bytes));
    sqlite3_bind_text(stmt, 7, rec.sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, rec.uploader_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, rec.uploader_message.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 10, rec.remote_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, rec.user_agent.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 12, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_text(stmt, 13, rec.scan_status.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        rollback();
        return false;
    }

    sqlite3_finalize(stmt);

    static const char* kUpdate =
        "UPDATE drop_zones "
        "SET bytes_uploaded = bytes_uploaded + ?1, "
        "    upload_count = upload_count + 1, "
        "    last_used_epoch = ?2 "
        "WHERE id = ?3";

    stmt = nullptr;
    rc_prep = sqlite3_prepare_v2(db_, kUpdate, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(rec.size_bytes));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_text(stmt, 3, rec.drop_zone_id.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        rollback();
        return false;
    }

    const int changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changed != 1) {
        if (err) *err = "drop zone update failed";
        rollback();
        return false;
    }

    if (!exec_sql(db_, "COMMIT;", err)) {
        rollback();
        return false;
    }

    return true;
}
    std::vector<DropZoneUploadRec> DropZoneIndex::list_uploads(const std::string& drop_zone_id,
                                                           std::size_t limit,
                                                           std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (err) err->clear();

    std::vector<DropZoneUploadRec> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    if (drop_zone_id.empty()) {
        if (err) *err = "empty drop_zone_id";
        return out;
    }

    if (limit == 0) limit = 100;
    if (limit > 500) limit = 500;

    static const char* kSql =
        "SELECT "
        "  id, drop_zone_id, original_filename, stored_filename, stored_path, "
        "  size_bytes, sha256, uploader_name, uploader_message, "
        "  remote_ip, user_agent, created_epoch, scan_status "
        "FROM drop_zone_uploads "
        "WHERE drop_zone_id = ?1 "
        "ORDER BY created_epoch DESC, id DESC "
        "LIMIT ?2";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);

    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, drop_zone_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW) {
            DropZoneUploadRec rec;

            auto col_text = [&](int idx) -> std::string {
                const unsigned char* p = sqlite3_column_text(stmt, idx);
                return p ? reinterpret_cast<const char*>(p) : std::string{};
            };

            rec.id = col_text(0);
            rec.drop_zone_id = col_text(1);
            rec.original_filename = col_text(2);
            rec.stored_filename = col_text(3);
            rec.stored_path = col_text(4);

            rec.size_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 5));
            rec.sha256 = col_text(6);
            rec.uploader_name = col_text(7);
            rec.uploader_message = col_text(8);

            rec.remote_ip = col_text(9);
            rec.user_agent = col_text(10);

            rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 11));
            rec.scan_status = col_text(12);

            out.push_back(std::move(rec));
            continue;
        }

        if (rc == SQLITE_DONE) {
            break;
        }

        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return {};
    }

    sqlite3_finalize(stmt);
    return out;
}
} // namespace pqnas
