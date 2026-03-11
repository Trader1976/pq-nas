#include "file_location_index.h"

#include <sqlite3.h>

namespace pqnas {

namespace {

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

    sqlite3_finalize(stmt);
    return true;
}

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

} // namespace pqnas