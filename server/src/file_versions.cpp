#include "file_versions.h"

#include "users_registry.h"

#include <sqlite3.h>
#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <random>
#include <system_error>

namespace pqnas {

/*
Architecture notes
==================

Purpose
-------
FileVersionsIndex stores per-file version metadata for both:
- user storage
- workspace storage

It is intentionally separate from FileLocationIndex:
- FileLocationIndex tracks the current live logical file location
- FileVersionsIndex tracks preserved historical file blobs

Design choices
--------------
1. Metadata lives in SQLite.
2. Preserved version blobs live on the filesystem under:
     <scope_root>/.pqnas/versions/blobs/...
3. blob_rel_path is stored relative to scope_root so a scope can later be
   migrated without rewriting absolute paths in the database.
4. v1 only supports preserving versions for file overwrite/delete flows.
   Directory versioning is intentionally out of scope for now.

Failure behavior
----------------
preserve_live_file_version() is written to be strict:
- source file must exist and be a regular file
- blob copy must succeed
- DB insert must succeed
- on DB insert failure, copied blob is cleaned up best-effort

This matches PQ-NAS's preference for auditable, fail-closed critical flows.
*/

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

static std::string hex_encode_lower_local(const unsigned char* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        const unsigned char b = data[i];
        out[i * 2 + 0] = kHex[(b >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[b & 0x0F];
    }
    return out;
}

static bool sha256_file_local(const std::filesystem::path& p,
                              std::string* out_hex,
                              std::string* err) {
    if (out_hex) out_hex->clear();
    if (err) err->clear();

    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    struct CtxGuard {
        EVP_MD_CTX* c;
        ~CtxGuard() { if (c) EVP_MD_CTX_free(c); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return false;
    }

    std::array<char, 64 * 1024> buf{};
    while (f.good()) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) != 1) {
                if (err) *err = "EVP_DigestUpdate failed";
                return false;
            }
        }
    }

    if (!f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return false;
    }

    if (out_hex) {
        *out_hex = hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
    }
    return true;
}

static std::int64_t now_epoch_sec_local() {
    using namespace std::chrono;
    return static_cast<std::int64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

static std::string iso_utc_from_epoch_sec_local(std::int64_t epoch_sec) {
    if (epoch_sec < 0) epoch_sec = 0;

    const std::time_t tt = static_cast<std::time_t>(epoch_sec);
    std::tm tm{};

#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    if (!gmtime_r(&tt, &tm)) return "";
#endif

    char buf[32] = {0};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) return "";
    return std::string(buf);
}

static std::string random_hex_local(std::size_t nbytes) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    std::string out;
    out.reserve(nbytes * 2);

    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < nbytes; ++i) {
        const unsigned int b = dist(gen);
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

static std::string make_version_id_local() {
    using namespace std::chrono;
    const auto now_ms = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();

    return std::to_string(static_cast<long long>(now_ms)) + "_" + random_hex_local(8);
}

static bool is_valid_scope_type_local(const std::string& s) {
    return s == "user" || s == "workspace";
}

static bool is_valid_event_kind_local(const std::string& s) {
    return s == "overwrite_preserve" || s == "delete_preserve";
}

static std::string actor_name_snapshot_for_fp_local(const UsersRegistry* users,
                                                    const std::string& fp) {
    if (!users || fp.empty()) return "";
    auto uopt = users->get(fp);
    if (!uopt.has_value()) return "";
    return uopt->name;
}

static std::string version_blob_rel_path_local(const std::string& version_id) {
    const std::string shard = (version_id.size() >= 2) ? version_id.substr(0, 2) : "xx";
    return (std::filesystem::path(".pqnas") /
            "versions" /
            "blobs" /
            shard /
            (version_id + ".bin")).generic_string();
}

static std::uint64_t file_size_u64_local(const std::filesystem::path& p) {
    std::error_code ec;
    const auto sz = std::filesystem::file_size(p, ec);
    return ec ? 0 : static_cast<std::uint64_t>(sz);
}

static void remove_file_best_effort_local(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove(p, ec);
}

} // namespace

FileVersionsIndex::FileVersionsIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

FileVersionsIndex::~FileVersionsIndex() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool FileVersionsIndex::open(std::string* err) {
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

bool FileVersionsIndex::init_schema(std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS file_versions (
    version_id           TEXT PRIMARY KEY,
    scope_type           TEXT NOT NULL,
    scope_id             TEXT NOT NULL,
    logical_rel_path     TEXT NOT NULL,

    event_kind           TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    created_epoch        INTEGER NOT NULL,

    actor_fp             TEXT NOT NULL,
    actor_name_snapshot  TEXT NOT NULL DEFAULT '',

    bytes                INTEGER NOT NULL DEFAULT 0,
    sha256_hex           TEXT NOT NULL DEFAULT '',

    source_physical_path TEXT NOT NULL,
    blob_rel_path        TEXT NOT NULL,

    is_deleted_event     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_file_versions_scope_path_time
ON file_versions(scope_type, scope_id, logical_rel_path, created_epoch DESC, version_id DESC);

CREATE INDEX IF NOT EXISTS idx_file_versions_scope_time
ON file_versions(scope_type, scope_id, created_epoch DESC, version_id DESC);
)SQL";

    return exec_sql(db_, kSchema, err);
}

bool FileVersionsIndex::preserve_live_file_version(const PreserveLiveFileVersionParams& params,
                                                   FileVersionRec* out,
                                                   std::string* err) {
    if (err) err->clear();
    if (out) *out = FileVersionRec{};

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    if (!is_valid_scope_type_local(params.scope_type)) {
        if (err) *err = "invalid scope_type";
        return false;
    }

    if (!is_valid_event_kind_local(params.event_kind)) {
        if (err) *err = "invalid event_kind";
        return false;
    }

    if (params.scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return false;
    }

    if (params.logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }

    if (params.actor_fp.empty()) {
        if (err) *err = "empty actor_fp";
        return false;
    }

    if (params.scope_root.empty()) {
        if (err) *err = "empty scope_root";
        return false;
    }

    if (params.live_abs_path.empty()) {
        if (err) *err = "empty live_abs_path";
        return false;
    }

    std::error_code ec;
    const auto st = std::filesystem::symlink_status(params.live_abs_path, ec);
    if (ec) {
        if (err) *err = "source stat failed: " + ec.message();
        return false;
    }

    if (!std::filesystem::exists(st)) {
        if (err) *err = "source not found";
        return false;
    }

    if (std::filesystem::is_symlink(st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }

    if (!std::filesystem::is_regular_file(st)) {
        if (err) *err = "source is not a regular file";
        return false;
    }

    const std::string version_id = make_version_id_local();
    const std::string blob_rel_path = version_blob_rel_path_local(version_id);
    const std::filesystem::path blob_abs_path =
        version_blob_abs_path(params.scope_root, blob_rel_path);

    std::string sha256_hex;
    if (!sha256_file_local(params.live_abs_path, &sha256_hex, err)) {
        return false;
    }

    const std::int64_t created_epoch = now_epoch_sec_local();
    const std::string created_at = iso_utc_from_epoch_sec_local(created_epoch);
    const std::string actor_name_snapshot =
        actor_name_snapshot_for_fp_local(params.users, params.actor_fp);
    const std::uint64_t bytes = file_size_u64_local(params.live_abs_path);
    const bool is_deleted_event = (params.event_kind == "delete_preserve");

    ec.clear();
    std::filesystem::create_directories(blob_abs_path.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    ec.clear();
    const bool copied = std::filesystem::copy_file(
        params.live_abs_path,
        blob_abs_path,
        std::filesystem::copy_options::none,
        ec
    );
    if (ec || !copied) {
        if (err) *err = "copy_file failed: " + (ec ? ec.message() : std::string("unknown"));
        return false;
    }

    static const char* kSql =
        "INSERT INTO file_versions ("
        "  version_id, scope_type, scope_id, logical_rel_path, "
        "  event_kind, created_at, created_epoch, "
        "  actor_fp, actor_name_snapshot, "
        "  bytes, sha256_hex, source_physical_path, blob_rel_path, is_deleted_event"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, "
        "  ?5, ?6, ?7, "
        "  ?8, ?9, "
        "  ?10, ?11, ?12, ?13, ?14"
        ")";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        remove_file_best_effort_local(blob_abs_path);
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, version_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, params.scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, params.scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, params.logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 5, params.event_kind.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, created_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(created_epoch));

    sqlite3_bind_text(stmt, 8, params.actor_fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, actor_name_snapshot.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(bytes));
    sqlite3_bind_text(stmt, 11, sha256_hex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, params.live_abs_path.string().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, blob_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 14, is_deleted_event ? 1 : 0);

    const int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        remove_file_best_effort_local(blob_abs_path);
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);

    if (out) {
        out->version_id = version_id;
        out->scope_type = params.scope_type;
        out->scope_id = params.scope_id;
        out->logical_rel_path = params.logical_rel_path;
        out->event_kind = params.event_kind;
        out->created_at = created_at;
        out->created_epoch = created_epoch;
        out->actor_fp = params.actor_fp;
        out->actor_name_snapshot = actor_name_snapshot;
        out->bytes = bytes;
        out->sha256_hex = sha256_hex;
        out->source_physical_path = params.live_abs_path.string();
        out->blob_rel_path = blob_rel_path;
        out->is_deleted_event = is_deleted_event;
    }

    return true;
}

std::vector<FileVersionRec> FileVersionsIndex::list_versions_for_path(const std::string& scope_type,
                                                                      const std::string& scope_id,
                                                                      const std::string& logical_rel_path,
                                                                      std::size_t limit,
                                                                      std::string* err) {
    if (err) err->clear();

    std::vector<FileVersionRec> out;
    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    if (!is_valid_scope_type_local(scope_type)) {
        if (err) *err = "invalid scope_type";
        return out;
    }

    static const char* kSql =
        "SELECT version_id, scope_type, scope_id, logical_rel_path, "
        "       event_kind, created_at, created_epoch, "
        "       actor_fp, actor_name_snapshot, "
        "       bytes, sha256_hex, source_physical_path, blob_rel_path, is_deleted_event "
        "FROM file_versions "
        "WHERE scope_type = ?1 AND scope_id = ?2 AND logical_rel_path = ?3 "
        "ORDER BY created_epoch DESC, version_id DESC "
        "LIMIT ?4";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    sqlite3_bind_text(stmt, 1, scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(limit));

    while (true) {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) break;

        if (rc != SQLITE_ROW) {
            if (err) *err = sqlite3_errmsg(db_);
            out.clear();
            sqlite3_finalize(stmt);
            return out;
        }

        FileVersionRec rec;
        rec.version_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.scope_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.scope_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.event_kind = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
        rec.actor_fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rec.actor_name_snapshot = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        rec.bytes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 9));
        rec.sha256_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        rec.source_physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        rec.blob_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        rec.is_deleted_event = (sqlite3_column_int64(stmt, 13) != 0);

        out.push_back(std::move(rec));
    }

    sqlite3_finalize(stmt);
    return out;
}

std::filesystem::path FileVersionsIndex::version_blob_abs_path(const std::filesystem::path& scope_root,
                                                               const std::string& blob_rel_path) {
    return scope_root / std::filesystem::path(blob_rel_path);
}

std::string FileVersionsIndex::truncate_fingerprint_for_display(const std::string& fp) {
    if (fp.size() <= 16) return fp;
    return fp.substr(0, 8) + "…" + fp.substr(fp.size() - 4);
}

std::string FileVersionsIndex::resolve_actor_display_name(const UsersRegistry* users,
                                                          const std::string& actor_fp,
                                                          const std::string& actor_name_snapshot) {
    if (users && !actor_fp.empty()) {
        auto uopt = users->get(actor_fp);
        if (uopt.has_value() && !uopt->name.empty()) {
            return uopt->name;
        }
    }

    if (!actor_name_snapshot.empty()) {
        return actor_name_snapshot;
    }

    return truncate_fingerprint_for_display(actor_fp);
}
std::optional<FileVersionRec> FileVersionsIndex::get_by_version_id(const std::string& version_id,
                                                                   std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return std::nullopt;
    }

    static const char* kSql =
        "SELECT version_id, scope_type, scope_id, logical_rel_path, "
        "       event_kind, created_at, created_epoch, "
        "       actor_fp, actor_name_snapshot, bytes, sha256_hex, "
        "       source_physical_path, blob_rel_path, is_deleted_event "
        "FROM file_versions "
        "WHERE version_id = ?1";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, version_id.c_str(), -1, SQLITE_TRANSIENT);

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

    FileVersionRec rec;
    rec.version_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    rec.scope_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    rec.scope_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    rec.logical_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    rec.event_kind = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    rec.created_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    rec.created_epoch = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 6));
    rec.actor_fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    rec.actor_name_snapshot = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    rec.bytes = static_cast<std::int64_t>(sqlite3_column_int64(stmt, 9));
    rec.sha256_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    rec.source_physical_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    rec.blob_rel_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
    rec.is_deleted_event = static_cast<int>(sqlite3_column_int(stmt, 13));

    sqlite3_finalize(stmt);
    return rec;
}

bool FileVersionsIndex::insert(const FileVersionRec& rec, std::string* err) {
    if (err) err->clear();
    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    static const char* kSql =
        "INSERT INTO file_versions ("
        "  version_id, scope_type, scope_id, logical_rel_path, "
        "  event_kind, created_at, created_epoch, "
        "  actor_fp, actor_name_snapshot, bytes, sha256_hex, "
        "  source_physical_path, blob_rel_path, is_deleted_event"
        ") VALUES ("
        "  ?1, ?2, ?3, ?4, "
        "  ?5, ?6, ?7, "
        "  ?8, ?9, ?10, ?11, "
        "  ?12, ?13, ?14"
        ")";

    sqlite3_stmt* stmt = nullptr;
    const int rc_prep = sqlite3_prepare_v2(db_, kSql, -1, &stmt, nullptr);
    if (rc_prep != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rec.version_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rec.scope_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rec.scope_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, rec.logical_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rec.event_kind.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, rec.created_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(rec.created_epoch));
    sqlite3_bind_text(stmt, 8, rec.actor_fp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, rec.actor_name_snapshot.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(rec.bytes));
    sqlite3_bind_text(stmt, 11, rec.sha256_hex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, rec.source_physical_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, rec.blob_rel_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 14, rec.is_deleted_event ? 1 : 0);

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