#include "people_contacts.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>

#include <sqlite3.h>

namespace pqnas {
namespace {

std::int64_t now_epoch_seconds_local() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

std::string trim_copy_local(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::string sqlite_err_local(sqlite3* db) {
    const char* msg = db ? sqlite3_errmsg(db) : nullptr;
    return msg ? std::string(msg) : std::string("sqlite error");
}

bool exec_sql_local(sqlite3* db, const char* sql, std::string* err) {
    char* msg = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &msg);
    if (rc != SQLITE_OK) {
        if (err) *err = msg ? std::string(msg) : sqlite_err_local(db);
        if (msg) sqlite3_free(msg);
        return false;
    }
    if (msg) sqlite3_free(msg);
    return true;
}

std::string col_text_local(sqlite3_stmt* st, int idx) {
    const unsigned char* p = sqlite3_column_text(st, idx);
    return p ? reinterpret_cast<const char*>(p) : std::string{};
}

void bind_text_local(sqlite3_stmt* st, int idx, const std::string& value) {
    sqlite3_bind_text(st, idx, value.c_str(), -1, SQLITE_TRANSIENT);
}

PeopleContactRecord row_to_contact_local(sqlite3_stmt* st) {
    PeopleContactRecord r;
    int i = 0;
    r.id = static_cast<std::int64_t>(sqlite3_column_int64(st, i++));
    r.owner_fingerprint = col_text_local(st, i++);
    r.subject_user_id = col_text_local(st, i++);
    r.subject_fingerprint = col_text_local(st, i++);
    r.subject_kind = col_text_local(st, i++);
    r.display_name = col_text_local(st, i++);
    r.nickname = col_text_local(st, i++);
    r.notes = col_text_local(st, i++);
    r.created_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, i++));
    r.updated_at_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, i++));
    return r;
}

bool open_db_local(const std::filesystem::path& db_path, sqlite3** out, std::string* err) {
    *out = nullptr;

    std::error_code ec;
    std::filesystem::create_directories(db_path.parent_path(), ec);
    if (ec) {
        if (err) *err = "failed to create people db directory: " + ec.message();
        return false;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.string().c_str(), &db) != SQLITE_OK) {
        if (err) *err = db ? sqlite3_errmsg(db) : "sqlite open failed";
        if (db) sqlite3_close(db);
        return false;
    }

    sqlite3_busy_timeout(db, 5000);
    *out = db;
    return true;
}

bool ensure_schema_local(sqlite3* db, std::string* err) {
    if (!exec_sql_local(db, "PRAGMA journal_mode=WAL;", err)) return false;
    if (!exec_sql_local(db, "PRAGMA busy_timeout=5000;", err)) return false;

    static const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS people_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_fingerprint TEXT NOT NULL,
    subject_user_id TEXT NOT NULL DEFAULT '',
    subject_fingerprint TEXT NOT NULL,
    subject_kind TEXT NOT NULL DEFAULT 'fingerprint',
    display_name TEXT NOT NULL,
    nickname TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at_epoch INTEGER NOT NULL,
    updated_at_epoch INTEGER NOT NULL,
    UNIQUE(owner_fingerprint, subject_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_people_contacts_owner_name
ON people_contacts(owner_fingerprint, display_name COLLATE NOCASE);

CREATE INDEX IF NOT EXISTS idx_people_contacts_owner_kind
ON people_contacts(owner_fingerprint, subject_kind);
)SQL";

    return exec_sql_local(db, kSchema, err);
}

} // namespace

PeopleContactsStore::PeopleContactsStore(std::filesystem::path db_path)
    : db_path_(std::move(db_path)) {}

bool PeopleContactsStore::init(std::string* err) const {
    sqlite3* db = nullptr;
    if (!open_db_local(db_path_, &db, err)) return false;

    const bool ok = ensure_schema_local(db, err);
    sqlite3_close(db);
    return ok;
}

bool PeopleContactsStore::list_for_owner(const std::string& owner_fp,
                                         std::vector<PeopleContactRecord>* out,
                                         std::string* err) const {
    if (!out) return false;
    out->clear();

    sqlite3* db = nullptr;
    if (!open_db_local(db_path_, &db, err)) return false;
    if (!ensure_schema_local(db, err)) {
        sqlite3_close(db);
        return false;
    }

    static const char* kSql = R"SQL(
SELECT id, owner_fingerprint, subject_user_id, subject_fingerprint, subject_kind,
       display_name, nickname, notes, created_at_epoch, updated_at_epoch
FROM people_contacts
WHERE owner_fingerprint = ?
ORDER BY display_name COLLATE NOCASE ASC, subject_fingerprint ASC
LIMIT 1000
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kSql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_close(db);
        return false;
    }

    bind_text_local(st, 1, owner_fp);

    while (true) {
        const int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            out->push_back(row_to_contact_local(st));
            continue;
        }
        if (rc == SQLITE_DONE) break;

        if (err) *err = sqlite_err_local(db);
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

bool PeopleContactsStore::find_for_owner(const std::string& owner_fp,
                                         const std::string& subject_fp,
                                         std::optional<PeopleContactRecord>* out,
                                         std::string* err) const {
    if (!out) return false;
    *out = std::nullopt;

    sqlite3* db = nullptr;
    if (!open_db_local(db_path_, &db, err)) return false;
    if (!ensure_schema_local(db, err)) {
        sqlite3_close(db);
        return false;
    }

    static const char* kSql = R"SQL(
SELECT id, owner_fingerprint, subject_user_id, subject_fingerprint, subject_kind,
       display_name, nickname, notes, created_at_epoch, updated_at_epoch
FROM people_contacts
WHERE owner_fingerprint = ? AND subject_fingerprint = ?
LIMIT 1
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kSql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_close(db);
        return false;
    }

    bind_text_local(st, 1, owner_fp);
    bind_text_local(st, 2, subject_fp);

    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *out = row_to_contact_local(st);
    } else if (rc != SQLITE_DONE) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

bool PeopleContactsStore::upsert_for_owner(const std::string& owner_fp,
                                           const PeopleContactRecord& input,
                                           PeopleContactRecord* out,
                                           std::string* err) const {
    const std::string subject_fp = people_canonical_fingerprint(input.subject_fingerprint);
    if (!people_valid_fingerprint(owner_fp) || !people_valid_fingerprint(subject_fp)) {
        if (err) *err = "invalid fingerprint";
        return false;
    }

    const std::string subject_kind = people_normalize_subject_kind(input.subject_kind);
    std::string display_name = trim_copy_local(input.display_name);
    std::string nickname = trim_copy_local(input.nickname);
    std::string notes = trim_copy_local(input.notes);
    std::string subject_user_id = trim_copy_local(input.subject_user_id);

    if (display_name.empty()) {
        display_name = people_fingerprint_short(subject_fp);
    }

    if (display_name.size() > 120) display_name.resize(120);
    if (nickname.size() > 120) nickname.resize(120);
    if (notes.size() > 2000) notes.resize(2000);
    if (subject_user_id.size() > 160) subject_user_id.resize(160);

    sqlite3* db = nullptr;
    if (!open_db_local(db_path_, &db, err)) return false;
    if (!ensure_schema_local(db, err)) {
        sqlite3_close(db);
        return false;
    }

    const std::int64_t now = now_epoch_seconds_local();

    static const char* kSql = R"SQL(
INSERT INTO people_contacts (
    owner_fingerprint, subject_user_id, subject_fingerprint, subject_kind,
    display_name, nickname, notes, created_at_epoch, updated_at_epoch
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner_fingerprint, subject_fingerprint) DO UPDATE SET
    subject_user_id = excluded.subject_user_id,
    subject_kind = excluded.subject_kind,
    display_name = excluded.display_name,
    nickname = excluded.nickname,
    notes = excluded.notes,
    updated_at_epoch = excluded.updated_at_epoch
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kSql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_close(db);
        return false;
    }

    bind_text_local(st, 1, owner_fp);
    bind_text_local(st, 2, subject_user_id);
    bind_text_local(st, 3, subject_fp);
    bind_text_local(st, 4, subject_kind);
    bind_text_local(st, 5, display_name);
    bind_text_local(st, 6, nickname);
    bind_text_local(st, 7, notes);
    sqlite3_bind_int64(st, 8, static_cast<sqlite3_int64>(now));
    sqlite3_bind_int64(st, 9, static_cast<sqlite3_int64>(now));

    if (sqlite3_step(st) != SQLITE_DONE) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(st);
    sqlite3_close(db);

    if (out) {
        std::optional<PeopleContactRecord> found;
        if (!find_for_owner(owner_fp, subject_fp, &found, err)) return false;
        if (found.has_value()) *out = *found;
    }

    return true;
}

bool PeopleContactsStore::delete_for_owner(const std::string& owner_fp,
                                           const std::string& subject_fp_in,
                                           bool* deleted,
                                           std::string* err) const {
    if (deleted) *deleted = false;

    const std::string subject_fp = people_canonical_fingerprint(subject_fp_in);
    if (!people_valid_fingerprint(owner_fp) || !people_valid_fingerprint(subject_fp)) {
        if (err) *err = "invalid fingerprint";
        return false;
    }

    sqlite3* db = nullptr;
    if (!open_db_local(db_path_, &db, err)) return false;
    if (!ensure_schema_local(db, err)) {
        sqlite3_close(db);
        return false;
    }

    static const char* kSql = R"SQL(
DELETE FROM people_contacts
WHERE owner_fingerprint = ? AND subject_fingerprint = ?
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kSql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_close(db);
        return false;
    }

    bind_text_local(st, 1, owner_fp);
    bind_text_local(st, 2, subject_fp);

    if (sqlite3_step(st) != SQLITE_DONE) {
        if (err) *err = sqlite_err_local(db);
        sqlite3_finalize(st);
        sqlite3_close(db);
        return false;
    }

    if (deleted) *deleted = sqlite3_changes(db) > 0;

    sqlite3_finalize(st);
    sqlite3_close(db);
    return true;
}

std::string people_canonical_fingerprint(const std::string& input) {
    std::string s = trim_copy_local(input);

    std::string out;
    out.reserve(s.size());
    for (unsigned char ch : s) {
        if (std::isspace(ch)) continue;
        if (ch == ':' || ch == '-') continue;
        out.push_back(static_cast<char>(std::tolower(ch)));
    }
    return out;
}

bool people_valid_fingerprint(const std::string& fp) {
    if (fp.size() < 16 || fp.size() > 256) return false;

    for (unsigned char ch : fp) {
        if (!std::isxdigit(ch)) return false;
    }

    return true;
}

std::string people_normalize_subject_kind(const std::string& input) {
    std::string s = trim_copy_local(input);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (s == "local_user") return s;
    if (s == "external_dna") return s;
    return "fingerprint";
}

std::string people_fingerprint_short(const std::string& fp) {
    if (fp.size() <= 16) return fp;
    return fp.substr(0, 8) + "…" + fp.substr(fp.size() - 6);
}

} // namespace pqnas
