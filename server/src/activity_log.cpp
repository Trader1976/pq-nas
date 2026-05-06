#include "activity_log.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>

#include <sqlite3.h>

namespace pqnas::activity {

namespace {

long long now_epoch_seconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string sqlite_err(sqlite3* db) {
    if (!db) return "sqlite error";
    const char* msg = sqlite3_errmsg(db);
    return msg ? std::string(msg) : std::string("sqlite error");
}

bool exec_sql(sqlite3* db, const char* sql, std::string* error_out) {
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        if (error_out) {
            *error_out = err ? std::string(err) : sqlite_err(db);
        }
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool ensure_activity_dir(const std::filesystem::path& user_root, std::string* error_out) {
    const auto dir = activity_dir_for_user_root(user_root);

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        if (error_out) {
            *error_out = "failed to create activity directory: " + ec.message();
        }
        return false;
    }

    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec
    );

    return true;
}

bool ensure_schema(sqlite3* db, std::string* error_out) {
    static constexpr const char* kSchema = R"SQL(
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_epoch INTEGER NOT NULL,

    owner_user_id TEXT NOT NULL,

    actor_user_id TEXT,
    actor_display_name TEXT,
    actor_device_name TEXT,
    actor_fingerprint_short TEXT,
    actor_kind TEXT NOT NULL DEFAULT 'user',

    event_type TEXT NOT NULL,

    scope_type TEXT NOT NULL DEFAULT 'user',
    scope_id TEXT,

    target_kind TEXT,
    target_name TEXT,
    target_path TEXT,

    message TEXT,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_activity_created
ON activity_events(created_at_epoch DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_activity_event_type
ON activity_events(event_type);

CREATE INDEX IF NOT EXISTS idx_activity_scope
ON activity_events(scope_type, scope_id);
)SQL";

    return exec_sql(db, kSchema, error_out);
}

void bind_text_or_null(sqlite3_stmt* st, int idx, const std::string& value) {
    if (value.empty()) {
        sqlite3_bind_null(st, idx);
    } else {
        sqlite3_bind_text(st, idx, value.c_str(), -1, SQLITE_TRANSIENT);
    }
}

std::string column_text(sqlite3_stmt* st, int idx) {
    const unsigned char* txt = sqlite3_column_text(st, idx);
    return txt ? reinterpret_cast<const char*>(txt) : "";
}

nlohmann::json parse_details_json(const std::string& s) {
    if (s.empty()) return nlohmann::json::object();

    try {
        auto j = nlohmann::json::parse(s);
        if (j.is_object()) return j;
    } catch (...) {
    }

    return nlohmann::json::object();
}

std::string safe_target_name(const ActivityEvent& ev) {
    if (!ev.target_name.empty()) return ev.target_name;

    if (!ev.target_path.empty()) {
        try {
            const std::filesystem::path p(ev.target_path);
            const auto name = p.filename().string();
            if (!name.empty()) return name;
        } catch (...) {
        }
    }

    if (!ev.target_kind.empty()) return ev.target_kind;
    return "item";
}

} // namespace

std::filesystem::path activity_dir_for_user_root(const std::filesystem::path& user_root) {
    return user_root / ".pqnas_activity";
}

std::filesystem::path activity_db_path_for_user_root(const std::filesystem::path& user_root) {
    return activity_dir_for_user_root(user_root) / "activity.sqlite";
}

std::string actor_label(const ActivityActor& actor) {
    if (!actor.display_name.empty()) return actor.display_name;
    if (!actor.user_id.empty()) return actor.user_id;
    if (!actor.device_name.empty()) return actor.device_name;
    if (!actor.fingerprint_short.empty()) return "Device " + actor.fingerprint_short;
    if (actor.kind == "guest") return "Guest";
    if (actor.kind == "system") return "System";
    return "Someone";
}

std::string build_default_message(const ActivityEvent& ev) {
    const std::string actor = actor_label(ev.actor);
    const std::string target = safe_target_name(ev);

    if (ev.event_type == "file.uploaded") {
        return actor + " uploaded " + target;
    }

    if (ev.event_type == "folder.created") {
        return actor + " created folder " + target;
    }

    if (ev.event_type == "file.trashed") {
        return actor + " moved " + target + " to Trash";
    }

    if (ev.event_type == "file.restored") {
        return actor + " restored " + target;
    }

    if (ev.event_type == "file.purged") {
        return actor + " permanently deleted " + target;
    }

    if (ev.event_type == "share.created") {
        return actor + " created a share link for " + target;
    }

    if (ev.event_type == "share.disabled") {
        return actor + " disabled a share link for " + target;
    }

    if (ev.event_type == "dropzone.created") {
        return actor + " created Drop Zone \"" + target + "\"";
    }

    if (ev.event_type == "dropzone.disabled") {
        return actor + " disabled Drop Zone \"" + target + "\"";
    }

    if (ev.event_type == "dropzone.uploaded") {
        std::string zone_name;
        if (ev.details.is_object() && ev.details.contains("dropzone_name") && ev.details["dropzone_name"].is_string()) {
            zone_name = ev.details["dropzone_name"].get<std::string>();
        }

        if (!zone_name.empty()) {
            return actor + " uploaded " + target + " through Drop Zone \"" + zone_name + "\"";
        }

        return actor + " uploaded " + target + " through Drop Zone";
    }

    if (ev.event_type == "security.login_success") {
        return actor + " signed in";
    }

    if (ev.event_type == "security.login_failed") {
        return "Failed sign-in attempt";
    }

    if (ev.event_type == "security.device_paired") {
        if (!ev.target_name.empty()) {
            return ev.target_name + " paired as a new device";
        }
        return "New device paired";
    }

    if (ev.event_type == "security.session_revoked") {
        return actor + " revoked a session";
    }

    return actor + " performed " + ev.event_type;
}

bool record_user_activity(
    const std::filesystem::path& user_root,
    const ActivityEvent& ev,
    std::string* error_out
) {
    try {
        if (user_root.empty()) {
            if (error_out) *error_out = "empty user root";
            return false;
        }

        if (ev.owner_user_id.empty()) {
            if (error_out) *error_out = "empty owner_user_id";
            return false;
        }

        if (ev.event_type.empty()) {
            if (error_out) *error_out = "empty event_type";
            return false;
        }

        if (!ensure_activity_dir(user_root, error_out)) {
            return false;
        }

        const auto db_path = activity_db_path_for_user_root(user_root);

        sqlite3* db = nullptr;
        const int open_rc = sqlite3_open(db_path.string().c_str(), &db);
        if (open_rc != SQLITE_OK) {
            if (error_out) *error_out = sqlite_err(db);
            if (db) sqlite3_close(db);
            return false;
        }

        std::error_code chmod_ec;
        std::filesystem::permissions(
            db_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            chmod_ec
        );

        if (!ensure_schema(db, error_out)) {
            sqlite3_close(db);
            return false;
        }

        static constexpr const char* kInsert = R"SQL(
INSERT INTO activity_events (
    created_at_epoch,
    owner_user_id,

    actor_user_id,
    actor_display_name,
    actor_device_name,
    actor_fingerprint_short,
    actor_kind,

    event_type,

    scope_type,
    scope_id,

    target_kind,
    target_name,
    target_path,

    message,
    details_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)SQL";

        sqlite3_stmt* st = nullptr;
        const int prep_rc = sqlite3_prepare_v2(db, kInsert, -1, &st, nullptr);
        if (prep_rc != SQLITE_OK) {
            if (error_out) *error_out = sqlite_err(db);
            sqlite3_close(db);
            return false;
        }

        const std::string message = ev.message.empty() ? build_default_message(ev) : ev.message;
        const std::string actor_kind = ev.actor.kind.empty() ? "user" : ev.actor.kind;
        const std::string scope_type = ev.scope_type.empty() ? "user" : ev.scope_type;
        const std::string details_json = ev.details.is_null()
            ? std::string("{}")
            : ev.details.dump();

        int i = 1;
        sqlite3_bind_int64(st, i++, now_epoch_seconds());
        sqlite3_bind_text(st, i++, ev.owner_user_id.c_str(), -1, SQLITE_TRANSIENT);

        bind_text_or_null(st, i++, ev.actor.user_id);
        bind_text_or_null(st, i++, ev.actor.display_name);
        bind_text_or_null(st, i++, ev.actor.device_name);
        bind_text_or_null(st, i++, ev.actor.fingerprint_short);
        sqlite3_bind_text(st, i++, actor_kind.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_bind_text(st, i++, ev.event_type.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_bind_text(st, i++, scope_type.c_str(), -1, SQLITE_TRANSIENT);
        bind_text_or_null(st, i++, ev.scope_id);

        bind_text_or_null(st, i++, ev.target_kind);
        bind_text_or_null(st, i++, ev.target_name);
        bind_text_or_null(st, i++, ev.target_path);

        sqlite3_bind_text(st, i++, message.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, i++, details_json.c_str(), -1, SQLITE_TRANSIENT);

        const int step_rc = sqlite3_step(st);
        if (step_rc != SQLITE_DONE) {
            if (error_out) *error_out = sqlite_err(db);
            sqlite3_finalize(st);
            sqlite3_close(db);
            return false;
        }

        sqlite3_finalize(st);
        sqlite3_close(db);
        return true;
    } catch (const std::exception& e) {
        if (error_out) *error_out = e.what();
        return false;
    } catch (...) {
        if (error_out) *error_out = "unknown activity log error";
        return false;
    }
}

std::vector<ActivityRow> list_user_activity(
    const std::filesystem::path& user_root,
    int limit,
    std::string* error_out
) {
    std::vector<ActivityRow> rows;

    try {
        if (user_root.empty()) {
            if (error_out) *error_out = "empty user root";
            return rows;
        }

        limit = std::clamp(limit, 1, 500);

        if (!ensure_activity_dir(user_root, error_out)) {
            return rows;
        }

        const auto db_path = activity_db_path_for_user_root(user_root);

        sqlite3* db = nullptr;
        const int open_rc = sqlite3_open(db_path.string().c_str(), &db);
        if (open_rc != SQLITE_OK) {
            if (error_out) *error_out = sqlite_err(db);
            if (db) sqlite3_close(db);
            return rows;
        }

        std::error_code chmod_ec;
        std::filesystem::permissions(
            db_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            chmod_ec
        );

        if (!ensure_schema(db, error_out)) {
            sqlite3_close(db);
            return rows;
        }

        static constexpr const char* kSelect = R"SQL(
SELECT
    id,
    created_at_epoch,
    owner_user_id,

    actor_user_id,
    actor_display_name,
    actor_device_name,
    actor_fingerprint_short,
    actor_kind,

    event_type,
    scope_type,
    scope_id,

    target_kind,
    target_name,
    target_path,

    message,
    details_json
FROM activity_events
ORDER BY created_at_epoch DESC, id DESC
LIMIT ?;
)SQL";

        sqlite3_stmt* st = nullptr;
        const int prep_rc = sqlite3_prepare_v2(db, kSelect, -1, &st, nullptr);
        if (prep_rc != SQLITE_OK) {
            if (error_out) *error_out = sqlite_err(db);
            sqlite3_close(db);
            return rows;
        }

        sqlite3_bind_int(st, 1, limit);

        while (sqlite3_step(st) == SQLITE_ROW) {
            ActivityRow row;

            int i = 0;
            row.id = sqlite3_column_int64(st, i++);
            row.created_at_epoch = sqlite3_column_int64(st, i++);
            row.owner_user_id = column_text(st, i++);

            row.actor.user_id = column_text(st, i++);
            row.actor.display_name = column_text(st, i++);
            row.actor.device_name = column_text(st, i++);
            row.actor.fingerprint_short = column_text(st, i++);
            row.actor.kind = column_text(st, i++);

            row.event_type = column_text(st, i++);
            row.scope_type = column_text(st, i++);
            row.scope_id = column_text(st, i++);

            row.target_kind = column_text(st, i++);
            row.target_name = column_text(st, i++);
            row.target_path = column_text(st, i++);

            row.message = column_text(st, i++);
            row.details = parse_details_json(column_text(st, i++));

            rows.push_back(std::move(row));
        }

        sqlite3_finalize(st);
        sqlite3_close(db);
    } catch (const std::exception& e) {
        if (error_out) *error_out = e.what();
    } catch (...) {
        if (error_out) *error_out = "unknown activity list error";
    }

    return rows;
}

nlohmann::json activity_row_to_json(const ActivityRow& row) {
    return nlohmann::json{
        {"id", row.id},
        {"created_at_epoch", row.created_at_epoch},

        {"owner_user_id", row.owner_user_id},

        {"actor_user_id", row.actor.user_id},
        {"actor_display_name", row.actor.display_name},
        {"actor_device_name", row.actor.device_name},
        {"actor_fingerprint_short", row.actor.fingerprint_short},
        {"actor_kind", row.actor.kind},
        {"actor_label", actor_label(row.actor)},

        {"event_type", row.event_type},
        {"scope_type", row.scope_type},
        {"scope_id", row.scope_id},

        {"target_kind", row.target_kind},
        {"target_name", row.target_name},
        {"target_path", row.target_path},

        {"message", row.message},
        {"details", row.details}
    };
}

} // namespace pqnas::activity
