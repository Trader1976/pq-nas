#include "routes_file_locks.h"

#include "activity_log.h"
#include "file_locks.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas {
namespace {

using json = nlohmann::json;

void reply_json_local(const FileLockRoutesDeps& deps,
                      httplib::Response& res,
                      int code,
                      const json& body) {
    if (deps.reply_json) {
        deps.reply_json(res, code, body.dump());
        return;
    }

    res.status = code;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

std::string trim_copy(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::string fp_short(const std::string& fp) {
    if (fp.size() <= 18) return fp;
    return fp.substr(0, 8) + "…" + fp.substr(fp.size() - 8);
}

std::string normalize_item_kind(std::string s) {
    s = trim_copy(s);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (s == "file") return "file";
    if (s == "dir" || s == "folder") return "dir";
    return "unknown";
}

bool normalize_rel_path(const std::string& raw, std::string* out, std::string* err) {
    if (!out) return false;

    std::string s = trim_copy(raw);
    std::replace(s.begin(), s.end(), '\\', '/');

    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    while (!s.empty() && s.back() == '/') s.pop_back();

    if (s.empty() || s == ".") {
        *out = "";
        return true;
    }

    std::vector<std::string> parts;
    std::size_t pos = 0;

    while (pos <= s.size()) {
        const std::size_t slash = s.find('/', pos);
        const std::string part = s.substr(
            pos,
            slash == std::string::npos ? std::string::npos : slash - pos);

        if (part.empty() || part == ".") {
            // skip
        } else if (part == "..") {
            if (err) *err = "path traversal is not allowed";
            return false;
        } else {
            parts.push_back(part);
        }

        if (slash == std::string::npos) break;
        pos = slash + 1;
    }

    std::string norm;
    for (const auto& p : parts) {
        if (!norm.empty()) norm += "/";
        norm += p;
    }

    *out = norm;
    return true;
}

std::string basename_rel(const std::string& rel, const std::string& fallback) {
    try {
        const std::filesystem::path p(rel);
        const std::string name = p.filename().string();
        if (!name.empty()) return name;
    } catch (...) {
    }

    if (!fallback.empty()) return fallback;
    return "item";
}

std::string param_or_empty(const httplib::Request& req, const char* name) {
    return req.has_param(name) ? req.get_param_value(name) : std::string{};
}

struct ScopeAuth {
    std::string scope_type;
    std::string scope_id;
    std::string actor_fp;
    std::string actor_role;
    bool can_read = false;
    bool can_write = false;
    bool can_override = false;
};

bool authorize_scope(const FileLockRoutesDeps& deps,
                     const httplib::Request& req,
                     httplib::Response& res,
                     std::string scope_type,
                     std::string scope_id,
                     bool need_write,
                     ScopeAuth* out) {
    if (!deps.users || !deps.cookie_key || !deps.require_user_auth_users_actor) {
        reply_json_local(deps, res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "file lock route dependencies missing"}
        });
        return false;
    }

    std::string actor_fp;
    std::string actor_role;
    if (!deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return false;
    }

    scope_type = trim_copy(scope_type);
    scope_id = trim_copy(scope_id);

    if (scope_type.empty()) {
        scope_type = scope_id.empty() ? "user" : "workspace";
    }

    ScopeAuth auth;
    auth.scope_type = scope_type;
    auth.actor_fp = actor_fp;
    auth.actor_role = actor_role;

    if (scope_type == "user") {
        if (scope_id.empty()) scope_id = actor_fp;

        if (scope_id != actor_fp) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "user file locks are private to the signed-in user"}
            });
            return false;
        }

        auth.scope_id = scope_id;
        auth.can_read = true;
        auth.can_write = true;
        auth.can_override = true;
    } else if (scope_type == "workspace") {
        if (scope_id.empty()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace scope_id"}
            });
            return false;
        }

        if (!deps.workspaces || !deps.workspaces->load(deps.workspaces_path)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            });
            return false;
        }

        auto wopt = deps.workspaces->get(scope_id);
        if (!wopt.has_value() || wopt->status != "enabled") {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            });
            return false;
        }

        std::optional<WorkspaceMemberRec> member;
        for (const auto& m : wopt->members) {
            if (m.fingerprint == actor_fp && m.status == "enabled") {
                member = m;
                break;
            }
        }

        if (!member.has_value()) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace membership required"}
            });
            return false;
        }

        auth.scope_id = scope_id;
        auth.can_read = true;
        auth.can_write = (member->role == "owner" || member->role == "editor");
        auth.can_override = (member->role == "owner");
    } else {
        reply_json_local(deps, res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid scope_type"}
        });
        return false;
    }

    if (need_write && !auth.can_write) {
        reply_json_local(deps, res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "editor access required"}
        });
        return false;
    }

    if (out) *out = auth;
    return true;
}

json lock_to_json(const FileLockRec& r,
                  const FileLockRoutesDeps& deps,
                  const ScopeAuth& auth) {
    std::string label;
    if (deps.display_name_for_fp) {
        label = deps.display_name_for_fp(r.locked_by_fp);
    }
    if (label.empty()) label = fp_short(r.locked_by_fp);

    const bool own_lock = !r.locked_by_fp.empty() && r.locked_by_fp == auth.actor_fp;

    return json{
        {"scope_type", r.scope_type},
        {"scope_id", r.scope_id},
        {"logical_rel_path", r.logical_rel_path},
        {"item_kind", r.item_kind},
        {"locked_by_fp_short", fp_short(r.locked_by_fp)},
        {"locked_by_label", label},
        {"own_lock", own_lock},
        {"can_unlock", own_lock || auth.can_override},
        {"note", r.note},
        {"created_at_epoch", r.created_at_epoch},
        {"updated_at_epoch", r.updated_at_epoch},
        {"expires_at_epoch", r.expires_at_epoch}
    };
}

std::optional<FileLockRec> get_live_lock_or_cleanup(FileLocksStore& store,
                                                    const std::string& scope_type,
                                                    const std::string& scope_id,
                                                    const std::string& rel,
                                                    std::int64_t now,
                                                    std::string* err) {
    auto lock = store.get_lock(scope_type, scope_id, rel, err);
    if (!lock.has_value()) return std::nullopt;

    if (!file_lock_is_live(*lock, now)) {
        std::string del_err;
        (void)store.delete_lock(scope_type, scope_id, rel, &del_err);
        return std::nullopt;
    }

    return lock;
}

void record_lock_activity_best_effort(const FileLockRoutesDeps& deps,
                                      const ScopeAuth& auth,
                                      const std::string& event_type,
                                      const std::string& rel,
                                      const std::string& item_kind,
                                      const FileLockRec* lock) {
    if (!deps.user_dir_for_fp || auth.actor_fp.empty()) return;

    std::filesystem::path user_root;
    try {
        user_root = deps.user_dir_for_fp(auth.actor_fp);
    } catch (...) {
        return;
    }

    if (user_root.empty()) return;

    pqnas::activity::ActivityEvent ev;
    ev.owner_user_id = auth.actor_fp;

    ev.actor.user_id = auth.actor_fp;
    ev.actor.kind = "user";
    if (deps.display_name_for_fp) ev.actor.display_name = deps.display_name_for_fp(auth.actor_fp);

    ev.event_type = event_type;
    ev.scope_type = auth.scope_type;
    ev.scope_id = auth.scope_id;
    ev.target_kind = item_kind.empty() ? "item" : item_kind;
    ev.target_path = rel;
    ev.target_name = basename_rel(rel, ev.target_kind);

    ev.details = json{
        {"scope_type", auth.scope_type},
        {"scope_id", auth.scope_id},
        {"original_rel_path", rel},
        {"item_type", ev.target_kind}
    };

    if (lock) {
        ev.details["expires_at_epoch"] = lock->expires_at_epoch;
        if (!lock->note.empty()) ev.details["note"] = lock->note;
        ev.details["locked_by_fp_short"] = fp_short(lock->locked_by_fp);
    }

    std::string activity_err;
    (void)pqnas::activity::record_user_activity(user_root, ev, &activity_err);
}

} // namespace

void register_file_lock_routes(httplib::Server& srv,
                               const FileLockRoutesDeps& deps) {
    srv.Get("/api/v4/file-locks/status",
            [deps](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");

        const std::string scope_type = param_or_empty(req, "scope_type");
        std::string scope_id = param_or_empty(req, "scope_id");
        if (scope_id.empty()) scope_id = param_or_empty(req, "workspace_id");

        ScopeAuth auth;
        if (!authorize_scope(deps, req, res, scope_type, scope_id, false, &auth)) return;

        std::string rel;
        std::string perr;
        if (!normalize_rel_path(param_or_empty(req, "path"), &rel, &perr)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_path"},
                {"message", perr.empty() ? "invalid path" : perr}
            });
            return;
        }

        const std::int64_t now = deps.now_epoch_sec ? deps.now_epoch_sec() : 0;

        FileLocksStore store(deps.locks_db_path);
        std::string err;
        (void)store.delete_expired(now, nullptr);

        auto lock = get_live_lock_or_cleanup(store, auth.scope_type, auth.scope_id, rel, now, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load file lock"}
            });
            return;
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"locked", lock.has_value()},
            {"lock", lock.has_value() ? lock_to_json(*lock, deps, auth) : json(nullptr)}
        });
    });

    srv.Post("/api/v4/file-locks/status-batch",
             [deps](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");

        json body = json::parse(req.body, nullptr, false);
        if (!body.is_object()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            });
            return;
        }

        const std::string scope_type = body.value("scope_type", "");
        std::string scope_id = body.value("scope_id", "");
        if (scope_id.empty()) scope_id = body.value("workspace_id", "");

        ScopeAuth auth;
        if (!authorize_scope(deps, req, res, scope_type, scope_id, false, &auth)) return;

        const json paths_j = body.value("paths", json::array());
        if (!paths_j.is_array() || paths_j.size() > 500) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "paths must be an array with at most 500 items"}
            });
            return;
        }

        const std::int64_t now = deps.now_epoch_sec ? deps.now_epoch_sec() : 0;

        FileLocksStore store(deps.locks_db_path);
        (void)store.delete_expired(now, nullptr);

        json out = json::object();

        for (const auto& p : paths_j) {
            if (!p.is_string()) continue;

            std::string rel;
            std::string perr;
            if (!normalize_rel_path(p.get<std::string>(), &rel, &perr)) continue;

            std::string err;
            auto lock = get_live_lock_or_cleanup(store, auth.scope_type, auth.scope_id, rel, now, &err);
            if (err.empty() && lock.has_value()) {
                out[rel] = lock_to_json(*lock, deps, auth);
            }
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"locks", out}
        });
    });

    srv.Post("/api/v4/file-locks/lock",
             [deps](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");

        json body = json::parse(req.body, nullptr, false);
        if (!body.is_object()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            });
            return;
        }

        const std::string scope_type = body.value("scope_type", "");
        std::string scope_id = body.value("scope_id", "");
        if (scope_id.empty()) scope_id = body.value("workspace_id", "");

        ScopeAuth auth;
        if (!authorize_scope(deps, req, res, scope_type, scope_id, true, &auth)) return;

        std::string rel;
        std::string perr;
        if (!normalize_rel_path(body.value("path", ""), &rel, &perr)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_path"},
                {"message", perr.empty() ? "invalid path" : perr}
            });
            return;
        }

        std::string note = body.value("note", "");
        if (note.size() > 2000) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "lock note is too large"}
            });
            return;
        }

        const std::int64_t now = deps.now_epoch_sec ? deps.now_epoch_sec() : 0;

        std::int64_t expires_at = body.value("expires_at_epoch", static_cast<std::int64_t>(0));
        const std::int64_t expires_in = body.value("expires_in_seconds", static_cast<std::int64_t>(0));
        if (expires_at <= 0 && expires_in > 0 && now > 0) {
            expires_at = now + expires_in;
        }

        FileLocksStore store(deps.locks_db_path);
        (void)store.delete_expired(now, nullptr);

        std::string err;
        auto existing = get_live_lock_or_cleanup(store, auth.scope_type, auth.scope_id, rel, now, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check existing file lock"}
            });
            return;
        }

        if (existing.has_value() && existing->locked_by_fp != auth.actor_fp) {
            reply_json_local(deps, res, 409, json{
                {"ok", false},
                {"error", "locked"},
                {"message", "file is already locked"},
                {"lock", lock_to_json(*existing, deps, auth)}
            });
            return;
        }

        FileLockRec rec;
        rec.scope_type = auth.scope_type;
        rec.scope_id = auth.scope_id;
        rec.logical_rel_path = rel;
        rec.item_kind = normalize_item_kind(body.value("item_kind", ""));
        rec.locked_by_fp = auth.actor_fp;
        rec.note = note;
        rec.created_at_epoch = existing.has_value() ? existing->created_at_epoch : now;
        rec.updated_at_epoch = now;
        rec.expires_at_epoch = expires_at;

        if (!store.upsert_lock(rec, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save file lock"}
            });
            return;
        }

        auto saved = store.get_lock(auth.scope_type, auth.scope_id, rel, &err);
        const FileLockRec& out = saved.has_value() ? *saved : rec;

        record_lock_activity_best_effort(deps, auth, "file.locked", rel, rec.item_kind, &out);

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"locked", true},
            {"lock", lock_to_json(out, deps, auth)}
        });
    });

    srv.Post("/api/v4/file-locks/unlock",
             [deps](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Cache-Control", "no-store");

        json body = json::parse(req.body, nullptr, false);
        if (!body.is_object()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            });
            return;
        }

        const std::string scope_type = body.value("scope_type", "");
        std::string scope_id = body.value("scope_id", "");
        if (scope_id.empty()) scope_id = body.value("workspace_id", "");

        ScopeAuth auth;
        if (!authorize_scope(deps, req, res, scope_type, scope_id, true, &auth)) return;

        std::string rel;
        std::string perr;
        if (!normalize_rel_path(body.value("path", ""), &rel, &perr)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_path"},
                {"message", perr.empty() ? "invalid path" : perr}
            });
            return;
        }

        const std::int64_t now = deps.now_epoch_sec ? deps.now_epoch_sec() : 0;

        FileLocksStore store(deps.locks_db_path);
        (void)store.delete_expired(now, nullptr);

        std::string err;
        auto lock = get_live_lock_or_cleanup(store, auth.scope_type, auth.scope_id, rel, now, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load file lock"}
            });
            return;
        }

        if (!lock.has_value()) {
            reply_json_local(deps, res, 200, json{
                {"ok", true},
                {"locked", false},
                {"lock", nullptr}
            });
            return;
        }

        const bool own_lock = lock->locked_by_fp == auth.actor_fp;
        if (!own_lock && !auth.can_override) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "only the lock owner or workspace owner can unlock this item"},
                {"lock", lock_to_json(*lock, deps, auth)}
            });
            return;
        }

        if (!store.delete_lock(auth.scope_type, auth.scope_id, rel, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to remove file lock"}
            });
            return;
        }

        record_lock_activity_best_effort(
            deps,
            auth,
            own_lock ? "file.unlocked" : "file.lock_force_released",
            rel,
            lock->item_kind,
            &*lock);

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"locked", false},
            {"lock", nullptr}
        });
    });
}

} // namespace pqnas
