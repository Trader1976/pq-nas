#include "routes_file_annotations.h"

#include "activity_log.h"
#include "file_annotations.h"

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

void reply_json_local(const FileAnnotationRoutesDeps& deps,
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
    if (s == "file" || s == "dir" || s == "folder") {
        return s == "folder" ? "dir" : s;
    }
    return "unknown";
}

bool note_has_description(const FileNoteRec& r) {
    return !trim_copy(r.description).empty();
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
        const std::string part = s.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);

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

struct ScopeAuth {
    std::string scope_type;
    std::string scope_id;
    std::string actor_fp;
    std::string actor_role;
    bool can_read = false;
    bool can_write = false;
};

bool authorize_scope(const FileAnnotationRoutesDeps& deps,
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
            {"message", "file annotation route dependencies missing"}
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

    if (scope_type.empty()) scope_type = scope_id.empty() ? "user" : "workspace";

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
                {"message", "user file notes are private to the signed-in user"}
            });
            return false;
        }

        auth.scope_id = scope_id;
        auth.can_read = true;
        auth.can_write = true;
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

json note_to_json(const FileNoteRec& r) {
    return json{
        {"scope_type", r.scope_type},
        {"scope_id", r.scope_id},
        {"logical_rel_path", r.logical_rel_path},
        {"item_kind", r.item_kind},
        {"description", r.description},
        {"has_description", note_has_description(r)},
        {"updated_by_fp", r.updated_by_fp},
        {"updated_by_fp_short", fp_short(r.updated_by_fp)},
        {"updated_by_label", fp_short(r.updated_by_fp)},
        {"created_at_epoch", r.created_at_epoch},
        {"updated_at_epoch", r.updated_at_epoch}
    };
}

std::string param_or_empty(const httplib::Request& req, const char* name) {
    return req.has_param(name) ? req.get_param_value(name) : std::string{};
}

std::string activity_target_name_for_path(const std::string& rel, const std::string& item_kind) {
    try {
        std::filesystem::path p(rel);
        const std::string leaf = p.filename().string();
        if (!leaf.empty()) return leaf;
    } catch (...) {
    }

    if (item_kind == "dir") return "folder";
    if (item_kind == "file") return "file";
    return "item";
}

void record_file_note_activity_best_effort(const FileAnnotationRoutesDeps& deps,
                                           const ScopeAuth& auth,
                                           const std::optional<FileNoteRec>& before,
                                           const FileNoteRec& after) {
    if (!deps.users || !deps.user_dir_for_fp || auth.actor_fp.empty()) return;

    const std::string before_desc = before.has_value() ? trim_copy(before->description) : "";
    const std::string after_desc = trim_copy(after.description);
    if (before.has_value() && before->description == after.description) return;
    if (before_desc.empty() && after_desc.empty()) return;

    std::filesystem::path user_root;
    try {
        user_root = deps.user_dir_for_fp(*deps.users, auth.actor_fp);
    } catch (...) {
        return;
    }
    if (user_root.empty()) return;

    const bool had_description = !before_desc.empty();
    const bool has_description = !after_desc.empty();

    pqnas::activity::ActivityEvent ev;
    ev.owner_user_id = auth.actor_fp;

    ev.actor.user_id = auth.actor_fp;
    ev.actor.display_name = fp_short(auth.actor_fp);
    ev.actor.fingerprint_short = fp_short(auth.actor_fp);
    ev.actor.kind = "user";

    if (!had_description && has_description) {
        ev.event_type = "file.description_added";
    } else if (had_description && has_description) {
        ev.event_type = "file.description_updated";
    } else {
        ev.event_type = "file.description_cleared";
    }

    ev.scope_type = auth.scope_type;
    ev.scope_id = auth.scope_id;

    ev.target_kind = after.item_kind == "dir" ? "folder" : (after.item_kind == "file" ? "file" : "item");
    ev.target_path = after.logical_rel_path;
    ev.target_name = activity_target_name_for_path(after.logical_rel_path, after.item_kind);

    if (ev.event_type == "file.description_added") {
        ev.message = "Added description to " + ev.target_name;
    } else if (ev.event_type == "file.description_updated") {
        ev.message = "Updated description for " + ev.target_name;
    } else {
        ev.message = "Cleared description for " + ev.target_name;
    }

    ev.details = json{
        {"scope_type", auth.scope_type},
        {"scope_id", auth.scope_id},
        {"logical_rel_path", after.logical_rel_path},
        {"item_type", after.item_kind},
        {"had_description", had_description},
        {"has_description", has_description}
    };

    std::string activity_err;
    (void)pqnas::activity::record_user_activity(user_root, ev, &activity_err);
}

} // namespace

void register_file_annotation_routes(httplib::Server& srv,
                                     const FileAnnotationRoutesDeps& deps) {
    srv.Get("/api/v4/file-annotations/note",
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

        FileAnnotationsStore store(deps.annotations_db_path);
        std::string err;
        auto note = store.get_note(auth.scope_type, auth.scope_id, rel, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load file note"}
            });
            return;
        }

        if (!note.has_value()) {
            reply_json_local(deps, res, 200, json{
                {"ok", true},
                {"resolved", false},
                {"note", nullptr}
            });
            return;
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"resolved", true},
            {"note", note_to_json(*note)}
        });
    });

    srv.Post("/api/v4/file-annotations/notes/resolve",
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

        if (!body.contains("paths") || !body["paths"].is_array()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "paths array required"}
            });
            return;
        }

        std::vector<std::string> paths;
        std::string perr;
        for (const auto& v : body["paths"]) {
            if (!v.is_string()) continue;
            std::string rel;
            if (!normalize_rel_path(v.get<std::string>(), &rel, &perr)) {
                reply_json_local(deps, res, 400, json{
                    {"ok", false},
                    {"error", "bad_path"},
                    {"message", perr.empty() ? "invalid path" : perr}
                });
                return;
            }
            paths.push_back(rel);
            if (paths.size() >= 500) break;
        }

        std::sort(paths.begin(), paths.end());
        paths.erase(std::unique(paths.begin(), paths.end()), paths.end());

        FileAnnotationsStore store(deps.annotations_db_path);
        std::string err;
        const auto rows = store.list_notes_for_paths(auth.scope_type, auth.scope_id, paths, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load file notes"}
            });
            return;
        }

        json notes = json::object();
        for (const auto& row : rows) {
            if (!note_has_description(row)) continue;
            notes[row.logical_rel_path] = note_to_json(row);
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"notes", notes},
            {"count", notes.size()}
        });
    });

    srv.Post("/api/v4/file-annotations/note",
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

        std::string description = body.value("description", "");
        if (description.size() > 20000) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "description is too large"}
            });
            return;
        }

        FileAnnotationsStore store(deps.annotations_db_path);

        std::string err;
        auto before = store.get_note(auth.scope_type, auth.scope_id, rel, &err);
        if (!err.empty()) err.clear();

        const std::int64_t now = deps.now_epoch_sec ? deps.now_epoch_sec() : 0;

        FileNoteRec rec;
        rec.scope_type = auth.scope_type;
        rec.scope_id = auth.scope_id;
        rec.logical_rel_path = rel;
        rec.item_kind = normalize_item_kind(body.value("item_kind", ""));
        rec.description = description;
        rec.updated_by_fp = auth.actor_fp;
        rec.created_at_epoch = before.has_value() && before->created_at_epoch > 0 ? before->created_at_epoch : now;
        rec.updated_at_epoch = now;

        if (!store.upsert_note(rec, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save file note"}
            });
            return;
        }

        err.clear();
        auto saved = store.get_note(auth.scope_type, auth.scope_id, rel, &err);
        const FileNoteRec saved_rec = saved.has_value() ? *saved : rec;

        record_file_note_activity_best_effort(deps, auth, before, saved_rec);

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"note", note_to_json(saved_rec)}
        });
    });
}

} // namespace pqnas
