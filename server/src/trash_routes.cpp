#include "trash_routes.h"

#include "storage_resolver.h"
#include "workspace_access_shared.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <system_error>

namespace pqnas {
namespace {

using json = nlohmann::json;

// Clamps client-provided list limits to a small, predictable server-side range.
//
// Architectural intent:
// - Keep trash list endpoints responsive even if a caller passes a very large limit.
// - Avoid exposing unlimited full-table scans through the HTTP API.
// - Keep pagination/simple "load more" behavior feasible at the route layer.
static std::size_t clamp_limit_local(std::size_t v) {
    if (v < 1) return 1;
    if (v > 500) return 500;
    return v;
}

// Parses the optional "limit" query parameter and falls back to a route-provided default.
//
// Bad/malformed input is intentionally treated as "use default" rather than as a hard error.
// That keeps the trash list endpoint tolerant of UI/client mistakes.
static std::size_t parse_limit_local(const httplib::Request& req, std::size_t defv) {
    if (!req.has_param("limit")) return defv;
    try {
        return clamp_limit_local(static_cast<std::size_t>(std::stoull(req.get_param_value("limit"))));
    } catch (...) {
        return defv;
    }
}

// Parses a simple boolean query-string flag.
//
// Accepted truthy forms are intentionally broad because these routes may be called by
// browser code, scripts, or future clients that serialize booleans differently.
static bool parse_bool_qs_local(const httplib::Request& req,
                                const char* key,
                                bool defv = false) {
    if (!req.has_param(key)) return defv;
    std::string v = req.get_param_value(key);
    for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return (v == "1" || v == "true" || v == "yes" || v == "on");
}

// Converts one TrashItemRec into the public API shape returned by trash endpoints.
//
// This intentionally exposes user-relevant trash metadata while keeping lower-level
// storage details such as payload_physical_path internal to the server.
static json trash_item_to_json_local(const TrashItemRec& rec) {
    return json{
        {"trash_id", rec.trash_id},
        {"scope_type", rec.scope_type},
        {"scope_id", rec.scope_id},
        {"origin_app", rec.origin_app},
        {"item_type", rec.item_type},
        {"original_rel_path", rec.original_rel_path},
        {"source_pool", rec.source_pool},
        {"source_tier_state", rec.source_tier_state},
        {"size_bytes", rec.size_bytes},
        {"file_count", rec.file_count},
        {"deleted_epoch", rec.deleted_epoch},
        {"purge_after_epoch", rec.purge_after_epoch},
        {"restore_status", rec.restore_status},
        {"status_updated_epoch", rec.status_updated_epoch}
    };
}

// Small bridge helper so route code can emit audit events without knowing whether
// auditing is wired in this process/context.
//
// This keeps the route implementation decoupled from the concrete audit backend.
static void audit_local(const TrashRoutesDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& fields) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
}

// Normalizes the "already handled elsewhere" race outcome used by restore/purge.
//
// Background auto-purge and manual restore/purge can legitimately race. The service layer
// reports that as "trash item is not active"; routes convert that into a nicer API error.
static bool is_trash_inactive_err_local(const std::string& err) {
    return err == "trash item is not active";
}
    static std::string trash_header_value_local(const httplib::Request& req, const char* key) {
    auto it = req.headers.find(key);
    return (it == req.headers.end()) ? std::string() : it->second;
}

    // Same-origin CSRF check for cookie-authenticated trash mutations.
    //
    // Why this exists:
    // - Trash restore and purge are destructive browser-triggered actions that
    //   usually authenticate with the session cookie.
    // - We require same-origin requests so another site cannot trigger restore or
    //   purge through the user's logged-in browser session.
    //
    // Rules:
    // - Bearer-token requests are exempt because they do not depend on ambient
    //   browser cookies.
    // - Prefer Origin when present.
    // - Fall back to Referer for same-origin browser requests that omit Origin.
    // - Reject requests with mismatched origin/referer or with neither header.
    bool require_same_origin_for_cookie_mutation_trash_local(
        const httplib::Request& req,
        httplib::Response& res,
        const std::string& expected_origin
    ) {
    const std::string auth = trash_header_value_local(req, "Authorization");
    if (auth.rfind("Bearer ", 0) == 0) return true;

    const std::string origin = trash_header_value_local(req, "Origin");
    if (!origin.empty()) {
        if (origin == expected_origin) return true;
        res.status = 403;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
        return false;
    }

    const std::string referer = trash_header_value_local(req, "Referer");
    if (!referer.empty()) {
        if (referer.rfind(expected_origin, 0) == 0) return true;
        res.status = 403;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
        return false;
    }

    res.status = 403;
    res.set_header("Content-Type", "application/json");
    res.body = R"({"ok":false,"error":"forbidden","message":"missing origin"})";
    return false;
}
    // Thin deps-aware wrapper for trash-route same-origin enforcement.
    //
    // Why this exists:
    // - Trash routes receive configuration through TrashRoutesDeps.
    // - This keeps the route file independent from any global ORIGIN symbol.
    // - It also fails closed if origin wiring is missing or empty, preventing trash
    //   mutations from running without the intended CSRF protection.
    bool require_same_origin_for_cookie_mutation_trash_deps(
        const httplib::Request& req,
        httplib::Response& res,
        const TrashRoutesDeps& deps
    ) {
    if (!deps.origin || deps.origin->empty()) {
        res.status = 500;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"server_error","message":"origin not configured"})";
        return false;
    }
    return require_same_origin_for_cookie_mutation_trash_local(req, res, *deps.origin);
}
// Resolves a logical relative path under an allowed restore root.
//
// Security intent:
// - Reuse strict path normalization rules already used elsewhere in the file/storage API.
// - Guarantee the resolved restore destination remains inside the allowed user/workspace root.
// - Prevent path traversal via crafted original_rel_path values.
static bool resolve_path_under_root_local(const std::filesystem::path& root,
                                          const std::string& rel_path,
                                          std::filesystem::path* out_abs,
                                          std::string* err) {
    if (err) err->clear();
    if (!out_abs) {
        if (err) *err = "null out_abs";
        return false;
    }

    std::string rel_norm;
    if (!normalize_user_rel_path_strict(rel_path, &rel_norm, err)) {
        return false;
    }

    const auto root_norm = root.lexically_normal();
    const auto abs = (root_norm / std::filesystem::path(rel_norm)).lexically_normal();

    const std::string root_s = root_norm.generic_string();
    const std::string abs_s = abs.generic_string();

    if (abs_s != root_s && abs_s.rfind(root_s + "/", 0) != 0) {
        if (err) *err = "resolved path escaped root";
        return false;
    }

    *out_abs = abs;
    return true;
}

// Reloads and resolves one workspace record by id for trash routes.
//
// Architectural note:
// - Workspaces are reloaded on demand here so route authorization uses the latest membership
//   and status state rather than stale in-memory assumptions.
// - That is especially important for restore/purge, which are write operations.
static bool load_workspace_for_scope_local(const TrashRoutesDeps& deps,
                                           const std::string& workspace_id,
                                           WorkspaceRec* out_w,
                                           std::string* err) {
    if (err) err->clear();
    if (!out_w) {
        if (err) *err = "null out_w";
        return false;
    }
    if (!deps.workspaces || !deps.workspaces_path) {
        if (err) *err = "workspaces missing";
        return false;
    }
    if (!deps.workspaces->load(*deps.workspaces_path)) {
        if (err) *err = "workspaces reload failed";
        return false;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        if (err) *err = "workspace not found";
        return false;
    }

    *out_w = *wopt;
    return true;
}

// Workspace trash is readable by any enabled workspace member.
//
// List access is intentionally broader than write access so regular members can inspect
// the workspace trash even if they cannot restore or purge from it.
static bool actor_can_read_workspace_trash_local(const WorkspaceRec& w,
                                                 const std::string& actor_fp) {
    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    return mopt.has_value();
}

// Workspace trash restore/purge requires write-capable membership.
//
// Current policy:
// - owners and editors may mutate workspace trash
// - viewers/readers may only inspect it
static bool actor_can_write_workspace_trash_local(const WorkspaceRec& w,
                                                  const std::string& actor_fp) {
    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) return false;
    return (mopt->role == "owner" || mopt->role == "editor");
}

// Resolves the live restore root for a user-scope trash item.
//
// This ensures restore only proceeds if the user's storage is currently allocated and
// a valid user root can be resolved. Trash restore is therefore tied to live storage
// availability, not just to the presence of the trash row.
static bool get_user_restore_root_local(const TrashRoutesDeps& deps,
                                        const std::string& actor_fp,
                                        std::filesystem::path* out_root,
                                        std::string* err) {
    if (err) err->clear();
    if (!out_root) {
        if (err) *err = "null out_root";
        return false;
    }
    if (!deps.users) {
        if (err) *err = "users missing";
        return false;
    }
    auto uopt = deps.users->get(actor_fp);
    if (!uopt.has_value()) {
        if (err) *err = "user missing";
        return false;
    }
    if (uopt->storage_state != "allocated") {
        if (err) *err = "storage unallocated";
        return false;
    }
    if (!deps.user_dir_for_fp) {
        if (err) *err = "user_dir_for_fp missing";
        return false;
    }

    *out_root = deps.user_dir_for_fp(*deps.users, actor_fp);
    return true;
}

// Resolves the live restore root for a workspace-scope trash item.
//
// Current implementation deliberately uses the existing "default pool only" workspace root
// resolver dependency. That keeps trash restore aligned with current workspace storage
// semantics without re-implementing path policy here.
static bool get_workspace_restore_root_local(const TrashRoutesDeps& deps,
                                             const WorkspaceRec& w,
                                             std::filesystem::path* out_root,
                                             std::string* err) {
    if (err) err->clear();
    if (!out_root) {
        if (err) *err = "null out_root";
        return false;
    }
    if (w.storage_state != "allocated") {
        if (err) *err = "workspace storage unallocated";
        return false;
    }
    if (!deps.workspace_dir_for_default_pool_only || !deps.users_path) {
        if (err) *err = "workspace root resolver missing";
        return false;
    }

    *out_root = deps.workspace_dir_for_default_pool_only(*deps.users_path, w);
    return true;
}

} // namespace

// Registers the public trash HTTP endpoints.
//
// Route-layer responsibilities:
// - authenticate the actor
// - authorize access to the requested trash scope
// - validate/normalize request parameters
// - translate between JSON and TrashService/TrashIndex types
// - emit audit events for success/failure
//
// Service/index responsibilities remain below this layer:
// - TrashIndex provides metadata queries/state transitions
// - TrashService performs restore/purge filesystem coordination safely
void register_trash_routes(httplib::Server& srv, const TrashRoutesDeps& deps) {
    // Lists trash entries for either the authenticated user's own trash or a specific
    // workspace trash view.
    //
    // Query semantics:
    // - scope=user      -> actor's own trash
    // - scope=workspace -> requires workspace_id and membership checks
    // - include_inactive=true exposes restored/purged history as well
    srv.Get("/api/v4/trash/list", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        const std::string scope = req.has_param("scope") ? req.get_param_value("scope") : "user";
        const bool include_inactive = parse_bool_qs_local(req, "include_inactive", false);
        const std::size_t limit = parse_limit_local(req, 200);

        if (!deps.trash_index) {
            audit_local(deps, "v4.trash_list_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_index_missing"}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "trash index missing"}
            }.dump());
            return;
        }

        std::string scope_type;
        std::string scope_id;

        if (scope == "workspace") {
            const std::string workspace_id =
                req.has_param("workspace_id") ? req.get_param_value("workspace_id") : "";

            if (workspace_id.empty()) {
                audit_local(deps, "v4.trash_list_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "missing_workspace_id"}
                });
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "missing workspace_id"}
                }.dump());
                return;
            }

            WorkspaceRec w;
            std::string werr;
            if (!load_workspace_for_scope_local(deps, workspace_id, &w, &werr)) {
                audit_local(deps, "v4.trash_list_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "workspace_lookup_failed"},
                    {"workspace_id", workspace_id},
                    {"detail", werr}
                });
                deps.reply_json(res, 404, json{
                    {"ok", false},
                    {"error", "not_found"},
                    {"message", "workspace not found"}
                }.dump());
                return;
            }

            if (w.status != "enabled" || !actor_can_read_workspace_trash_local(w, actor_fp)) {
                audit_local(deps, "v4.trash_list_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "workspace_access_denied"},
                    {"workspace_id", workspace_id}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "forbidden"},
                    {"message", "workspace access denied"}
                }.dump());
                return;
            }

            scope_type = "workspace";
            scope_id = workspace_id;
        } else {
            // Any non-workspace value falls back to user scope intentionally.
            // This keeps the endpoint simple for UI callers and avoids introducing
            // a separate scope validation error path for stray values.
            scope_type = "user";
            scope_id = actor_fp;
        }

        std::string lerr;
        const auto rows = deps.trash_index->list_scope(scope_type, scope_id, include_inactive, limit, &lerr);
        if (!lerr.empty()) {
            audit_local(deps, "v4.trash_list_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "list_scope_failed"},
                {"scope_type", scope_type},
                {"scope_id", scope_id},
                {"detail", lerr}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list trash"}
            }.dump());
            return;
        }

        json items = json::array();
        for (const auto& row : rows) items.push_back(trash_item_to_json_local(row));

        audit_local(deps, "v4.trash_list_ok", "ok", {
            {"actor_fp", actor_fp},
            {"scope_type", scope_type},
            {"scope_id", scope_id},
            {"count", std::to_string(items.size())}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"scope_type", scope_type},
            {"scope_id", scope_id},
            {"include_inactive", include_inactive},
            {"items", items}
        }.dump());
    });

    // Restores one trash entry back into its live user/workspace root.
    //
    // Important route-layer flow:
    // 1) authenticate actor
    // 2) load trash row by id
    // 3) verify actor may write that scope
    // 4) resolve and validate the destination path under the allowed root
    // 5) delegate the actual restore/race-safe state transition to TrashService
    srv.Post("/api/v4/trash/restore", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }
        if (!require_same_origin_for_cookie_mutation_trash_deps(req, res, deps)) return;
        if (!deps.trash_index || !deps.trash_service) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_service_missing"}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "trash service missing"}
            }.dump());
            return;
        }

        json in = json::object();
        try {
            if (!req.body.empty()) in = json::parse(req.body);
        } catch (...) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "bad_json"}
            });
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string trash_id = in.value("trash_id", "");
        const bool rename_if_conflict = in.value("rename_if_conflict", false);

        if (trash_id.empty()) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "missing_trash_id"}
            });
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing trash_id"}
            }.dump());
            return;
        }

        std::string gerr;
        auto rec_opt = deps.trash_index->get(trash_id, &gerr);
        if (!gerr.empty()) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_get_failed"},
                {"trash_id", trash_id},
                {"detail", gerr}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read trash item"}
            }.dump());
            return;
        }
        if (!rec_opt.has_value()) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_not_found"},
                {"trash_id", trash_id}
            });
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "trash item not found"}
            }.dump());
            return;
        }

        const auto& rec = *rec_opt;

        std::filesystem::path restore_root;
        if (rec.scope_type == "workspace") {
            WorkspaceRec w;
            std::string werr;
            if (!load_workspace_for_scope_local(deps, rec.scope_id, &w, &werr) ||
                !actor_can_write_workspace_trash_local(w, actor_fp)) {
                audit_local(deps, "v4.trash_restore_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "workspace_write_denied"},
                    {"trash_id", trash_id},
                    {"workspace_id", rec.scope_id}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "forbidden"},
                    {"message", "workspace write access denied"}
                }.dump());
                return;
            }

            std::string rerr;
            if (!get_workspace_restore_root_local(deps, w, &restore_root, &rerr)) {
                audit_local(deps, "v4.trash_restore_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "workspace_restore_root_failed"},
                    {"trash_id", trash_id},
                    {"workspace_id", rec.scope_id},
                    {"detail", rerr}
                });
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "workspace restore root unavailable"}
                }.dump());
                return;
            }
        } else {
            if (rec.scope_id != actor_fp) {
                audit_local(deps, "v4.trash_restore_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "user_scope_denied"},
                    {"trash_id", trash_id},
                    {"scope_id", rec.scope_id}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "forbidden"},
                    {"message", "trash access denied"}
                }.dump());
                return;
            }

            std::string rerr;
            if (!get_user_restore_root_local(deps, actor_fp, &restore_root, &rerr)) {
                audit_local(deps, "v4.trash_restore_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "user_restore_root_failed"},
                    {"trash_id", trash_id},
                    {"detail", rerr}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "storage_unallocated"},
                    {"message", "storage not allocated"}
                }.dump());
                return;
            }
        }

        std::filesystem::path restore_abs;
        std::string perr;
        if (!resolve_path_under_root_local(restore_root, rec.original_rel_path, &restore_abs, &perr)) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "invalid_restore_path"},
                {"trash_id", trash_id},
                {"detail", perr}
            });
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid restore path"}
            }.dump());
            return;
        }

        TrashService::RestoreParams rp;
        rp.trash_id = trash_id;
        rp.restore_abs_path = restore_abs;
        rp.restore_root_abs = restore_root;
        rp.rename_if_conflict = rename_if_conflict;

        TrashService::RestoreResult rr;
        std::string rerr;
        if (!deps.trash_service->restore_from_trash(rp, &rr, &rerr)) {
            audit_local(deps, "v4.trash_restore_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "restore_failed"},
                {"trash_id", trash_id},
                {"detail", rerr}
            });

            if (is_trash_inactive_err_local(rerr)) {
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "trash_inactive"},
                    {"message", "trash item is no longer active"},
                    {"detail", rerr}
                }.dump());
                return;
            }

            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "restore failed"},
                {"detail", rerr}
            }.dump());
            return;
        }

        // The restore service may rename on conflict, so the route recomputes the final
        // logical relative path for audit/API response purposes.
        std::string restored_rel_path = rec.original_rel_path;
        {
            std::error_code ec;
            auto rel = std::filesystem::relative(rr.restored_abs_path, restore_root, ec);
            if (!ec && !rel.empty()) restored_rel_path = rel.generic_string();
        }

        audit_local(deps, "v4.trash_restore_ok", "ok", {
            {"actor_fp", actor_fp},
            {"trash_id", trash_id},
            {"scope_type", rec.scope_type},
            {"scope_id", rec.scope_id},
            {"original_rel_path", rec.original_rel_path},
            {"restored_rel_path", restored_rel_path},
            {"renamed", rr.renamed ? "true" : "false"}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"trash_id", rr.trash_id},
            {"item_type", rr.item_type},
            {"original_rel_path", rec.original_rel_path},
            {"restored_rel_path", restored_rel_path},
            {"size_bytes", rr.size_bytes},
            {"file_count", rr.file_count},
            {"renamed", rr.renamed}
        }.dump());
    });

    // Permanently purges one trash entry.
    //
    // Authorization mirrors restore:
    // - user trash: actor must own the scope
    // - workspace trash: actor must have write-capable workspace membership
    //
    // The actual payload removal and race-safe state claim happen inside TrashService.
    srv.Post("/api/v4/trash/purge", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }
        if (!require_same_origin_for_cookie_mutation_trash_deps(req, res, deps)) return;
        if (!deps.trash_index || !deps.trash_service) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_service_missing"}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "trash service missing"}
            }.dump());
            return;
        }

        json in = json::object();
        try {
            if (!req.body.empty()) in = json::parse(req.body);
        } catch (...) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "bad_json"}
            });
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string trash_id = in.value("trash_id", "");
        if (trash_id.empty()) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "missing_trash_id"}
            });
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing trash_id"}
            }.dump());
            return;
        }

        std::string gerr;
        auto rec_opt = deps.trash_index->get(trash_id, &gerr);
        if (!gerr.empty()) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_get_failed"},
                {"trash_id", trash_id},
                {"detail", gerr}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read trash item"}
            }.dump());
            return;
        }
        if (!rec_opt.has_value()) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "trash_not_found"},
                {"trash_id", trash_id}
            });
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "trash item not found"}
            }.dump());
            return;
        }

        const auto& rec = *rec_opt;

        if (rec.scope_type == "workspace") {
            WorkspaceRec w;
            std::string werr;
            if (!load_workspace_for_scope_local(deps, rec.scope_id, &w, &werr) ||
                !actor_can_write_workspace_trash_local(w, actor_fp)) {
                audit_local(deps, "v4.trash_purge_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "workspace_write_denied"},
                    {"trash_id", trash_id},
                    {"workspace_id", rec.scope_id}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "forbidden"},
                    {"message", "workspace write access denied"}
                }.dump());
                return;
            }
        } else {
            if (rec.scope_id != actor_fp) {
                audit_local(deps, "v4.trash_purge_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "user_scope_denied"},
                    {"trash_id", trash_id},
                    {"scope_id", rec.scope_id}
                });
                deps.reply_json(res, 403, json{
                    {"ok", false},
                    {"error", "forbidden"},
                    {"message", "trash access denied"}
                }.dump());
                return;
            }
        }

        TrashService::PurgeParams pp;
        pp.trash_id = trash_id;

        TrashService::PurgeResult pr;
        std::string perr;
        if (!deps.trash_service->purge_from_trash(pp, &pr, &perr)) {
            audit_local(deps, "v4.trash_purge_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "purge_failed"},
                {"trash_id", trash_id},
                {"detail", perr}
            });

            if (is_trash_inactive_err_local(perr)) {
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "trash_inactive"},
                    {"message", "trash item is no longer active"},
                    {"detail", perr}
                }.dump());
                return;
            }

            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "purge failed"},
                {"detail", perr}
            }.dump());
            return;
        }

        audit_local(deps, "v4.trash_purge_ok", "ok", {
            {"actor_fp", actor_fp},
            {"trash_id", trash_id},
            {"scope_type", rec.scope_type},
            {"scope_id", rec.scope_id},
            {"original_rel_path", rec.original_rel_path}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"trash_id", pr.trash_id},
            {"size_bytes", pr.size_bytes},
            {"file_count", pr.file_count}
        }.dump());
    });
}

} // namespace pqnas