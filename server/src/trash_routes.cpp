#include "trash_routes.h"

#include "storage_resolver.h"
#include "workspace_access_shared.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <system_error>

namespace pqnas {
namespace {

using json = nlohmann::json;

static std::size_t clamp_limit_local(std::size_t v) {
    if (v < 1) return 1;
    if (v > 500) return 500;
    return v;
}

static std::size_t parse_limit_local(const httplib::Request& req, std::size_t defv) {
    if (!req.has_param("limit")) return defv;
    try {
        return clamp_limit_local(static_cast<std::size_t>(std::stoull(req.get_param_value("limit"))));
    } catch (...) {
        return defv;
    }
}

static bool parse_bool_qs_local(const httplib::Request& req,
                                const char* key,
                                bool defv = false) {
    if (!req.has_param(key)) return defv;
    std::string v = req.get_param_value(key);
    for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return (v == "1" || v == "true" || v == "yes" || v == "on");
}

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

static void audit_local(const TrashRoutesDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& fields) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
}

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

static bool actor_can_read_workspace_trash_local(const WorkspaceRec& w,
                                                 const std::string& actor_fp) {
    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    return mopt.has_value();
}

static bool actor_can_write_workspace_trash_local(const WorkspaceRec& w,
                                                  const std::string& actor_fp) {
    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) return false;
    return (mopt->role == "owner" || mopt->role == "editor");
}

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

void register_trash_routes(httplib::Server& srv, const TrashRoutesDeps& deps) {
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

    srv.Post("/api/v4/trash/restore", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

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
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "restore failed"},
                {"detail", rerr}
            }.dump());
            return;
        }

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

    srv.Post("/api/v4/trash/purge", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

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