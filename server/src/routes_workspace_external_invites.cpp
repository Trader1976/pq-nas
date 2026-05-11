#include "routes_workspace_external_invites.h"

#include "workspace_access_shared.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>

#include <nlohmann/json.hpp>

namespace pqnas {
namespace {

using nlohmann::json;

std::string trim_copy_safe(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::string header_value_local(const httplib::Request& req, const char* key) {
    auto it = req.headers.find(key);
    return (it == req.headers.end()) ? std::string{} : it->second;
}

bool require_same_origin_for_cookie_mutation_local(
    const httplib::Request& req,
    httplib::Response& res,
    const WorkspaceExternalInviteRouteDeps& deps
) {
    if (!deps.origin || deps.origin->empty()) {
        res.status = 500;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"server_error","message":"origin not configured"})";
        return false;
    }

    const std::string authz = header_value_local(req, "Authorization");
    if (authz.rfind("Bearer ", 0) == 0) return true;

    const std::string origin = header_value_local(req, "Origin");
    if (!origin.empty()) {
        if (origin == *deps.origin) return true;

        res.status = 403;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
        return false;
    }

    const std::string referer = header_value_local(req, "Referer");
    if (!referer.empty()) {
        const std::string allowed_prefix = *deps.origin + "/";
        if (referer == *deps.origin || referer.rfind(allowed_prefix, 0) == 0) return true;

        res.status = 403;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
        return false;
    }

    res.status = 403;
    res.set_header("Content-Type", "application/json");
    res.body = R"({"ok":false,"error":"forbidden","message":"origin required"})";
    return false;
}

void audit_invite_event(const WorkspaceExternalInviteRouteDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& fields) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
}

bool reload_workspaces_or_500(const WorkspaceExternalInviteRouteDeps& deps,
                              httplib::Response& res) {
    if (!deps.workspaces || !deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return false;
    }
    return true;
}

bool reload_invites_or_500(const WorkspaceExternalInviteRouteDeps& deps,
                           httplib::Response& res) {
    if (!deps.external_invites || !deps.external_invites->load(deps.external_invites_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "external_invites_reload_failed"},
            {"message", "failed to reload external invites"}
        }.dump());
        return false;
    }
    return true;
}

bool save_invites_or_500(const WorkspaceExternalInviteRouteDeps& deps,
                         httplib::Response& res) {
    if (!deps.external_invites || !deps.external_invites->save(deps.external_invites_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "external_invites_save_failed"},
            {"message", "failed to save external invites"}
        }.dump());
        return false;
    }
    return true;
}

bool actor_is_enabled_workspace_owner(const WorkspaceRec& w, const std::string& actor_fp) {
    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) return false;
    return mopt->role == "owner";
}

long json_long_default(const json& j, const char* key, long defv) {
    auto it = j.find(key);
    if (it == j.end()) return defv;

    try {
        if (it->is_number_integer()) return it->get<long>();
        if (it->is_number_unsigned()) {
            const auto v = it->get<unsigned long long>();
            if (v > static_cast<unsigned long long>(std::numeric_limits<long>::max())) {
                return std::numeric_limits<long>::max();
            }
            return static_cast<long>(v);
        }
    } catch (...) {
        return defv;
    }

    return defv;
}

json invite_public_json(const WorkspaceExternalInviteRec& in) {
    WorkspaceExternalInviteRec r = in;
    normalize_workspace_external_invite_rec_v1(&r);

    return json{
        {"invite_id", r.invite_id},
        {"workspace_id", r.workspace_id},
        {"role", r.role},
        {"status", r.status},
        {"created_by", r.created_by},
        {"created_at", r.created_at},
        {"expires_at_epoch", r.expires_at_epoch},
        {"accepted_fingerprint", r.accepted_fingerprint},
        {"accepted_at", r.accepted_at}
    };
}

bool expire_pending_invites_if_needed(const WorkspaceExternalInviteRouteDeps& deps,
                                      httplib::Response& res,
                                      long now) {
    const std::size_t changed = deps.external_invites
        ? deps.external_invites->mark_expired_pending(now)
        : 0;

    if (changed == 0) return true;
    return save_invites_or_500(deps, res);
}

} // namespace

void register_workspace_external_invite_routes(
    httplib::Server& srv,
    const WorkspaceExternalInviteRouteDeps& deps) {

    // POST /api/v4/workspaces/external-invites/create
    //
    // Creates a workspace-scoped external invite and returns a QR endpoint.
    // MVP policy: only enabled workspace owners may create external invites.
    srv.Post("/api/v4/workspaces/external-invites/create",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) return;

        if (!deps.reply_json || !deps.workspaces || !deps.external_invites ||
            !deps.origin || !deps.app ||
            !deps.random_b64url || !deps.build_req_payload_canonical ||
            !deps.sign_req_token || !deps.st_hash_b64_from_st) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "external invite routes not fully configured"}
            }.dump());
            return;
        }

        json j;
        try {
            j = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (...) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string role = normalize_workspace_external_invite_role_copy(j.value("role", "viewer"));

        if (!is_valid_workspace_id(workspace_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id"}
            }.dump());
            return;
        }

        long ttl = json_long_default(j, "expires_in_seconds", 24 * 3600);
        if (ttl < 300) ttl = 300;
        if (ttl > 7 * 24 * 3600) ttl = 7 * 24 * 3600;

        if (!reload_workspaces_or_500(deps, res)) return;
        if (!reload_invites_or_500(deps, res)) return;

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        if (!expire_pending_invites_if_needed(deps, res, now)) return;

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value() || wopt->status != "enabled") {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "workspace_not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        if (!actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            audit_invite_event(deps, "workspace.external_invite_create_refused", "fail", {
                {"reason", "owner_required"},
                {"workspace_id", workspace_id},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        const std::string sid = deps.random_b64url(18);
        const std::string chal = deps.random_b64url(32);
        const std::string nonce = deps.random_b64url(18);

        if (sid.empty() || chal.empty() || nonce.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "rng failed"}
            }.dump());
            return;
        }

        const long iat = now;
        const long exp = now + ttl;

        const std::string payload = deps.build_req_payload_canonical(sid, chal, nonce, iat, exp);
        const std::string st = deps.sign_req_token(payload);
        const std::string st_hash = deps.st_hash_b64_from_st(st);

        if (payload.empty() || st.empty() || st_hash.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create auth token"}
            }.dump());
            return;
        }

        WorkspaceExternalInviteRec rec;
        for (int i = 0; i < 16; ++i) {
            rec.invite_id = new_workspace_external_invite_id();
            if (!deps.external_invites->exists(rec.invite_id)) break;
            rec.invite_id.clear();
        }

        if (rec.invite_id.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to generate invite id"}
            }.dump());
            return;
        }

        rec.workspace_id = workspace_id;
        rec.st_hash_b64 = st_hash;
        rec.st_token = st;
        rec.role = role;
        rec.status = "pending";
        rec.created_by = actor_fp;
        rec.created_at = deps.now_iso_utc ? deps.now_iso_utc() : "";
        rec.expires_at_epoch = exp;

        if (!deps.external_invites->upsert(rec)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to store invite"}
            }.dump());
            return;
        }

        if (!save_invites_or_500(deps, res)) return;

        audit_invite_event(deps, "workspace.external_invite_created", "ok", {
            {"workspace_id", workspace_id},
            {"invite_id", rec.invite_id},
            {"role", role},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"invite", invite_public_json(rec)},
            {"qr_svg", std::string("/api/v4/workspaces/external-invites/qr.svg?invite_id=") +
                       (deps.url_encode ? deps.url_encode(rec.invite_id) : rec.invite_id)}
        }.dump());
    });

    // GET /api/v4/workspaces/external-invites/qr.svg?invite_id=wsi_xxx
    //
    // Public-by-invite-id: this QR link is intentionally sendable to outsiders.
    // The invite_id is the bearer secret; acceptance still requires DNA Connect auth.
    srv.Get("/api/v4/workspaces/external-invites/qr.svg",
            [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.reply_json || !deps.external_invites ||
            !deps.origin || !deps.app || !deps.url_encode || !deps.qr_svg_from_text) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "external invite QR route not fully configured"}
            }.dump());
            return;
        }

        const std::string invite_id = trim_copy_safe(req.get_param_value("invite_id"));
        if (!is_valid_workspace_external_invite_id(invite_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid invite_id"}
            }.dump());
            return;
        }

        if (!reload_invites_or_500(deps, res)) return;

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        if (!expire_pending_invites_if_needed(deps, res, now)) return;

        auto inv = deps.external_invites->get(invite_id);
        if (!inv.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "invite_not_found"},
                {"message", "invite not found"}
            }.dump());
            return;
        }

        if (inv->status != "pending" || inv->st_token.empty()) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "invite_not_pending"},
                {"message", "invite is not pending"}
            }.dump());
            return;
        }

        const std::string qr_uri =
            "dna://auth?v=5&st=" + deps.url_encode(inv->st_token) +
            "&origin=" + deps.url_encode(*deps.origin) +
            "&app=" + deps.url_encode(*deps.app);

        try {
            const std::string svg = deps.qr_svg_from_text(qr_uri, 6, 4);

            res.status = 200;
            res.set_header("Content-Type", "image/svg+xml; charset=utf-8");
            res.set_header("Cache-Control", "no-store");
            res.body = svg;
        } catch (const std::exception&) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to generate QR code"}
            }.dump());
        }
    });

    // GET /api/v4/workspaces/external-invites/status?invite_id=wsi_xxx
    srv.Get("/api/v4/workspaces/external-invites/status",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        const std::string invite_id = trim_copy_safe(req.get_param_value("invite_id"));
        if (!is_valid_workspace_external_invite_id(invite_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid invite_id"}
            }.dump());
            return;
        }

        if (!reload_workspaces_or_500(deps, res)) return;
        if (!reload_invites_or_500(deps, res)) return;

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        if (!expire_pending_invites_if_needed(deps, res, now)) return;

        auto inv = deps.external_invites->get(invite_id);
        if (!inv.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "invite_not_found"},
                {"message", "invite not found"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(inv->workspace_id);
        if (!wopt.has_value() || !actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"invite", invite_public_json(*inv)}
        }.dump());
    });
}

} // namespace pqnas
