#include "routes_workspace_external_sessions.h"

#include <cctype>
#include <limits>

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

json external_session_public_json(const WorkspaceExternalSessionRec& in) {
    WorkspaceExternalSessionRec r = in;
    normalize_workspace_external_session_rec_v1(&r);

    return json{
        {"session_id", r.session_id},
        {"workspace_id", r.workspace_id},
        {"status", r.status},
        {"reason", r.reason},
        {"workspace_role", r.workspace_role},
        {"created_at", r.created_at},
        {"approved_at", r.approved_at},
        {"expires_at_epoch", r.expires_at_epoch}
    };
}

void audit_session_event(const WorkspaceExternalSessionRouteDeps& deps,
                         const std::string& event,
                         const std::string& outcome,
                         const std::map<std::string, std::string>& fields) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
}

bool reload_workspaces_or_500(const WorkspaceExternalSessionRouteDeps& deps,
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

} // namespace

void register_workspace_external_session_routes(
    httplib::Server& srv,
    const WorkspaceExternalSessionRouteDeps& deps) {

    // Public start route. The link itself grants no access; it only creates
    // a short-lived DNA auth challenge for this workspace.
    srv.Post("/api/v4/workspaces/external-sessions/start",
             [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.reply_json || !deps.workspaces || !deps.external_sessions ||
            !deps.origin || !deps.app ||
            !deps.random_b64url || !deps.build_req_payload_canonical ||
            !deps.sign_req_token || !deps.st_hash_b64_from_st) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "external session routes not fully configured"}
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
        if (!is_valid_workspace_id(workspace_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id"}
            }.dump());
            return;
        }

        long ttl = json_long_default(j, "expires_in_seconds", 120);
        if (ttl < 60) ttl = 60;
        if (ttl > 10 * 60) ttl = 10 * 60;

        if (!reload_workspaces_or_500(deps, res)) return;

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value() || wopt->status != "enabled") {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "workspace_not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        deps.external_sessions->mark_expired_pending(now);

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

        WorkspaceExternalSessionRec rec;
        for (int i = 0; i < 16; ++i) {
            rec.session_id = new_workspace_external_session_id();
            if (!deps.external_sessions->get(rec.session_id).has_value()) break;
            rec.session_id.clear();
        }

        if (rec.session_id.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to generate session id"}
            }.dump());
            return;
        }

        rec.workspace_id = workspace_id;
        rec.st_hash_b64 = st_hash;
        rec.st_token = st;
        rec.status = "pending";
        rec.created_at = deps.now_iso_utc ? deps.now_iso_utc() : "";
        rec.expires_at_epoch = exp;

        if (!deps.external_sessions->upsert(rec)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to store external session"}
            }.dump());
            return;
        }

        audit_session_event(deps, "workspace.external_session_started", "ok", {
            {"session_id", rec.session_id},
            {"workspace_id", rec.workspace_id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"session", external_session_public_json(rec)},
            {"qr_svg", std::string("/api/v4/workspaces/external-sessions/qr.svg?session_id=") +
                       (deps.url_encode ? deps.url_encode(rec.session_id) : rec.session_id)}
        }.dump());
    });

    srv.Get("/api/v4/workspaces/external-sessions/qr.svg",
            [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.reply_json || !deps.external_sessions ||
            !deps.origin || !deps.app || !deps.url_encode || !deps.qr_svg_from_text) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "external session QR route not fully configured"}
            }.dump());
            return;
        }

        const std::string session_id = trim_copy_safe(req.get_param_value("session_id"));
        if (!is_valid_workspace_external_session_id(session_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid session_id"}
            }.dump());
            return;
        }

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        deps.external_sessions->mark_expired_pending(now);

        auto sess = deps.external_sessions->get(session_id);
        if (!sess.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "session_not_found"},
                {"message", "session not found"}
            }.dump());
            return;
        }

        if (sess->status != "pending" || sess->st_token.empty()) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "session_not_pending"},
                {"message", "session is not pending"}
            }.dump());
            return;
        }

        const std::string qr_uri =
            "dna://auth?v=5&st=" + deps.url_encode(sess->st_token) +
            "&origin=" + deps.url_encode(*deps.origin) +
            "&app=" + deps.url_encode(*deps.app);

        try {
            const std::string svg = deps.qr_svg_from_text(qr_uri, 6, 4);

            res.status = 200;
            res.set_header("Content-Type", "image/svg+xml; charset=utf-8");
            res.set_header("Cache-Control", "no-store");
            res.body = svg;
        } catch (const std::exception& e) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", e.what()}
            }.dump());
        }
    });

    srv.Get("/api/v4/workspaces/external-sessions/status",
            [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.reply_json || !deps.external_sessions) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "external session status route not fully configured"}
            }.dump());
            return;
        }

        const std::string session_id = trim_copy_safe(req.get_param_value("session_id"));
        if (!is_valid_workspace_external_session_id(session_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid session_id"}
            }.dump());
            return;
        }

        const long now = deps.now_epoch_sec ? static_cast<long>(deps.now_epoch_sec()) : 0L;
        deps.external_sessions->mark_expired_pending(now);

        auto sess = deps.external_sessions->get(session_id);
        if (!sess.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "session_not_found"},
                {"message", "session not found"}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"session", external_session_public_json(*sess)}
        }.dump());
    });
}

} // namespace pqnas
