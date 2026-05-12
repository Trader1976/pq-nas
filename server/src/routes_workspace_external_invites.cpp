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


std::string html_escape_local(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);

    for (char ch : in) {
        switch (ch) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out.push_back(ch); break;
        }
    }

    return out;
}

bool request_wants_html_local(const httplib::Request& req) {
    const std::string accept = header_value_local(req, "Accept");
    return accept.find("text/html") != std::string::npos;
}

void reply_external_invite_landing_html_local(
    const WorkspaceExternalInviteRouteDeps& deps,
    httplib::Response& res,
    const WorkspaceExternalInviteRec& inv,
    const WorkspaceRec& w
) {
    const std::string origin = deps.origin ? *deps.origin : std::string{};
    const std::string invite_id_q = deps.url_encode ? deps.url_encode(inv.invite_id) : inv.invite_id;
    const std::string workspace_id_q = deps.url_encode ? deps.url_encode(w.workspace_id) : w.workspace_id;

    const std::string page_url =
        origin + "/api/v4/workspaces/external-invites/qr.svg?invite_id=" + invite_id_q;

    const std::string qr_url =
        "/api/v4/workspaces/external-invites/qr.svg?invite_id=" + invite_id_q;

    const std::string member_access_url =
        origin + "/static/external_workspace.html?workspace_id=" + workspace_id_q;

    std::string refresh_meta;
    if (inv.status == "pending" && !inv.st_token.empty()) {
        // Keep the browser page alive while the outsider scans/accepts with DNA Connect.
        // Once the invite becomes accepted, the next refresh will redirect to member access.
        refresh_meta = "<meta http-equiv=\"refresh\" content=\"2\">\n";
    } else if (inv.status == "accepted") {
        refresh_meta =
            "<meta http-equiv=\"refresh\" content=\"1; url=" +
            html_escape_local(member_access_url) +
            "\">\n";
    }

    const std::string workspace_name =
        html_escape_local(w.name.empty() ? w.workspace_id : w.name);

    const std::string workspace_notes = html_escape_local(w.notes);
    const std::string invite_role = html_escape_local(inv.role.empty() ? "viewer" : inv.role);
    const std::string invite_status = html_escape_local(inv.status.empty() ? "pending" : inv.status);

    std::string state_title = "Scan with DNA Connect";
    std::string state_text =
        "Open DNA Connect on your phone and scan this QR code to accept the external Shared Space invite.";

    if (inv.status == "accepted") {
        state_title = "Invite already accepted";
        state_text =
            "This one-time invite has already been accepted. Use the member access link below for future visits.";
    } else if (inv.status == "expired") {
        state_title = "Invite expired";
        state_text =
            "This one-time invite has expired. Ask the Shared Space owner to create a new invite.";
    } else if (inv.status != "pending" || inv.st_token.empty()) {
        state_title = "Invite unavailable";
        state_text =
            "This one-time invite cannot be used. Ask the Shared Space owner to create a new invite.";
    }

    std::string notes_html;
    if (!workspace_notes.empty()) {
        notes_html =
            "<div class=\"notes\"><div class=\"label\">Description</div><p>" +
            workspace_notes +
            "</p></div>";
    }

    std::string qr_html;
    if (inv.status == "pending" && !inv.st_token.empty()) {
        qr_html =
            "<div class=\"qrbox\">"
            "<img src=\"" + html_escape_local(qr_url) + "\" alt=\"DNA Connect invite QR\">"
            "</div>";
    } else {
        qr_html =
            "<div class=\"qrbox mutedbox\">"
            "<div class=\"bigmark\">!</div>"
            "<div>This QR invite is no longer active.</div>"
            "</div>";
    }

    const std::string html =
        std::string("<!doctype html>\n") +
R"HTML(<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
)HTML" +
        refresh_meta +
R"HTML(<title>DNA-Nexus External Invite</title>
<style>
:root{
    color-scheme:dark;
    --bg:#080807;
    --panel:#14110e;
    --panel2:#1c1712;
    --fg:#f5eee6;
    --muted:#c9b7a6;
    --orange:#ff7a18;
    --orange2:#ffb36a;
    --line:rgba(255,122,24,.38);
}
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    background:
        radial-gradient(circle at 20% 10%, rgba(255,122,24,.20), transparent 32rem),
        radial-gradient(circle at 80% 70%, rgba(255,122,24,.10), transparent 34rem),
        linear-gradient(135deg, #050505, #14100c 60%, #080807);
    color:var(--fg);
    font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
.wrap{
    max-width:1040px;
    margin:0 auto;
    padding:42px 18px;
}
.brand{
    display:flex;
    align-items:center;
    gap:12px;
    margin-bottom:18px;
    letter-spacing:.08em;
    text-transform:uppercase;
    color:var(--orange2);
    font-weight:900;
}
.logo{
    width:38px;
    height:38px;
    border-radius:12px;
    border:1px solid var(--line);
    background:
        linear-gradient(135deg, rgba(255,122,24,.85), rgba(255,122,24,.08)),
        #111;
    box-shadow:0 0 26px rgba(255,122,24,.22);
}
.card{
    border:1px solid var(--line);
    background:linear-gradient(180deg, rgba(28,23,18,.96), rgba(12,10,8,.96));
    border-radius:24px;
    box-shadow:0 22px 80px rgba(0,0,0,.52);
    overflow:hidden;
}
.hero{
    display:grid;
    grid-template-columns:minmax(0,1fr) minmax(260px,390px);
    gap:28px;
    padding:30px;
}
@media (max-width: 820px){
    .hero{grid-template-columns:1fr;padding:20px}
}
.kicker{
    display:inline-flex;
    align-items:center;
    gap:8px;
    color:var(--orange2);
    border:1px solid var(--line);
    border-radius:999px;
    padding:7px 12px;
    background:rgba(255,122,24,.08);
    font-size:12px;
    font-weight:900;
    margin-bottom:14px;
}
h1{
    margin:0 0 12px;
    font-size:clamp(28px,5vw,52px);
    line-height:1.02;
}
.lead{
    color:var(--muted);
    line-height:1.55;
    font-size:16px;
    max-width:62ch;
}
.meta{
    display:flex;
    flex-wrap:wrap;
    gap:10px;
    margin:20px 0;
}
.pill{
    border:1px solid rgba(255,255,255,.14);
    background:rgba(255,255,255,.055);
    border-radius:999px;
    padding:8px 12px;
    font-weight:800;
    font-size:12px;
}
.notes{
    margin-top:18px;
    border-left:3px solid var(--orange);
    padding:10px 14px;
    background:rgba(255,255,255,.045);
    border-radius:0 14px 14px 0;
}
.label{
    color:var(--orange2);
    font-weight:900;
    font-size:12px;
    text-transform:uppercase;
    letter-spacing:.08em;
}
.notes p{margin:6px 0 0;color:var(--muted);line-height:1.5}
.qrbox{
    display:flex;
    align-items:center;
    justify-content:center;
    min-height:360px;
    border-radius:22px;
    border:1px solid rgba(255,255,255,.12);
    background:rgba(255,255,255,.055);
    padding:18px;
}
.qrbox img{
    width:min(100%,330px);
    height:auto;
    background:#fff;
    padding:14px;
    border-radius:18px;
    box-shadow:0 18px 40px rgba(0,0,0,.36);
}
.mutedbox{
    color:var(--muted);
    text-align:center;
    display:grid;
    gap:10px;
}
.bigmark{
    margin:0 auto;
    width:62px;
    height:62px;
    display:grid;
    place-items:center;
    border:1px solid var(--line);
    border-radius:999px;
    color:var(--orange2);
    font-size:34px;
    font-weight:900;
}
.actions{
    display:flex;
    flex-wrap:wrap;
    gap:12px;
    margin-top:22px;
}
button,a.button{
    appearance:none;
    border:1px solid var(--line);
    background:linear-gradient(180deg, rgba(255,122,24,.24), rgba(255,122,24,.10));
    color:var(--fg);
    border-radius:14px;
    padding:12px 15px;
    font:inherit;
    font-weight:900;
    text-decoration:none;
    cursor:pointer;
}
button:hover,a.button:hover{
    border-color:rgba(255,179,106,.8);
    box-shadow:0 0 24px rgba(255,122,24,.18);
}
.footer{
    border-top:1px solid rgba(255,255,255,.10);
    padding:18px 30px;
    color:var(--muted);
    font-size:13px;
    line-height:1.45;
}
code{
    color:var(--orange2);
    overflow-wrap:anywhere;
}
</style>
</head>
<body>
<div class="wrap">
    <div class="brand"><div class="logo"></div><div>DNA-Nexus / External Shared Space Invite</div></div>
    <main class="card">
        <section class="hero">
            <div>
)HTML" +
        "                <div class=\"kicker\">One-time invite</div>\n"
        "                <h1>" + html_escape_local(state_title) + "</h1>\n"
        "                <p class=\"lead\">" + html_escape_local(state_text) + "</p>\n"
        "                <div class=\"meta\">\n"
        "                    <div class=\"pill\">Shared Space: " + workspace_name + "</div>\n"
        "                    <div class=\"pill\">Role: " + invite_role + "</div>\n"
        "                    <div class=\"pill\">Status: " + invite_status + "</div>\n"
        "                </div>\n" +
        notes_html +
R"HTML(
                <div class="actions">
)HTML" +
        "                    <button type=\"button\" data-copy=\"" + html_escape_local(page_url) + "\">Copy invite link</button>\n"
        "                    <a class=\"button\" href=\"" + html_escape_local(member_access_url) + "\">Open member access page</a>\n"
R"HTML(                </div>
            </div>
)HTML" +
        qr_html +
R"HTML(
        </section>
        <div class="footer">
            Scan the QR with DNA Connect to accept this one-time invite. After acceptance,
            use the member access page for future visits. Invite link:
)HTML" +
        " <code>" + html_escape_local(page_url) + "</code>\n" +
R"HTML(        </div>
    </main>
</div>
<script>
(function(){
    document.querySelectorAll("[data-copy]").forEach(function(btn){
        btn.addEventListener("click", async function(){
            var value = btn.getAttribute("data-copy") || "";
            try {
                await navigator.clipboard.writeText(value);
                btn.textContent = "Copied";
                setTimeout(function(){ btn.textContent = "Copy invite link"; }, 1400);
            } catch (e) {
                btn.textContent = "Copy failed";
                setTimeout(function(){ btn.textContent = "Copy invite link"; }, 1400);
            }
        });
    });
})();
</script>
</body>
</html>
)HTML";

    res.status = 200;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    res.set_header("Cache-Control", "no-store");
    res.body = html;
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

bool save_workspaces_or_500(const WorkspaceExternalInviteRouteDeps& deps,
                            httplib::Response& res) {
    if (!deps.workspaces || !deps.workspaces->save(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_save_failed"},
            {"message", "failed to save workspaces"}
        }.dump());
        return false;
    }
    return true;
}

bool parse_json_body_or_400(const WorkspaceExternalInviteRouteDeps& deps,
                            const httplib::Request& req,
                            httplib::Response& res,
                            json* out) {
    try {
        *out = json::parse(req.body.empty() ? "{}" : req.body);
    } catch (...) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return false;
    }

    if (!out->is_object()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "json object required"}
        }.dump());
        return false;
    }

    return true;
}

const WorkspaceMemberRec* find_workspace_member_const(const WorkspaceRec& w,
                                                      const std::string& fingerprint) {
    const std::string fp = trim_copy_safe(fingerprint);
    for (const auto& m : w.members) {
        if (m.fingerprint == fp) return &m;
    }
    return nullptr;
}

json workspace_member_public_json(const WorkspaceMemberRec& in_m) {
    WorkspaceMemberRec m = in_m;
    normalize_workspace_member_v1(&m);

    return json{
        {"fingerprint", m.fingerprint},
        {"role", m.role},
        {"status", m.status},
        {"member_kind", m.member_kind},
        {"display_name", m.display_name},
        {"name", m.display_name},
        {"added_at", m.added_at},
        {"added_by", m.added_by},
        {"responded_at", m.responded_at},
        {"responded_by", m.responded_by}
    };
}

bool workspace_route_role_assignable(const std::string& role) {
    const std::string r = normalize_workspace_role_copy(role);
    return r == "viewer" || r == "editor";
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
    // GET /api/v4/workspaces/members?workspace_id=ws_xxx
    //
    // Any enabled member can view the member list. Only owners can mutate it.
    srv.Get("/api/v4/workspaces/members",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!deps.reply_json || !deps.workspaces) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "workspace member routes not fully configured"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(req.get_param_value("workspace_id"));
        if (!is_valid_workspace_id(workspace_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id"}
            }.dump());
            return;
        }

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

        auto actor_member = workspace_enabled_member_for_actor(*wopt, actor_fp);
        if (!actor_member.has_value()) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace member required"}
            }.dump());
            return;
        }

        json members = json::array();
        for (const auto& m : wopt->members) {
            members.push_back(workspace_member_public_json(m));
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace", {
                {"workspace_id", wopt->workspace_id},
                {"name", wopt->name},
                {"kind", wopt->kind},
                {"status", wopt->status}
            }},
            {"members", members}
        }.dump());
    });

    // POST /api/v4/workspaces/members/invite
    srv.Post("/api/v4/workspaces/members/invite",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) return;

        json j;
        if (!parse_json_body_or_400(deps, req, res, &j)) return;

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string target_fp = trim_copy_safe(j.value("fingerprint", ""));
        const std::string role = normalize_workspace_role_copy(j.value("role", "viewer"));

        if (!is_valid_workspace_id(workspace_id) || target_fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id/fingerprint"}
            }.dump());
            return;
        }

        if (!workspace_route_role_assignable(role)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "role must be viewer or editor"}
            }.dump());
            return;
        }

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

        if (!actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        WorkspaceMemberRec m;
        if (const auto* existing = find_workspace_member_const(*wopt, target_fp)) {
            if (existing->role == "owner") {
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "cannot_modify_owner"},
                    {"message", "cannot modify workspace owner through member invite"}
                }.dump());
                return;
            }
            m = *existing;
        } else {
            m.fingerprint = target_fp;
            m.member_kind = "user";
            m.added_at = deps.now_iso_utc ? deps.now_iso_utc() : "";
            m.added_by = actor_fp;
        }

        m.role = role;
        m.status = "enabled";
        m.responded_at = deps.now_iso_utc ? deps.now_iso_utc() : "";
        m.responded_by = actor_fp;
        normalize_workspace_member_v1(&m);

        if (!deps.workspaces->add_or_update_member(workspace_id, m)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "member_update_failed"},
                {"message", "failed to add workspace member"}
            }.dump());
            return;
        }

        if (!save_workspaces_or_500(deps, res)) return;

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"member", workspace_member_public_json(m)}
        }.dump());
    });

    // POST /api/v4/workspaces/members/set_role
    srv.Post("/api/v4/workspaces/members/set_role",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) return;

        json j;
        if (!parse_json_body_or_400(deps, req, res, &j)) return;

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string target_fp = trim_copy_safe(j.value("fingerprint", ""));
        const std::string role = normalize_workspace_role_copy(j.value("role", "viewer"));

        if (!is_valid_workspace_id(workspace_id) || target_fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id/fingerprint"}
            }.dump());
            return;
        }

        if (!workspace_route_role_assignable(role)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "role must be viewer or editor"}
            }.dump());
            return;
        }

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

        if (!actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        const auto* target = find_workspace_member_const(*wopt, target_fp);
        if (!target) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "member_not_found"},
                {"message", "workspace member not found"}
            }.dump());
            return;
        }

        if (target->role == "owner") {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "cannot_modify_owner"},
                {"message", "cannot change workspace owner role here"}
            }.dump());
            return;
        }

        if (!deps.workspaces->set_member_role(workspace_id, target_fp, role)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "role_update_failed"},
                {"message", "failed to update workspace member role"}
            }.dump());
            return;
        }

        if (!save_workspaces_or_500(deps, res)) return;

        deps.reply_json(res, 200, json{{"ok", true}}.dump());
    });

    // POST /api/v4/workspaces/members/remove
    srv.Post("/api/v4/workspaces/members/remove",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) return;

        json j;
        if (!parse_json_body_or_400(deps, req, res, &j)) return;

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string target_fp = trim_copy_safe(j.value("fingerprint", ""));

        if (!is_valid_workspace_id(workspace_id) || target_fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id/fingerprint"}
            }.dump());
            return;
        }

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

        if (!actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        const auto* target = find_workspace_member_const(*wopt, target_fp);
        if (!target) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "member_not_found"},
                {"message", "workspace member not found"}
            }.dump());
            return;
        }

        if (target->role == "owner") {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "cannot_remove_owner"},
                {"message", "cannot remove workspace owner"}
            }.dump());
            return;
        }

        if (!deps.workspaces->remove_member(workspace_id, target_fp)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "member_remove_failed"},
                {"message", "failed to remove workspace member"}
            }.dump());
            return;
        }

        if (!save_workspaces_or_500(deps, res)) return;

        deps.reply_json(res, 200, json{{"ok", true}}.dump());
    });

    // POST /api/v4/workspaces/delete
    //
    // Soft-delete for owner-created Shared Spaces. Files are preserved on disk.
    srv.Post("/api/v4/workspaces/delete",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) return;

        json j;
        if (!parse_json_body_or_400(deps, req, res, &j)) return;

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));

        if (!is_valid_workspace_id(workspace_id)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing or invalid workspace_id"}
            }.dump());
            return;
        }

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

        if (wopt->kind != "personal") {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "only personal Shared Spaces can be deleted here"}
            }.dump());
            return;
        }

        if (!actor_is_enabled_workspace_owner(*wopt, actor_fp)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace owner required"}
            }.dump());
            return;
        }

        WorkspaceRec w = *wopt;
        w.status = "disabled";

        if (!deps.workspaces->upsert(w)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspace_delete_failed"},
                {"message", "failed to disable workspace"}
            }.dump());
            return;
        }

        if (!save_workspaces_or_500(deps, res)) return;

        deps.reply_json(res, 200, json{{"ok", true}}.dump());
    });
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

        if (request_wants_html_local(req)) {
            if (!deps.workspaces) {
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "workspaces registry not configured"}
                }.dump());
                return;
            }

            if (!reload_workspaces_or_500(deps, res)) return;

            auto wopt = deps.workspaces->get(inv->workspace_id);
            if (!wopt.has_value()) {
                deps.reply_json(res, 404, json{
                    {"ok", false},
                    {"error", "workspace_not_found"},
                    {"message", "workspace not found"}
                }.dump());
                return;
            }

            reply_external_invite_landing_html_local(deps, res, *inv, *wopt);
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
