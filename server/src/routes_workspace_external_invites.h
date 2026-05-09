#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

#include <httplib.h>

#include "users_registry.h"
#include "workspaces.h"
#include "workspace_external_invites.h"

namespace pqnas {

using WorkspaceExternalInviteReplyJsonFn =
    std::function<void(httplib::Response&, int, const std::string&)>;

using WorkspaceExternalInviteRequireUserAuthFn =
    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       pqnas::UsersRegistry*,
                       std::string*,
                       std::string*)>;

using WorkspaceExternalInviteAuditEmitFn =
    std::function<void(const std::string& event,
                       const std::string& outcome,
                       const std::map<std::string, std::string>& fields)>;

struct WorkspaceExternalInviteRouteDeps {
    pqnas::UsersRegistry* users = nullptr;
    pqnas::WorkspacesRegistry* workspaces = nullptr;
    pqnas::WorkspaceExternalInvitesRegistry* external_invites = nullptr;

    std::string users_path;
    std::string workspaces_path;
    std::string external_invites_path;

    const std::string* origin = nullptr;
    const std::string* app = nullptr;
    const unsigned char* cookie_key = nullptr;

    WorkspaceExternalInviteReplyJsonFn reply_json;
    WorkspaceExternalInviteRequireUserAuthFn require_user_auth_users_actor;
    WorkspaceExternalInviteAuditEmitFn audit_emit;

    std::function<std::int64_t()> now_epoch_sec;
    std::function<std::string()> now_iso_utc;

    std::function<std::string(int)> random_b64url;
    std::function<std::string(const std::string&)> url_encode;

    std::function<std::string(const std::string& sid,
                              const std::string& chal,
                              const std::string& nonce,
                              long issued_at,
                              long expires_at)> build_req_payload_canonical;

    std::function<std::string(const std::string& payload)> sign_req_token;
    std::function<std::string(const std::string& st_token)> st_hash_b64_from_st;
    std::function<std::string(const std::string& text, int scale, int border)> qr_svg_from_text;
};

void register_workspace_external_invite_routes(
    httplib::Server& srv,
    const WorkspaceExternalInviteRouteDeps& deps);

} // namespace pqnas
