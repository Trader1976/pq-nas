#pragma once

#include <functional>
#include <map>
#include <string>

#include <httplib.h>

#include "users_registry.h"
#include "workspaces.h"

namespace pqnas {

    using ReplyJsonFn =
        std::function<void(httplib::Response&, int, const std::string&)>;

    using RequireAdminCookieUsersActorFn =
        std::function<bool(const httplib::Request&,
                           httplib::Response&,
                           const unsigned char*,
                           const std::string&,
                           pqnas::UsersRegistry*,
                           std::string*)>;

    using AuditEmitFn =
        std::function<void(const std::string& event,
                           const std::string& outcome,
                           const std::map<std::string, std::string>& fields)>;

    using NowIsoUtcFn =
        std::function<std::string()>;

    struct AdminWorkspaceRouteDeps {
        pqnas::UsersRegistry* users = nullptr;
        pqnas::WorkspacesRegistry* workspaces = nullptr;

        std::string users_path;
        std::string workspaces_path;
        const std::string* origin = nullptr;
        const unsigned char* cookie_key = nullptr;

        ReplyJsonFn reply_json;
        RequireAdminCookieUsersActorFn require_admin_cookie_users_actor;
        AuditEmitFn audit_emit;
        NowIsoUtcFn now_iso_utc;
    };

    void register_admin_workspace_routes(httplib::Server& srv,
                                         const AdminWorkspaceRouteDeps& deps);

} // namespace pqnas