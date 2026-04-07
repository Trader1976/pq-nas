#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

#include <httplib.h>

#include "users_registry.h"
#include "workspaces.h"

namespace pqnas {

    using ReplyJsonFn =
        std::function<void(httplib::Response&, int, const std::string&)>;

    using RequireUserAuthUsersActorFn =
        std::function<bool(const httplib::Request&,
                           httplib::Response&,
                           const unsigned char*,
                           pqnas::UsersRegistry*,
                           std::string*,
                           std::string*)>;

    using AuditEmitFn =
        std::function<void(const std::string& event,
                           const std::string& outcome,
                           const std::map<std::string, std::string>& fields)>;

    using NowEpochSecFn =
        std::function<std::int64_t()>;

    struct WorkspaceFileRouteDeps {
        pqnas::UsersRegistry* users = nullptr;
        pqnas::WorkspacesRegistry* workspaces = nullptr;

        std::string users_path;
        std::string workspaces_path;

        const unsigned char* cookie_key = nullptr;

        std::uint64_t transport_max_upload_bytes = 0;
        std::uint64_t payload_max_upload_bytes = 0;

        ReplyJsonFn reply_json;
        RequireUserAuthUsersActorFn require_user_auth_users_actor;
        AuditEmitFn audit_emit;
        NowEpochSecFn now_epoch_sec;
    };

    void register_workspace_file_routes(httplib::Server& srv,
                                        const WorkspaceFileRouteDeps& deps);

} // namespace pqnas