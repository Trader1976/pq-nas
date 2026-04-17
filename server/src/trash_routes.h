#pragma once

#include "trash_index.h"
#include "trash_service.h"
#include "users_registry.h"
#include "workspaces.h"
#include "httplib.h"

#include <filesystem>
#include <functional>
#include <map>
#include <string>

namespace pqnas {

    struct TrashRoutesDeps {
        UsersRegistry* users = nullptr;
        const std::string* users_path = nullptr;

        WorkspacesRegistry* workspaces = nullptr;
        const std::string* workspaces_path = nullptr;

        TrashIndex* trash_index = nullptr;
        TrashService* trash_service = nullptr;

        const unsigned char* cookie_key = nullptr;

        std::function<bool(const httplib::Request&,
                           httplib::Response&,
                           const unsigned char*,
                           UsersRegistry*,
                           std::string*,
                           std::string*)> require_user_auth_users_actor;

        std::function<void(httplib::Response&, int, const std::string&)> reply_json;

        std::function<void(const std::string&,
                           const std::string&,
                           const std::map<std::string, std::string>&)> audit_emit;

        std::function<std::filesystem::path(UsersRegistry&, const std::string&)> user_dir_for_fp;

        std::function<std::filesystem::path(const std::string&, const WorkspaceRec&)>
            workspace_dir_for_default_pool_only;
    };

    void register_trash_routes(httplib::Server& srv, const TrashRoutesDeps& deps);

} // namespace pqnas