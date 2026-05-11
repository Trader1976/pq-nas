#pragma once

#include "httplib.h"
#include "users_registry.h"
#include "workspaces.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace pqnas {

struct FileLockRoutesDeps {
    UsersRegistry* users = nullptr;
    WorkspacesRegistry* workspaces = nullptr;

    std::string users_path;
    std::string workspaces_path;
    std::filesystem::path locks_db_path;

    const unsigned char* cookie_key = nullptr;

    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       UsersRegistry*,
                       std::string*,
                       std::string*)> require_user_auth_users_actor;

    std::function<void(httplib::Response&, int, const std::string&)> reply_json;
    std::function<std::int64_t()> now_epoch_sec;

    std::function<std::filesystem::path(const std::string& fp_hex)> user_dir_for_fp;
    std::function<std::string(const std::string& fp_hex)> display_name_for_fp;
};

void register_file_lock_routes(httplib::Server& srv,
                               const FileLockRoutesDeps& deps);

} // namespace pqnas
