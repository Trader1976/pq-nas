#pragma once

#include "httplib.h"
#include "users_registry.h"

#include <filesystem>
#include <functional>
#include <string>

namespace pqnas {

struct ActivityRoutesDeps {
    UsersRegistry* users = nullptr;

    const unsigned char* cookie_key = nullptr;

    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       UsersRegistry*,
                       std::string*,
                       std::string*)> require_user_auth_users_actor;

    std::function<void(httplib::Response&, int, const std::string&)> reply_json;

    std::function<std::filesystem::path(UsersRegistry&, const std::string&)> user_dir_for_fp;
};

void register_activity_routes(httplib::Server& srv, const ActivityRoutesDeps& deps);

} // namespace pqnas
