#pragma once

#include "httplib.h"
#include "users_registry.h"

#include <filesystem>
#include <functional>
#include <string>

namespace pqnas {

struct PeopleRoutesDeps {
    UsersRegistry* users = nullptr;
    const unsigned char* cookie_key = nullptr;

    std::filesystem::path people_db_path;

    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       UsersRegistry*,
                       std::string*,
                       std::string*)> require_user_auth_users_actor;

    std::function<void(httplib::Response&, int, const std::string&)> reply_json;
};

void register_people_routes(httplib::Server& srv, const PeopleRoutesDeps& deps);

} // namespace pqnas
