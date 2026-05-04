#pragma once

#include "echo_stack_index.h"
#include "httplib.h"
#include "users_registry.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>

namespace pqnas {

struct EchoStackRoutesDeps {
    UsersRegistry* users = nullptr;
    EchoStackIndex* echo_index = nullptr;

    const unsigned char* cookie_key = nullptr;
    const std::string* origin = nullptr;

    std::function<std::filesystem::path(UsersRegistry&, const std::string&)> user_dir_for_fp;
    std::function<std::string(std::size_t)> random_b64url;
    std::function<std::int64_t()> now_epoch;

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
};

void register_echo_stack_routes(httplib::Server& srv, const EchoStackRoutesDeps& deps);

} // namespace pqnas
