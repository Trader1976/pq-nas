#include "routes_activity.h"

#include "activity_log.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas {

namespace {

using json = nlohmann::json;

void reply_json_local(const ActivityRoutesDeps& deps,
                      httplib::Response& res,
                      int code,
                      const json& body) {
    if (deps.reply_json) {
        deps.reply_json(res, code, body.dump());
        return;
    }

    res.status = code;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

int parse_limit_local(const httplib::Request& req, int fallback) {
    if (!req.has_param("limit")) return fallback;

    try {
        const int n = std::stoi(req.get_param_value("limit"));
        return std::clamp(n, 1, 500);
    } catch (...) {
        return fallback;
    }
}

} // namespace

void register_activity_routes(httplib::Server& srv, const ActivityRoutesDeps& deps) {
    srv.Get("/api/v4/activity/list", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.users || !deps.cookie_key || !deps.require_user_auth_users_actor ||
            !deps.reply_json || !deps.user_dir_for_fp) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "activity route dependencies missing"}
            });
            return;
        }

        std::string actor_fp;
        std::string actor_role;
        if (!deps.require_user_auth_users_actor(
                req,
                res,
                deps.cookie_key,
                deps.users,
                &actor_fp,
                &actor_role)) {
            return;
        }

        const int limit = parse_limit_local(req, 100);

        const std::filesystem::path user_root = deps.user_dir_for_fp(*deps.users, actor_fp);
        if (user_root.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "could not resolve user storage root"}
            });
            return;
        }

        // Do not accidentally create a brand-new user root during a read-only list call.
        // Existing allocated users will have their .pqnas_activity directory created by
        // list_user_activity() if this is their first activity request.
        std::error_code ec;
        const bool root_exists = std::filesystem::exists(user_root, ec);
        const bool root_is_dir = root_exists && std::filesystem::is_directory(user_root, ec);

        if (!root_exists || !root_is_dir) {
            reply_json_local(deps, res, 200, json{
                {"ok", true},
                {"events", json::array()},
                {"count", 0}
            });
            return;
        }

        std::string err;
        const auto rows = activity::list_user_activity(user_root, limit, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list activity"}
            });
            return;
        }

        json events = json::array();
        for (const auto& row : rows) {
            json item = activity::activity_row_to_json(row);

            // This is a user-facing endpoint. Avoid exposing full internal identity
            // fingerprints even though the caller owns this activity store.
            item.erase("owner_user_id");
            item.erase("actor_user_id");

            // Keep internal scope IDs in SQLite for future linking, but do not expose
            // raw user/workspace identifiers through this user-facing endpoint.
            item.erase("scope_id");

            if (item.contains("details") && item["details"].is_object()) {
                item["details"].erase("scope_id");
                item["details"].erase("workspace_id");
                item["details"].erase("actor_fp");
                item["details"].erase("owner_user_id");
                item["details"].erase("actor_user_id");
            }

            events.push_back(std::move(item));
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"events", events},
            {"count", events.size()}
        });
    });
}

} // namespace pqnas
