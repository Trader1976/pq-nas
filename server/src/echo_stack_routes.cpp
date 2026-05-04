#include "echo_stack_routes.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <sstream>

using json = nlohmann::json;

namespace pqnas {
namespace {

static std::string lower_ascii_local(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool starts_with_local(const std::string& s, const std::string& pfx) {
    return s.rfind(pfx, 0) == 0;
}

static bool is_http_url_local(const std::string& url) {
    const std::string low = lower_ascii_local(url);
    return starts_with_local(low, "https://") || starts_with_local(low, "http://");
}

static std::string cap_string_local(std::string s, std::size_t max_bytes) {
    if (s.size() > max_bytes) s.resize(max_bytes);
    return s;
}

static std::string json_string_local(const json& j,
                                     const char* key,
                                     const std::string& defv,
                                     std::size_t cap_bytes) {
    if (!j.contains(key) || !j[key].is_string()) return defv;
    return cap_string_local(j[key].get<std::string>(), cap_bytes);
}

static bool json_bool_local(const json& j, const char* key, bool defv) {
    if (!j.contains(key)) return defv;
    if (j[key].is_boolean()) return j[key].get<bool>();
    if (j[key].is_number_integer()) return j[key].get<int>() != 0;
    return defv;
}

static std::size_t parse_limit_local(const httplib::Request& req,
                                     std::size_t defv,
                                     std::size_t maxv) {
    std::size_t v = defv;
    if (req.has_param("limit")) {
        try {
            long long n = std::stoll(req.get_param_value("limit"));
            if (n > 0) v = static_cast<std::size_t>(n);
        } catch (...) {}
    }
    if (v < 1) v = 1;
    if (v > maxv) v = maxv;
    return v;
}

static bool origin_allowed_local(const EchoStackRoutesDeps& deps,
                                 const httplib::Request& req) {
    if (!deps.origin || deps.origin->empty()) return true;
    const std::string origin = *deps.origin;

    if (req.has_header("Origin")) {
        return req.get_header_value("Origin") == origin;
    }

    if (req.has_header("Referer")) {
        const std::string ref = req.get_header_value("Referer");
        return ref == origin || starts_with_local(ref, origin + "/");
    }

    // Preserve compatibility with same-origin tools/curl. Browser requests
    // normally carry Origin/Referer on mutating calls.
    return true;
}

static json item_json_local(const EchoStackItemRec& r) {
    return json{
        {"id", r.id},
        {"url", r.url},
        {"final_url", r.final_url},
        {"title", r.title},
        {"description", r.description},
        {"site_name", r.site_name},
        {"favicon_url", r.favicon_url},
        {"preview_image_url", r.preview_image_url},
        {"tags_text", r.tags_text},
        {"collection", r.collection},
        {"notes", r.notes},
        {"read_state", r.read_state},
        {"favorite", r.favorite},
        {"archive_status", r.archive_status},
        {"archive_error", r.archive_error},
        {"archive_rel_dir", r.archive_rel_dir},
        {"archive_bytes", r.archive_bytes},
        {"created_epoch", r.created_epoch},
        {"updated_epoch", r.updated_epoch},
        {"archived_epoch", r.archived_epoch}
    };
}

static void audit_local(const EchoStackRoutesDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& f) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, f);
}

static bool require_actor_local(const EchoStackRoutesDeps& deps,
                                const httplib::Request& req,
                                httplib::Response& res,
                                std::string* fp,
                                std::string* role) {
    if (!deps.require_user_auth_users_actor ||
        !deps.users ||
        !deps.cookie_key ||
        !deps.echo_index ||
        !deps.reply_json) {
        if (deps.reply_json) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "Echo Stack route dependencies not configured"}
            }.dump());
        }
        return false;
    }

    return deps.require_user_auth_users_actor(
        req, res, deps.cookie_key, deps.users, fp, role
    );
}

static json parse_body_json_local(const httplib::Request& req) {
    try {
        return json::parse(req.body);
    } catch (...) {
        return json();
    }
}

static EchoStackItemRec mutable_from_json_local(const json& j,
                                                const EchoStackItemRec& base,
                                                std::int64_t now) {
    EchoStackItemRec r = base;

    if (j.contains("url")) r.url = json_string_local(j, "url", r.url, 4096);
    if (j.contains("final_url")) r.final_url = json_string_local(j, "final_url", r.final_url, 4096);
    if (j.contains("title")) r.title = json_string_local(j, "title", r.title, 512);
    if (j.contains("description")) r.description = json_string_local(j, "description", r.description, 2000);
    if (j.contains("site_name")) r.site_name = json_string_local(j, "site_name", r.site_name, 256);
    if (j.contains("favicon_url")) r.favicon_url = json_string_local(j, "favicon_url", r.favicon_url, 4096);
    if (j.contains("preview_image_url")) r.preview_image_url = json_string_local(j, "preview_image_url", r.preview_image_url, 4096);
    if (j.contains("tags_text")) r.tags_text = json_string_local(j, "tags_text", r.tags_text, 1000);
    if (j.contains("collection")) r.collection = json_string_local(j, "collection", r.collection, 256);
    if (j.contains("notes")) r.notes = json_string_local(j, "notes", r.notes, 8000);

    if (j.contains("read_state")) {
        std::string rs = lower_ascii_local(json_string_local(j, "read_state", r.read_state, 32));
        if (rs != "read" && rs != "unread") rs = "unread";
        r.read_state = rs;
    }

    if (j.contains("favorite")) r.favorite = json_bool_local(j, "favorite", r.favorite);

    r.updated_epoch = now;
    return r;
}

} // namespace

void register_echo_stack_routes(httplib::Server& srv, const EchoStackRoutesDeps& deps) {
    srv.Get("/api/v4/echostack/items", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::size_t limit = parse_limit_local(req, 200, 500);
        const std::string q = req.has_param("q")
            ? cap_string_local(req.get_param_value("q"), 256)
            : std::string();

        std::string err;
        const auto rows = deps.echo_index->list_owner(fp, q, limit, &err);
        if (!err.empty()) {
            audit_local(deps, "v4.echostack_list_fail", "fail", {
                {"actor_fp", fp},
                {"reason", err}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "list_failed"},
                {"message", "failed to list Echo Stack items"}
            }.dump());
            return;
        }

        json items = json::array();
        for (const auto& r : rows) items.push_back(item_json_local(r));

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"items", items}
        }.dump());
    });

    srv.Get("/api/v4/echostack/items/get", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || id.size() > 160) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string err;
        auto rec = deps.echo_index->get_owner_item(fp, id, &err);
        if (!rec.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(*rec)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/create", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            audit_local(deps, "v4.echostack_create_fail", "fail", {
                {"actor_fp", fp},
                {"reason", "origin_mismatch"}
            });
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string url = json_string_local(body, "url", "", 4096);
        if (url.empty() || !is_http_url_local(url)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_url"},
                {"message", "url must start with http:// or https://"}
            }.dump());
            return;
        }

        const std::int64_t now = deps.now_epoch ? deps.now_epoch() : 0;

        EchoStackItemRec r;
        r.id = "es_" + (deps.random_b64url ? deps.random_b64url(18) : std::to_string(now));
        r.owner_fp = fp;
        r.url = url;
        r.final_url = json_string_local(body, "final_url", "", 4096);
        r.title = json_string_local(body, "title", url, 512);
        r.description = json_string_local(body, "description", "", 2000);
        r.site_name = json_string_local(body, "site_name", "", 256);
        r.favicon_url = json_string_local(body, "favicon_url", "", 4096);
        r.preview_image_url = json_string_local(body, "preview_image_url", "", 4096);
        r.tags_text = json_string_local(body, "tags_text", "", 1000);
        r.collection = json_string_local(body, "collection", "", 256);
        r.notes = json_string_local(body, "notes", "", 8000);
        r.read_state = lower_ascii_local(json_string_local(body, "read_state", "unread", 32));
        if (r.read_state != "read" && r.read_state != "unread") r.read_state = "unread";
        r.favorite = json_bool_local(body, "favorite", false);
        r.archive_status = "none";
        r.created_epoch = now;
        r.updated_epoch = now;

        std::string err;
        if (!deps.echo_index->insert(r, &err)) {
            audit_local(deps, "v4.echostack_create_fail", "fail", {
                {"actor_fp", fp},
                {"reason", err}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "create_failed"},
                {"message", "failed to create Echo Stack item"}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_create_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", r.id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(r)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/update", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string id = json_string_local(body, "id", "", 160);
        if (id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string err;
        auto existing = deps.echo_index->get_owner_item(fp, id, &err);
        if (!existing.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        const std::int64_t now = deps.now_epoch ? deps.now_epoch() : existing->updated_epoch;
        EchoStackItemRec updated = mutable_from_json_local(body, *existing, now);

        if (updated.url.empty() || !is_http_url_local(updated.url)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_url"},
                {"message", "url must start with http:// or https://"}
            }.dump());
            return;
        }

        err.clear();
        if (!deps.echo_index->update_mutable(updated, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "update_failed"},
                {"message", err.empty() ? "failed to update Echo Stack item" : err}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_update_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(updated)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/delete", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        const std::string id = body.is_object() ? json_string_local(body, "id", "", 160) : "";

        if (id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string err;
        if (!deps.echo_index->delete_owner_item(fp, id, &err)) {
            deps.reply_json(res, err == "not_found" ? 404 : 500, json{
                {"ok", false},
                {"error", err == "not_found" ? "not_found" : "delete_failed"},
                {"message", err.empty() ? "failed to delete Echo Stack item" : err}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_delete_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/archive", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        deps.reply_json(res, 501, json{
            {"ok", false},
            {"error", "not_implemented"},
            {"message", "Echo Stack archiving is reserved for the quota-safe archive patch"}
        }.dump());
    });
}

} // namespace pqnas
