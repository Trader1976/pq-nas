#include "gallery_albums_routes.h"

#include "gallery_albums.h"
#include "users_registry.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <ctime>
namespace pqnas {

namespace {

using json = nlohmann::json;

static std::string trim_copy_album_local(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

static std::string json_string_or_album_local(const json& j,
                                              const char* key,
                                              const std::string& def = "") {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return def;
    return it->get<std::string>();
}

static std::int64_t now_epoch_album_local() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

    static json album_to_json_local(const pqnas::GalleryAlbumRec& r) {
    return json{
            {"album_id", r.album_id},
            {"scope_type", r.scope_type},
            {"scope_id", r.scope_id},
            {"name", r.name},
            {"description", r.description},
            {"cover_path", r.cover_logical_rel_path},
            {"cover_logical_rel_path", r.cover_logical_rel_path},
            {"created_epoch", r.created_epoch},
            {"updated_epoch", r.updated_epoch},
            {"item_count", r.item_count}
    };
}

static json album_item_to_json_local(const GalleryAlbumItemRec& r) {
    return json{
        {"album_id", r.album_id},
        {"scope_type", r.scope_type},
        {"scope_id", r.scope_id},
        {"logical_rel_path", r.logical_rel_path},
        {"sort_order", r.sort_order},
        {"added_epoch", r.added_epoch}
    };
}

static std::string random_album_id_local() {
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out = "alb_";
    out.resize(4 + 24);

    std::uint64_t x =
        static_cast<std::uint64_t>(std::time(nullptr)) ^
        (static_cast<std::uint64_t>(::getpid()) << 32);

    for (std::size_t i = 4; i < out.size(); ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out[i] = kHex[x & 0x0F];
    }

    return out;
}

static bool require_gallery_album_deps_local(const GalleryAlbumRoutesDeps& deps,
                                             httplib::Response& res) {
    if (!deps.users || !deps.albums || !deps.require_user_auth_users_actor || !deps.reply_json) {
        res.status = 500;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"server_error","message":"gallery album routes not configured"})";
        return false;
    }
    return true;
}

} // namespace

void register_gallery_album_routes(httplib::Server& srv,
                                   const GalleryAlbumRoutesDeps& deps) {
    using json = nlohmann::json;
    // POST /api/v4/gallery/albums/remove_items
    srv.Post("/api/v4/gallery/albums/remove_items",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string album_id =
            trim_copy_album_local(json_string_or_album_local(in, "album_id"));

        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "album_id is required"}
            }.dump());
            return;
        }

        std::vector<std::string> paths;
        if (in.contains("paths") && in["paths"].is_array()) {
            for (const auto& v : in["paths"]) {
                if (!v.is_string()) continue;
                const std::string p = trim_copy_album_local(v.get<std::string>());
                if (!p.empty()) paths.push_back(p);
            }
        }

        if (paths.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "paths is required"}
            }.dump());
            return;
        }

        std::string err;
        if (!deps.albums->remove_items("user", fp_hex, album_id, paths, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to remove album items"},
                {"detail", err}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album_id", album_id},
            {"removed", paths.size()}
        }.dump());
    });
    // POST /api/v4/gallery/albums/set_cover
    srv.Post("/api/v4/gallery/albums/set_cover",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string album_id =
            trim_copy_album_local(json_string_or_album_local(in, "album_id"));

        std::string path =
            trim_copy_album_local(json_string_or_album_local(in, "path"));

        if (path.empty()) {
            path = trim_copy_album_local(json_string_or_album_local(in, "logical_rel_path"));
        }

        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "album_id is required"}
            }.dump());
            return;
        }

        if (path.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "path is required"}
            }.dump());
            return;
        }

        std::string err;
        if (!deps.albums->set_album_cover(
                "user", fp_hex, album_id, path, now_epoch_album_local(), &err)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "set_cover_failed"},
                {"message", err.empty() ? "failed to set album cover" : err}
            }.dump());
            return;
        }

        std::string get_err;
        auto rec = deps.albums->get_album("user", fp_hex, album_id, &get_err);
        if (!rec.has_value()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "cover was set but album could not be reloaded"}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album", album_to_json_local(*rec)}
        }.dump());
    });

    // POST /api/v4/gallery/albums/update
    srv.Post("/api/v4/gallery/albums/update",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string album_id =
            trim_copy_album_local(json_string_or_album_local(in, "album_id"));

        std::string name = trim_copy_album_local(json_string_or_album_local(in, "name"));
        if (name.empty()) {
            name = trim_copy_album_local(json_string_or_album_local(in, "title"));
        }

        const std::string description =
            trim_copy_album_local(json_string_or_album_local(in, "description"));

        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "album_id is required"}
            }.dump());
            return;
        }

        if (name.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "album name is required"}
            }.dump());
            return;
        }

        const std::int64_t now_epoch = static_cast<std::int64_t>(std::time(nullptr));

        std::string err;
        if (!deps.albums->rename_album(
                "user", fp_hex, album_id, name, description, now_epoch, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to update album"},
                {"detail", err}
            }.dump());
            return;
        }

        std::string get_err;
        auto rec = deps.albums->get_album("user", fp_hex, album_id, &get_err);
        if (!rec.has_value()) {
            deps.reply_json(res, 200, json{
                {"ok", true},
                {"album_id", album_id}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album", album_to_json_local(*rec)}
        }.dump());
    });
    // GET /api/v4/gallery/albums/list
    srv.Get("/api/v4/gallery/albums/list",
            [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_gallery_album_deps_local(deps, res)) return;

        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        (void)role;
        res.set_header("Cache-Control", "no-store");

        std::string err;
        const auto albums = deps.albums->list_albums("user", fp_hex, 500, &err);
        if (!err.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list albums"},
                {"detail", err}
            }.dump());
            return;
        }

        json arr = json::array();
        for (const auto& a : albums) {
            arr.push_back(album_to_json_local(a));
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"albums", arr}
        }.dump());
    });

    // POST /api/v4/gallery/albums/create
    srv.Post("/api/v4/gallery/albums/create",
             [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_gallery_album_deps_local(deps, res)) return;

        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        (void)role;
        res.set_header("Cache-Control", "no-store");

        json in = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid JSON"}
            }.dump());
            return;
        }

         std::string name = trim_copy_album_local(json_string_or_album_local(in, "name"));
         if (name.empty()) {
             // Backward-compatible input name in case older UI code sends "title".
             name = trim_copy_album_local(json_string_or_album_local(in, "title"));
         }

         const std::string description =
             trim_copy_album_local(json_string_or_album_local(in, "description"));

                 if (name.empty()) {
                     deps.reply_json(res, 400, json{
                         {"ok", false},
                         {"error", "bad_request"},
                         {"message", "album name is required"}
                     }.dump());
                     return;
                 }

        const std::int64_t now = now_epoch_album_local();

        GalleryAlbumRec rec;
        rec.album_id = random_album_id_local();
        rec.scope_type = "user";
        rec.scope_id = fp_hex;
        rec.name = name;
        rec.description = description;
        rec.created_epoch = now;
        rec.updated_epoch = now;

        std::string err;
        if (!deps.albums->create_album(rec, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create album"},
                {"detail", err}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album", album_to_json_local(rec)}
        }.dump());
    });

    // POST /api/v4/gallery/albums/add_items
    srv.Post("/api/v4/gallery/albums/add_items",
             [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_gallery_album_deps_local(deps, res)) return;

        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        (void)role;
        res.set_header("Cache-Control", "no-store");

        json in = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid JSON"}
            }.dump());
            return;
        }

        const std::string album_id = trim_copy_album_local(json_string_or_album_local(in, "album_id"));
        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing album_id"}
            }.dump());
            return;
        }

        std::vector<std::string> paths;
        auto it = in.find("paths");
        if (it != in.end() && it->is_array()) {
            for (const auto& v : *it) {
                if (!v.is_string()) continue;
                const std::string p = trim_copy_album_local(v.get<std::string>());
                if (!p.empty()) paths.push_back(p);
            }
        }

        if (paths.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "no paths provided"}
            }.dump());
            return;
        }

        std::string err;
        if (!deps.albums->add_items("user", fp_hex, album_id, paths, now_epoch_album_local(), &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to add items to album"},
                {"detail", err}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album_id", album_id},
            {"added", paths.size()}
        }.dump());
    });
    // POST /api/v4/gallery/albums/delete
    srv.Post("/api/v4/gallery/albums/delete",
             [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.users || !deps.albums || !deps.require_user_auth_users_actor || !deps.reply_json) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "gallery album routes not configured"}
            }.dump());
            return;
        }

        std::string fp_hex;
        std::string role;

        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        json in = json::object();
        try {
            if (!req.body.empty()) {
                in = json::parse(req.body);
            }
        } catch (...) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            }.dump());
            return;
        }

        const std::string album_id =
            trim_copy_album_local(json_string_or_album_local(in, "album_id"));

        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "album_id is required"}
            }.dump());
            return;
        }

        std::string err;
        if (!deps.albums->delete_album("user", fp_hex, album_id, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "delete_failed"},
                {"message", err.empty() ? "failed to delete album" : err}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album_id", album_id}
        }.dump());
    });

    // GET /api/v4/gallery/albums/items?album_id=...
    srv.Get("/api/v4/gallery/albums/items",
            [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_gallery_album_deps_local(deps, res)) return;

        std::string fp_hex, role;
        if (!deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &fp_hex, &role)) {
            return;
        }

        (void)role;
        res.set_header("Cache-Control", "no-store");

        const std::string album_id =
            req.has_param("album_id") ? trim_copy_album_local(req.get_param_value("album_id")) : "";

        if (album_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing album_id"}
            }.dump());
            return;
        }

        std::string err;
        const auto items = deps.albums->list_items("user", fp_hex, album_id, 5000, &err);
        if (!err.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list album items"},
                {"detail", err}
            }.dump());
            return;
        }

        json arr = json::array();
        for (const auto& item : items) {
            arr.push_back(album_item_to_json_local(item));
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"album_id", album_id},
            {"items", arr}
        }.dump());
    });
}

} // namespace pqnas