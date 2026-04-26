#pragma once

#include <functional>
#include <string>

#include <httplib.h>
#include <nlohmann/json.hpp>

namespace pqnas {

    class UsersRegistry;
    class GalleryAlbumsIndex;

    struct GalleryAlbumRoutesDeps {
        UsersRegistry* users = nullptr;
        GalleryAlbumsIndex* albums = nullptr;
        const unsigned char* cookie_key = nullptr;

        std::function<bool(
            const httplib::Request&,
            httplib::Response&,
            const unsigned char*,
            UsersRegistry*,
            std::string*,
            std::string*
        )> require_user_auth_users_actor;

        std::function<void(
            httplib::Response&,
            int,
            const std::string&
        )> reply_json;
    };

    void register_gallery_album_routes(httplib::Server& srv,
                                       const GalleryAlbumRoutesDeps& deps);

} // namespace pqnas