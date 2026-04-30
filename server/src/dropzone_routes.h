#pragma once

#include "dropzone_index.h"
#include "httplib.h"
#include "users_registry.h"
#include "file_location_index.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>

namespace pqnas {

class GalleryMetaIndex;

// Dependencies injected from main.cpp into the Drop Zone route module.
//
// Keep route registration decoupled from main.cpp globals. This makes the
// module easier to audit and easier to move later if Drop Zone grows into a
// larger bundled app/service.
//
// Route responsibilities:
// - authenticated owner APIs: create/list/disable Drop Zones
// - public token APIs: info, chunked upload start/chunk/finish/cancel
// - public /dz/<token> upload page
//
// Storage details live in DropZoneIndex.
// User/root path resolution stays injected so this module does not need to know
// how the UsersRegistry maps fingerprints to on-disk storage directories.
struct DropZoneRoutesDeps {
    // Metadata/facts index used by the modern file resolver.
    // Drop Zone writes files directly, so after a successful upload we must
    // touch file facts or File Manager read/stat may not see the new file.
    GalleryMetaIndex* file_facts = nullptr;

    // File Manager / storage resolver metadata index.
    // Drop Zone uploads must touch this so files are openable through normal
    // /api/v4/files routes after public upload completes.
    FileLocationIndex* file_locations = nullptr;

    // User registry is used for owner auth checks and for validating that the
    // Drop Zone owner still exists, is enabled, and has allocated storage.
    UsersRegistry* users = nullptr;

    // SQLite-backed Drop Zone metadata/index.
    DropZoneIndex* dropzone_index = nullptr;

    // Session cookie verification key used by require_user_auth_users_actor.
    const unsigned char* cookie_key = nullptr;

    // Canonical public origin, e.g. https://example.com.
    // Used when returning full Drop Zone URLs and for same-origin checks on
    // authenticated owner mutations.
    const std::string* origin = nullptr;

    // Resolve a user's fingerprint to their storage root.
    //
    // Public uploads must still normalize paths and verify that final paths stay
    // under this root before writing anything.
    std::function<std::filesystem::path(UsersRegistry&, const std::string&)> user_dir_for_fp;

    // Cryptographically strong URL-safe random generator from main.cpp.
    // Used for Drop Zone ids, public tokens, upload session ids, and temp-file
    // suffixes.
    std::function<std::string(std::size_t)> random_b64url;

    // Injectable clock for expiry checks and durable timestamps.
    std::function<std::int64_t()> now_epoch;

    // Existing PQ-NAS user auth bridge.
    //
    // Returns authenticated actor fingerprint + role for owner-side APIs.
    // Public token upload APIs do not use this; they authorize by Drop Zone token.
    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       UsersRegistry*,
                       std::string*,
                       std::string*)> require_user_auth_users_actor;

    // Shared JSON response helper from main.cpp.
    // Keeps headers/status formatting consistent with the rest of the v4 API.
    std::function<void(httplib::Response&, int, const std::string&)> reply_json;

    // Shared audit bridge from main.cpp.
    //
    // Route code should avoid placing secrets here:
    // - no raw Drop Zone token
    // - no password
    // - no full public link unless deliberately needed
    std::function<void(const std::string&,
                       const std::string&,
                       const std::map<std::string, std::string>&)> audit_emit;
};

void register_dropzone_routes(httplib::Server& srv, const DropZoneRoutesDeps& deps);

} // namespace pqnas