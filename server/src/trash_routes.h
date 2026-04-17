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

// Dependency bundle for trash route registration.
//
// Architectural role:
// - register_trash_routes() is intentionally written as a thin orchestration layer.
// - Instead of reaching directly into globals, it receives everything it needs through
//   this struct.
// - That keeps the route module easier to test, easier to embed in different server
//   setups, and clearer about which cross-subsystem services it depends on.
//
// The fields below fall into four groups:
// 1) registries / persisted config sources
// 2) trash-specific service/index objects
// 3) shared platform helpers (auth, reply, audit)
// 4) path resolution helpers used to turn logical scopes into concrete filesystem roots
struct TrashRoutesDeps {
    // User registry and its backing path.
    //
    // Used for:
    // - authenticating/authorizing user-scoped trash operations
    // - resolving live user storage roots for restore
    // - reloading or consulting current user state when needed
    UsersRegistry* users = nullptr;
    const std::string* users_path = nullptr;

    // Workspace registry and its backing path.
    //
    // Used for:
    // - workspace membership checks
    // - verifying workspace status before restore/purge/list
    // - resolving workspace-scoped restore targets
    WorkspacesRegistry* workspaces = nullptr;
    const std::string* workspaces_path = nullptr;

    // Core trash metadata/service dependencies.
    //
    // Separation of concerns:
    // - TrashIndex provides metadata queries and lifecycle status storage
    // - TrashService performs restore/purge filesystem work and coordinates safe
    //   state transitions using TrashIndex
    TrashIndex* trash_index = nullptr;
    TrashService* trash_service = nullptr;

    // Shared cookie key passed through to the auth helper.
    //
    // The route layer does not interpret session cookies itself; it delegates that
    // responsibility to require_user_auth_users_actor below.
    const unsigned char* cookie_key = nullptr;

    // Authentication / actor resolution helper.
    //
    // Expected contract:
    // - validate the user cookie/session
    // - populate actor fingerprint and role
    // - write the appropriate HTTP response on failure
    //
    // This keeps the trash route module independent from the concrete auth
    // implementation used by main.cpp.
    std::function<bool(const httplib::Request&,
                       httplib::Response&,
                       const unsigned char*,
                       UsersRegistry*,
                       std::string*,
                       std::string*)> require_user_auth_users_actor;

    // Shared JSON response helper.
    //
    // Routes use this rather than constructing reply behavior themselves so response
    // formatting stays consistent with the rest of the API surface.
    std::function<void(httplib::Response&, int, const std::string&)> reply_json;

    // Shared audit bridge.
    //
    // Trash routes emit success/failure events, but they do not own the audit sink.
    // main.cpp or tests can provide the concrete implementation here.
    std::function<void(const std::string&,
                       const std::string&,
                       const std::map<std::string, std::string>&)> audit_emit;

    // Resolves a user's live filesystem root from the user registry + fingerprint.
    //
    // Restore routes deliberately depend on a helper instead of hardcoding path logic
    // here, so the route layer stays focused on authorization and request handling.
    std::function<std::filesystem::path(UsersRegistry&, const std::string&)> user_dir_for_fp;

    // Resolves a workspace's live filesystem root.
    //
    // The current name reflects the present implementation strategy: workspace roots
    // are resolved through the existing "default pool only" logic already used in the
    // server. Exposing this as a dependency avoids duplicating storage topology rules
    // inside the trash route module.
    std::function<std::filesystem::path(const std::string&, const WorkspaceRec&)>
        workspace_dir_for_default_pool_only;
};

// Registers all trash-related HTTP routes onto the given server.
//
// High-level route responsibilities:
// - authenticate the caller
// - authorize access to user/workspace trash scope
// - validate request input
// - translate between HTTP JSON and TrashService / TrashIndex operations
// - emit audit events
//
// Lower-level responsibilities such as metadata persistence, payload restore/purge,
// and race-safe lifecycle transitions are delegated to TrashIndex and TrashService.
void register_trash_routes(httplib::Server& srv, const TrashRoutesDeps& deps);

} // namespace pqnas