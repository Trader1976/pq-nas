#include "routes_admin_workspaces.h"

#include <cmath>
#include <filesystem>
#include <limits>
#include <sys/statvfs.h>
#include <system_error>
#include <cstdlib>

namespace pqnas {

namespace {
    // Trims leading and trailing ASCII whitespace from a copy of the input string.
    //
    // Why this exists:
    // - Admin workspace routes accept human-entered JSON fields such as names,
    //   notes, fingerprints, and ids.
    // - Normalizing whitespace early keeps validation and comparisons consistent.
    std::string trim_copy_safe(const std::string& s) {
        std::size_t a = 0;
        while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

        std::size_t b = s.size();
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

        return s.substr(a, b - a);
    }

    // Normalizes a pool id for internal comparisons.
    //
    // Rules:
    // - surrounding whitespace is removed
    // - empty stays empty
    // - "default" is normalized to empty string so the default pool has one
    //   canonical internal representation
    // - other values keep their original spelling after trim
    std::string normalize_pool_id_copy(const std::string& s) {
        const std::string v = trim_copy_safe(s);
        if (v.empty()) return "";
        std::string low = v;
        for (char& c : low) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (low == "default") return "";
        return v;
    }

    // Resolves the filesystem root used for default-pool workspace storage.
    //
    // Resolution order:
    // - PQNAS_DATA_ROOT if set
    // - PQNAS_STORAGE_ROOT + "/data" if set
    // - legacy fallback derived from users_path
    //
    // Why this exists:
    // - Admin workspace create/delete needs a stable way to find the on-disk root
    //   for default-pool workspace directories.
    std::filesystem::path default_data_root_from_users_path(const std::string& users_path) {
        if (const char* p = std::getenv("PQNAS_DATA_ROOT")) {
            if (*p) return std::filesystem::path(p);
        }

        if (const char* p = std::getenv("PQNAS_STORAGE_ROOT")) {
            if (*p) return std::filesystem::path(p) / "data";
        }

        // Legacy fallback only.
        const std::filesystem::path up(users_path);
        return up.parent_path().parent_path() / "data";
    }
        static std::string admin_ws_header_value_local(const httplib::Request& req, const char* key) {
        auto it = req.headers.find(key);
        return (it == req.headers.end()) ? std::string() : it->second;
    }
    // Same-origin CSRF check for cookie-authenticated admin workspace mutations.
    //
    // Why this exists:
    // - Admin workspace actions (create/delete/rename/member changes) are
    //   high-impact browser actions that typically use the session cookie.
    // - We therefore require the request to come from this server origin before
    //   allowing the mutation.
    //
    // Rules:
    // - Bearer-token requests are exempt because they do not rely on ambient
    //   browser cookies.
    // - Prefer Origin when present.
    // - Fall back to Referer for same-origin browser requests that omit Origin.
    // - Reject requests with mismatched origin/referer or with neither header.
    bool require_same_origin_for_cookie_mutation_admin_ws_local(
        const httplib::Request& req,
        httplib::Response& res,
        const std::string& expected_origin
    ) {
        const std::string auth = admin_ws_header_value_local(req, "Authorization");
        if (auth.rfind("Bearer ", 0) == 0) return true;

        const std::string origin = admin_ws_header_value_local(req, "Origin");
        if (!origin.empty()) {
            if (origin == expected_origin) return true;
            res.status = 403;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
            return false;
        }

        const std::string referer = admin_ws_header_value_local(req, "Referer");
        if (!referer.empty()) {
            if (referer.rfind(expected_origin, 0) == 0) return true;
            res.status = 403;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"ok":false,"error":"forbidden","message":"origin mismatch"})";
            return false;
        }

        res.status = 403;
        res.set_header("Content-Type", "application/json");
        res.body = R"({"ok":false,"error":"forbidden","message":"missing origin"})";
        return false;
    }

    // Thin deps-aware wrapper for admin-workspace same-origin enforcement.
    //
    // Why this exists:
    // - Admin route code should read configuration through AdminWorkspaceRouteDeps
    //   instead of depending on a global ORIGIN symbol.
    // - This also fails closed when origin wiring is missing or empty, which is
    //   safer than accidentally running admin mutations without CSRF checks.
    bool require_same_origin_for_cookie_mutation_admin_ws_deps(
            const httplib::Request& req,
            httplib::Response& res,
            const AdminWorkspaceRouteDeps& deps
        ) {
        if (!deps.origin || deps.origin->empty()) {
            res.status = 500;
            res.set_header("Content-Type", "application/json");
            res.body = R"({"ok":false,"error":"server_error","message":"origin not configured"})";
            return false;
        }
        return require_same_origin_for_cookie_mutation_admin_ws_local(req, res, *deps.origin);
    }


    // Best-effort directory creation helper.
    //
    // Behavior:
    // - creates the full directory chain if missing
    // - succeeds if the directory already exists
    // - returns the filesystem error message through err on failure
    bool ensure_dir_exists_local(const std::filesystem::path& p, std::string* err) {
        if (err) err->clear();

        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        if (ec) {
            if (err) *err = ec.message();
            return false;
        }
        return true;
    }

    std::uint64_t dir_size_bytes_best_effort_local(const std::filesystem::path& root) {
        std::uint64_t total = 0;
        std::error_code ec;

        if (!std::filesystem::exists(root, ec)) return 0;
        ec.clear();

        for (std::filesystem::recursive_directory_iterator it(root, ec), end;
             it != end && !ec;
             it.increment(ec)) {
            if (ec) break;

            std::error_code ec2;
            if (it->is_regular_file(ec2) && !ec2) {
                std::error_code ec3;
                const auto sz = it->file_size(ec3);
                if (!ec3) total += static_cast<std::uint64_t>(sz);
            }
        }

        return total;
    }
    bool statvfs_path_local(const std::string& path,
                            std::uint64_t* out_total_bytes,
                            std::uint64_t* out_free_bytes) {
        if (out_total_bytes) *out_total_bytes = 0;
        if (out_free_bytes) *out_free_bytes = 0;

        struct statvfs st {};
        if (::statvfs(path.c_str(), &st) != 0) return false;

        const unsigned long long total =
            static_cast<unsigned long long>(st.f_blocks) *
            static_cast<unsigned long long>(st.f_frsize);

        const unsigned long long freeb =
            static_cast<unsigned long long>(st.f_bavail) *
            static_cast<unsigned long long>(st.f_frsize);

        if (out_total_bytes) *out_total_bytes = static_cast<std::uint64_t>(total);
        if (out_free_bytes) *out_free_bytes = static_cast<std::uint64_t>(freeb);
        return true;
    }

    // Finds the nearest existing path at or above p that can be safely passed to
    // statvfs().
    //
    // Why this exists:
    // - New workspace paths may not exist yet.
    // - Capacity checks still need a real existing path on the target filesystem.
    std::string nearest_existing_path_for_statvfs(const std::filesystem::path& p) {
        std::error_code ec;
        std::filesystem::path cur = p;

        while (!cur.empty()) {
            if (std::filesystem::exists(cur, ec) && !ec) {
                return cur.string();
            }
            ec.clear();
            cur = cur.parent_path();
        }

        return "/";
    }
    std::uint64_t sum_allocated_user_quota_on_pool_local(const UsersRegistry& users,
                                                         const std::string& want_pool_id,
                                                         const std::string& exclude_fp) {
    const std::string want_pool = normalize_pool_id_copy(want_pool_id);
    std::uint64_t total = 0;

    for (const auto& kv : users.snapshot()) {
        const auto& u = kv.second;

        if (!exclude_fp.empty() && u.fingerprint == exclude_fp) continue;
        if (u.storage_state != "allocated") continue;

        const std::string user_pool = normalize_pool_id_copy(u.storage_pool_id);
        if (user_pool != want_pool) continue;

        const std::uint64_t q = static_cast<std::uint64_t>(u.quota_bytes);
        if (std::numeric_limits<std::uint64_t>::max() - total < q) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        total += q;
    }

    return total;
}
bool quota_gb_json_to_bytes(const json& j,
                            std::uint64_t* out_quota_bytes,
                            std::string* out_err) {
    if (out_quota_bytes) *out_quota_bytes = 0;
    if (out_err) out_err->clear();

    if (!j.contains("quota_gb")) {
        if (out_err) *out_err = "missing quota_gb";
        return false;
    }

    double quota_gb_d = 0.0;
    try {
        const auto& v = j["quota_gb"];
        if (v.is_number_integer()) quota_gb_d = static_cast<double>(v.get<long long>());
        else if (v.is_number_unsigned()) quota_gb_d = static_cast<double>(v.get<unsigned long long>());
        else if (v.is_number_float()) quota_gb_d = v.get<double>();
        else {
            if (out_err) *out_err = "quota_gb must be a number";
            return false;
        }
    } catch (...) {
        if (out_err) *out_err = "invalid quota_gb";
        return false;
    }

    if (quota_gb_d < 0.0) {
        if (out_err) *out_err = "quota_gb must be >= 0";
        return false;
    }

    const long double bytes_ld =
        static_cast<long double>(quota_gb_d) *
        1024.0L * 1024.0L * 1024.0L;

    if (bytes_ld > static_cast<long double>(std::numeric_limits<std::uint64_t>::max())) {
        if (out_err) *out_err = "quota_gb too large";
        return false;
    }

    if (out_quota_bytes) {
        *out_quota_bytes = static_cast<std::uint64_t>(bytes_ld + 0.5L);
    }
    return true;
}
    // Small audit helper for admin workspace routes.
    //
    // Why this exists:
    // - Keeps route code shorter and makes audit emission optional through deps.
    void audit_workspace_event(const AdminWorkspaceRouteDeps& deps,
                               const std::string& event,
                               const std::string& outcome,
                               const std::map<std::string, std::string>& fields) {
        if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
    }

    bool is_enabled_user_for_workspace_owner(const UsersRegistry& users,
                                             const std::string& fp) {
        auto uopt = users.get(fp);
        if (!uopt.has_value()) return false;
        return uopt->status == "enabled";
    }

    // Converts one workspace record into the admin API response shape.
    //
    // Included data:
    // - basic workspace metadata
    // - storage metadata
    // - member list
    // - best-effort storage_used_bytes for allocated default-pool workspaces
    json workspace_to_admin_json(const WorkspaceRec& w,
                                 const std::string& users_path) {
        json out = json::object();

        out["workspace_id"] = w.workspace_id;
        out["name"] = w.name;
        out["status"] = w.status;
        out["notes"] = w.notes;

        out["created_at"] = w.created_at;
        out["created_by"] = w.created_by;

        out["storage_state"] = w.storage_state;
        out["storage_pool_id"] = w.storage_pool_id;
        out["pool_id"] = w.storage_pool_id.empty() ? "default" : w.storage_pool_id;
        out["root_rel"] = w.root_rel;
        out["quota_bytes"] = w.quota_bytes;
        out["storage_set_at"] = w.storage_set_at;
        out["storage_set_by"] = w.storage_set_by;

        out["member_count"] = static_cast<unsigned long long>(w.members.size());

        json members = json::array();
        for (const auto& m : w.members) {
            members.push_back(json{
                {"fingerprint", m.fingerprint},
                {"role", m.role},
                {"status", m.status},
                {"added_at", m.added_at},
                {"added_by", m.added_by},
                {"responded_at", m.responded_at},
                {"responded_by", m.responded_by}
            });
        }
        out["members"] = std::move(members);

        std::uint64_t used_bytes = 0;
        if (w.storage_state == "allocated" && w.storage_pool_id.empty() && !w.root_rel.empty()) {
            const std::filesystem::path abs =
                default_data_root_from_users_path(users_path) / w.root_rel;
            used_bytes = dir_size_bytes_best_effort_local(abs);
        }
        out["storage_used_bytes"] = used_bytes;

        return out;
    }

} // namespace

    // Counts enabled owners in a workspace.
    //
    // Why this exists:
    // - Delete/demotion/removal rules depend on whether a workspace would lose its
    //   last enabled owner.
    std::size_t count_enabled_owners(const WorkspaceRec& w) {
    std::size_t n = 0;
    for (const auto& m : w.members) {
        if (m.status == "enabled" && m.role == "owner") ++n;
    }
    return n;
}


    // Returns true when the workspace has exactly one enabled member and that
    // member is an owner.
    //
    // Why this exists:
    // - Workspace delete is allowed only in the "sole enabled owner, no other
    //   active members" state.
    bool has_single_enabled_owner_only(const WorkspaceRec& w) {
    std::size_t enabled_count = 0;
    std::size_t enabled_owner_count = 0;

    for (const auto& m : w.members) {
        if (m.status != "enabled") continue;
        ++enabled_count;
        if (m.role == "owner") ++enabled_owner_count;
    }

    return enabled_count == 1 && enabled_owner_count == 1;
}
    // Returns true if the workspace contains a member entry for the given
    // fingerprint, regardless of status.
    bool workspace_member_exists(const WorkspaceRec& w, const std::string& fp) {
    for (const auto& m : w.members) {
        if (m.fingerprint == fp) return true;
    }
    return false;
}
    // Looks up one workspace member by fingerprint.
    //
    // Returns:
    // - the matching member record if found
    // - std::nullopt otherwise
    std::optional<WorkspaceMemberRec> workspace_member_get(const WorkspaceRec& w, const std::string& fp) {
    for (const auto& m : w.members) {
        if (m.fingerprint == fp) return m;
    }
    return std::nullopt;
}

    bool reload_workspaces_or_500(const AdminWorkspaceRouteDeps& deps,
                                  httplib::Response& res) {
    if (!deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return false;
    }
    return true;
}
    // Registers admin workspace HTTP routes.
    //
    // Route groups:
    // - list workspaces
    // - create/delete/rename workspaces
    // - add/remove members
    // - change member roles
    //
    // Security:
    // - all mutating routes require admin cookie auth
    // - all mutating routes enforce same-origin checks
void register_admin_workspace_routes(httplib::Server& srv,
                                     const AdminWorkspaceRouteDeps& deps) {
    // GET /api/v4/admin/workspaces
    //
    // Returns the current admin view of all workspaces with expanded metadata and
    // member information.
    srv.Get("/api/v4/admin/workspaces",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!deps.require_admin_cookie_users_actor ||
            !deps.require_admin_cookie_users_actor(
                req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
            return;
        }

        if (!deps.workspaces->load(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        res.set_header("Cache-Control", "no-store");

        json out;
        out["ok"] = true;
        out["actor_fp"] = actor_fp;
        out["workspaces"] = json::array();

        for (const auto& kv : deps.workspaces->snapshot()) {
            out["workspaces"].push_back(workspace_to_admin_json(kv.second, deps.users_path));
        }

        deps.reply_json(res, 200, out.dump());
    });
    // POST /api/v4/admin/workspaces/create
    //
    // Creates a new workspace in the default pool, allocates its on-disk directory,
    // validates the requested owner, and performs committed-quota admission checks
    // against the backing filesystem capacity.
srv.Post("/api/v4/admin/workspaces/create",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp;
    if (!deps.require_admin_cookie_users_actor ||
        !deps.require_admin_cookie_users_actor(
            req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
        return;
    }
    if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
    res.set_header("Cache-Control", "no-store");

    json j;
    try {
        j = json::parse(req.body);
    } catch (...) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string name = trim_copy_safe(j.value("name", ""));
    const std::string notes = trim_copy_safe(j.value("notes", ""));
    const std::string owner_fp = trim_copy_safe(j.value("owner_fingerprint", ""));
    const std::string pool_id_norm = normalize_pool_id_copy(j.value("pool_id", ""));

    if (name.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing name"}
        }.dump());
        return;
    }

    if (owner_fp.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing owner_fingerprint"}
        }.dump());
        return;
    }

    std::uint64_t quota_bytes = 0;
    std::string quota_err;
    if (!quota_gb_json_to_bytes(j, &quota_bytes, &quota_err)) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", quota_err}
        }.dump());
        return;
    }

    if (!is_enabled_user_for_workspace_owner(*deps.users, owner_fp)) {
        audit_workspace_event(deps, "admin.workspace_create_refused", "fail", {
            {"reason", "owner_not_enabled"},
            {"owner_fp", owner_fp},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "owner_not_enabled"},
            {"message", "owner_fingerprint must refer to an enabled user"}
        }.dump());
        return;
    }

    // v1 minimal: support default pool only until pool root resolution is moved
    // out of main.cpp into reusable helpers.
    if (!pool_id_norm.empty()) {
        audit_workspace_event(deps, "admin.workspace_create_refused", "fail", {
            {"reason", "pool_not_supported_yet"},
            {"pool_id", pool_id_norm},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "pool_not_supported_yet"},
            {"message", "workspace create currently supports default pool only"}
        }.dump());
        return;
    }

    std::string workspace_id;
    for (int i = 0; i < 16; ++i) {
        workspace_id = new_workspace_id();
        if (!deps.workspaces->exists(workspace_id)) break;
        workspace_id.clear();
    }

    if (workspace_id.empty()) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to generate unique workspace_id"}
        }.dump());
        return;
    }

    // Workspace storage currently uses the default pool/data_root only.
    // Keep it outside tiering for now, but still enforce committed-quota
    // admission against the backing filesystem capacity.
    {
        const std::string effective_pool_id = ""; // default pool
        const std::filesystem::path data_root =
            default_data_root_from_users_path(deps.users_path);

        const std::string stat_path =
            nearest_existing_path_for_statvfs(data_root);

        std::uint64_t pool_total_bytes = 0;
        std::uint64_t pool_free_bytes = 0;

        if (!statvfs_path_local(stat_path, &pool_total_bytes, &pool_free_bytes)) {
            audit_workspace_event(deps, "admin.workspace_create_refused", "fail", {
                {"reason", "pool_statvfs_failed"},
                {"pool_id", "default"},
                {"path", stat_path},
                {"data_root", data_root.string()},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "pool_statvfs_failed"},
                {"message", "failed to read default pool capacity"},
                {"pool_id", "default"},
                {"path", stat_path},
                {"data_root", data_root.string()}
            }.dump());
            return;
        }

        const std::uint64_t allocated_user_bytes =
            sum_allocated_user_quota_on_pool_local(*deps.users, effective_pool_id, "");

        const std::uint64_t allocated_workspace_bytes =
            sum_allocated_workspace_quota_on_pool(*deps.workspaces, effective_pool_id, "");

        std::uint64_t allocated_other_bytes = allocated_user_bytes;
        if (std::numeric_limits<std::uint64_t>::max() - allocated_other_bytes < allocated_workspace_bytes) {
            allocated_other_bytes = std::numeric_limits<std::uint64_t>::max();
        } else {
            allocated_other_bytes += allocated_workspace_bytes;
        }

        std::uint64_t would_total_bytes = allocated_other_bytes;
        if (std::numeric_limits<std::uint64_t>::max() - would_total_bytes < quota_bytes) {
            would_total_bytes = std::numeric_limits<std::uint64_t>::max();
        } else {
            would_total_bytes += quota_bytes;
        }

        if (would_total_bytes > pool_total_bytes) {
            audit_workspace_event(deps, "admin.workspace_create_refused", "fail", {
                {"reason", "pool_quota_overcommit"},
                {"pool_id", "default"},
                {"requested_quota_bytes", std::to_string(static_cast<unsigned long long>(quota_bytes))},
                {"allocated_user_bytes", std::to_string(static_cast<unsigned long long>(allocated_user_bytes))},
                {"allocated_workspace_bytes", std::to_string(static_cast<unsigned long long>(allocated_workspace_bytes))},
                {"allocated_other_bytes", std::to_string(static_cast<unsigned long long>(allocated_other_bytes))},
                {"would_total_bytes", std::to_string(static_cast<unsigned long long>(would_total_bytes))},
                {"pool_total_bytes", std::to_string(static_cast<unsigned long long>(pool_total_bytes))},
                {"pool_free_bytes", std::to_string(static_cast<unsigned long long>(pool_free_bytes))},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "pool_quota_overcommit"},
                {"message", "requested workspace quota would exceed default pool capacity"},
                {"pool_id", "default"},
                {"requested_quota_bytes", quota_bytes},
                {"allocated_user_bytes", allocated_user_bytes},
                {"allocated_workspace_bytes", allocated_workspace_bytes},
                {"allocated_other_bytes", allocated_other_bytes},
                {"would_total_bytes", would_total_bytes},
                {"pool_total_bytes", pool_total_bytes},
                {"pool_free_bytes", pool_free_bytes}
            }.dump());
            return;
        }
    }

    const std::string root_rel = default_workspace_root_rel_for_id(workspace_id);
    if (root_rel.empty()) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to derive workspace root_rel"}
        }.dump());
        return;
    }

    const std::filesystem::path data_root = default_data_root_from_users_path(deps.users_path);
    const std::filesystem::path ws_dir = data_root / root_rel;

    {
        std::string fs_err;
        if (!ensure_dir_exists_local(ws_dir.parent_path(), &fs_err)) {
            audit_workspace_event(deps, "admin.workspace_create_fail", "fail", {
                {"reason", "mkdir_parent_failed"},
                {"workspace_id", workspace_id},
                {"path", ws_dir.parent_path().string()},
                {"detail", fs_err},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create workspace parent directory"},
                {"path", ws_dir.parent_path().string()},
                {"detail", fs_err}
            }.dump());
            return;
        }
    }

    {
        std::string fs_err;
        if (!ensure_dir_exists_local(ws_dir, &fs_err)) {
            audit_workspace_event(deps, "admin.workspace_create_fail", "fail", {
                {"reason", "mkdir_workspace_failed"},
                {"workspace_id", workspace_id},
                {"path", ws_dir.string()},
                {"detail", fs_err},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create workspace directory"},
                {"path", ws_dir.string()},
                {"detail", fs_err}
            }.dump());
            return;
        }
    }

    const std::string now_iso = deps.now_iso_utc ? deps.now_iso_utc() : "";

    WorkspaceRec w;
    w.workspace_id = workspace_id;
    w.name = name;
    w.status = "enabled";
    w.notes = notes;

    w.created_at = now_iso;
    w.created_by = actor_fp;

    w.storage_state = "allocated";
    w.storage_pool_id = "";
    w.root_rel = root_rel;
    w.quota_bytes = quota_bytes;
    w.storage_set_at = now_iso;
    w.storage_set_by = actor_fp;

    WorkspaceMemberRec owner;
    owner.fingerprint = owner_fp;
    owner.role = "owner";
    owner.status = "enabled";
    owner.added_at = now_iso;
    owner.added_by = actor_fp;
    w.members.push_back(owner);

    if (!deps.workspaces->upsert(w)) {
        audit_workspace_event(deps, "admin.workspace_create_fail", "fail", {
            {"reason", "upsert_failed"},
            {"workspace_id", workspace_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "workspace upsert failed"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_workspace_event(deps, "admin.workspace_create_fail", "fail", {
            {"reason", "save_failed"},
            {"workspace_id", workspace_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "workspaces save failed"}
        }.dump());
        return;
    }

    audit_workspace_event(deps, "admin.workspace_created", "ok", {
        {"workspace_id", workspace_id},
        {"name", name},
        {"owner_fp", owner_fp},
        {"quota_bytes", std::to_string(static_cast<unsigned long long>(quota_bytes))},
        {"root_rel", root_rel},
        {"pool_id", "default"},
        {"actor_fp", actor_fp}
    });

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace", workspace_to_admin_json(w, deps.users_path)}
    }.dump());
});
    // POST /api/v4/admin/workspaces/delete
    //
    // Deletes a workspace only when it is in the safe "single enabled owner only"
    // state, removes its directory tree for default-pool storage, and erases the
    // registry entry.
    srv.Post("/api/v4/admin/workspaces/delete",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp;
    if (!deps.require_admin_cookie_users_actor ||
        !deps.require_admin_cookie_users_actor(
            req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
        return;
    }
    if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
    res.set_header("Cache-Control", "no-store");

    if (!reload_workspaces_or_500(deps, res)) return;

    json j;
    try {
        j = json::parse(req.body);
    } catch (...) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    const WorkspaceRec w = *wopt;

    if (!has_single_enabled_owner_only(w)) {
        audit_workspace_event(deps, "admin.workspace_delete_refused", "fail", {
            {"reason", "not_sole_enabled_owner_state"},
            {"workspace_id", workspace_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 409, json{
            {"ok", false},
            {"error", "workspace_not_deletable"},
            {"message", "workspace can be deleted only when one enabled owner is the last active member"}
        }.dump());
        return;
    }

    if (!w.storage_pool_id.empty()) {
        audit_workspace_event(deps, "admin.workspace_delete_refused", "fail", {
            {"reason", "pool_not_supported_yet"},
            {"workspace_id", workspace_id},
            {"pool_id", w.storage_pool_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "pool_not_supported_yet"},
            {"message", "workspace delete currently supports default pool only"}
        }.dump());
        return;
    }

    std::filesystem::path ws_dir;
    if (w.storage_state == "allocated" && !w.root_rel.empty()) {
        ws_dir = default_data_root_from_users_path(deps.users_path) / w.root_rel;
    }

    std::uintmax_t removed_entries = 0;
    if (!ws_dir.empty()) {
        std::error_code ec;
        removed_entries = std::filesystem::remove_all(ws_dir, ec);
        if (ec) {
            audit_workspace_event(deps, "admin.workspace_delete_fail", "fail", {
                {"reason", "remove_all_failed"},
                {"workspace_id", workspace_id},
                {"path", ws_dir.string()},
                {"detail", ec.message()},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to delete workspace directory"},
                {"detail", ec.message()}
            }.dump());
            return;
        }
    }

    if (!deps.workspaces->erase(workspace_id)) {
        audit_workspace_event(deps, "admin.workspace_delete_fail", "fail", {
            {"reason", "erase_failed"},
            {"workspace_id", workspace_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to erase workspace registry entry"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        // best-effort rollback of registry entry because filesystem content is already gone
        deps.workspaces->upsert(w);
        deps.workspaces->save(deps.workspaces_path);

        audit_workspace_event(deps, "admin.workspace_delete_fail", "fail", {
            {"reason", "save_failed"},
            {"workspace_id", workspace_id},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces after delete"}
        }.dump());
        return;
    }

    audit_workspace_event(deps, "admin.workspace_deleted", "ok", {
        {"workspace_id", workspace_id},
        {"name", w.name},
        {"root_rel", w.root_rel},
        {"removed_entries", std::to_string(static_cast<unsigned long long>(removed_entries))},
        {"actor_fp", actor_fp}
    });

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace_id", workspace_id}
    }.dump());
});
    // POST /api/v4/admin/workspaces/rename
    //
    // Renames an existing workspace in the registry. This affects workspace
    // metadata only; it does not move or rename the on-disk root.
srv.Post("/api/v4/admin/workspaces/rename",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp;
    if (!deps.require_admin_cookie_users_actor ||
        !deps.require_admin_cookie_users_actor(
            req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
        return;
    }
    if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
    res.set_header("Cache-Control", "no-store");

    if (!reload_workspaces_or_500(deps, res)) return;

    json j;
    try {
        j = json::parse(req.body);
    } catch (...) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    const std::string new_name = trim_copy_safe(j.value("name", ""));

    if (workspace_id.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (new_name.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing name"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    WorkspaceRec w = *wopt;
    const std::string old_name = w.name;

    w.name = new_name;

    if (!deps.workspaces->upsert(w)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to update workspace"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    audit_workspace_event(deps, "admin.workspace_renamed", "ok", {
        {"workspace_id", workspace_id},
        {"old_name", old_name},
        {"new_name", new_name},
        {"actor_fp", actor_fp}
    });

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace", workspace_to_admin_json(w, deps.users_path)}
    }.dump());
});
    // POST /api/v4/admin/workspaces/members/add
    //
    // Adds a new workspace member or updates an existing member entry.
    //
    // Behavior:
    // - enabled members stay enabled
    // - invited members keep invited status
    // - missing/disabled members become invited again
    // - role is normalized before storing
    srv.Post("/api/v4/admin/workspaces/members/add",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!deps.require_admin_cookie_users_actor ||
            !deps.require_admin_cookie_users_actor(
                req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
            return;
        }
        if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
        res.set_header("Cache-Control", "no-store");

        if (!reload_workspaces_or_500(deps, res)) return;

        json j;
        try {
            j = json::parse(req.body);
        } catch (...) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string fp = trim_copy_safe(j.value("fingerprint", ""));
        const std::string role = normalize_workspace_role_copy(j.value("role", "viewer"));

        if (workspace_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        if (fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing fingerprint"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        if (!is_enabled_user_for_workspace_owner(*deps.users, fp)) {
            audit_workspace_event(deps, "admin.workspace_member_add_refused", "fail", {
                {"reason", "user_not_enabled"},
                {"workspace_id", workspace_id},
                {"target_fp", fp},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "user_not_enabled"},
                {"message", "fingerprint must refer to an enabled user"}
            }.dump());
            return;
        }

                 const std::string now_iso = deps.now_iso_utc ? deps.now_iso_utc() : "";

         auto existing = workspace_member_get(*wopt, fp);
         [[maybe_unused]] const bool existed = existing.has_value();

         WorkspaceMemberRec member;
         member.fingerprint = fp;
         member.role = role;

         if (!existing.has_value()) {
             member.status = "invited";
             member.added_at = now_iso;
             member.added_by = actor_fp;
             member.responded_at.clear();
             member.responded_by.clear();
         } else if (existing->status == "enabled") {
             member.status = "enabled";
             member.added_at = existing->added_at;
             member.added_by = existing->added_by;
             member.responded_at = existing->responded_at;
             member.responded_by = existing->responded_by;
         } else if (existing->status == "invited") {
             member.status = "invited";
             member.added_at = existing->added_at;
             member.added_by = existing->added_by;
             member.responded_at.clear();
             member.responded_by.clear();
         } else {
             member.status = "invited";
             member.added_at = now_iso;
             member.added_by = actor_fp;
             member.responded_at.clear();
             member.responded_by.clear();
         }

         if (!deps.workspaces->add_or_update_member(workspace_id, member)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to add workspace member"}
            }.dump());
            return;
        }

        auto w2 = deps.workspaces->get(workspace_id);
        if (!w2.has_value() || !deps.workspaces->save(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save workspaces"}
            }.dump());
            return;
        }

                 std::string audit_event = "admin.workspace_member_invited";
                 if (existing.has_value() && existing->status == "enabled") {
                     audit_event = "admin.workspace_member_updated";
                 } else if (existing.has_value() && existing->status == "invited") {
                     audit_event = "admin.workspace_member_invite_updated";
                 } else if (existing.has_value() && existing->status == "disabled") {
                     audit_event = "admin.workspace_member_reinvited";
                 }

                 audit_workspace_event(deps, audit_event, "ok", {
                     {"workspace_id", workspace_id},
                     {"target_fp", fp},
                     {"role", role},
                     {"status", member.status},
                     {"actor_fp", actor_fp}
                 });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace", workspace_to_admin_json(*w2, deps.users_path)}
        }.dump());
    });
    // POST /api/v4/admin/workspaces/members/remove
    //
    // Removes a workspace member, but refuses to remove the last enabled owner.
    srv.Post("/api/v4/admin/workspaces/members/remove",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!deps.require_admin_cookie_users_actor ||
            !deps.require_admin_cookie_users_actor(
                req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
            return;
        }
        if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
        res.set_header("Cache-Control", "no-store");

        if (!reload_workspaces_or_500(deps, res)) return;

        json j;
        try {
            j = json::parse(req.body);
        } catch (...) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string fp = trim_copy_safe(j.value("fingerprint", ""));

        if (workspace_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        if (fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing fingerprint"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        auto mopt = workspace_member_get(*wopt, fp);
        if (!mopt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "member not found"}
            }.dump());
            return;
        }

        if (mopt->status == "enabled" && mopt->role == "owner" && count_enabled_owners(*wopt) <= 1) {
            audit_workspace_event(deps, "admin.workspace_member_remove_refused", "fail", {
                {"reason", "last_enabled_owner"},
                {"workspace_id", workspace_id},
                {"target_fp", fp},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "last_enabled_owner"},
                {"message", "cannot remove the last enabled owner"}
            }.dump());
            return;
        }

        if (!deps.workspaces->remove_member(workspace_id, fp)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to remove workspace member"}
            }.dump());
            return;
        }

        auto w2 = deps.workspaces->get(workspace_id);
        if (!w2.has_value() || !deps.workspaces->save(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save workspaces"}
            }.dump());
            return;
        }

        audit_workspace_event(deps, "admin.workspace_member_removed", "ok", {
            {"workspace_id", workspace_id},
            {"target_fp", fp},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace", workspace_to_admin_json(*w2, deps.users_path)}
        }.dump());
    });
    // POST /api/v4/admin/workspaces/members/set_role
    //
    // Changes a member's workspace role, but refuses to demote the last enabled
    // owner away from owner role.
    srv.Post("/api/v4/admin/workspaces/members/set_role",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!deps.require_admin_cookie_users_actor ||
            !deps.require_admin_cookie_users_actor(
                req, res, deps.cookie_key, deps.users_path, deps.users, &actor_fp)) {
            return;
        }
        if (!require_same_origin_for_cookie_mutation_admin_ws_deps(req, res, deps)) return;
        res.set_header("Cache-Control", "no-store");

        if (!reload_workspaces_or_500(deps, res)) return;

        json j;
        try {
            j = json::parse(req.body);
        } catch (...) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
        const std::string fp = trim_copy_safe(j.value("fingerprint", ""));
        const std::string new_role = normalize_workspace_role_copy(j.value("role", "viewer"));

        if (workspace_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        if (fp.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing fingerprint"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        auto mopt = workspace_member_get(*wopt, fp);
        if (!mopt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "member not found"}
            }.dump());
            return;
        }

        if (mopt->status == "enabled" && mopt->role == "owner" &&
            new_role != "owner" && count_enabled_owners(*wopt) <= 1) {
            audit_workspace_event(deps, "admin.workspace_member_role_refused", "fail", {
                {"reason", "last_enabled_owner"},
                {"workspace_id", workspace_id},
                {"target_fp", fp},
                {"requested_role", new_role},
                {"actor_fp", actor_fp}
            });

            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "last_enabled_owner"},
                {"message", "cannot demote the last enabled owner"}
            }.dump());
            return;
        }

        if (!deps.workspaces->set_member_role(workspace_id, fp, new_role)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to update workspace member role"}
            }.dump());
            return;
        }

        auto w2 = deps.workspaces->get(workspace_id);
        if (!w2.has_value() || !deps.workspaces->save(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save workspaces"}
            }.dump());
            return;
        }

        audit_workspace_event(deps, "admin.workspace_member_role_changed", "ok", {
            {"workspace_id", workspace_id},
            {"target_fp", fp},
            {"role", new_role},
            {"actor_fp", actor_fp}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace", workspace_to_admin_json(*w2, deps.users_path)}
        }.dump());
    });
}

} // namespace pqnas