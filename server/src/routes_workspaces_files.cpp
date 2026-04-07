#include "routes_workspaces_files.h"

#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <system_error>

#include "storage_resolver.h"
#include "user_quota.h"

namespace pqnas {

namespace {

std::string trim_copy_safe(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::filesystem::path default_data_root_from_users_path(const std::string& users_path) {
    const std::filesystem::path up(users_path);
    return up.parent_path().parent_path() / "data";
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

std::optional<WorkspaceMemberRec> enabled_member_for_actor(const WorkspaceRec& w,
                                                           const std::string& actor_fp) {
    const std::string fp = trim_copy_safe(actor_fp);
    if (fp.empty()) return std::nullopt;

    for (const auto& m : w.members) {
        if (m.fingerprint == fp && m.status == "enabled") {
            return m;
        }
    }

    return std::nullopt;
}

    std::optional<WorkspaceMemberRec> invited_member_for_actor(const WorkspaceRec& w,
                                                               const std::string& actor_fp) {
    const std::string fp = trim_copy_safe(actor_fp);
    if (fp.empty()) return std::nullopt;

    for (const auto& m : w.members) {
        if (m.fingerprint == fp && m.status == "invited") {
            return m;
        }
    }

    return std::nullopt;
}

    std::string iso_utc_from_epoch_sec(std::int64_t epoch_sec) {
    if (epoch_sec < 0) epoch_sec = 0;

    std::time_t tt = static_cast<std::time_t>(epoch_sec);
    std::tm tm{};

#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    if (!gmtime_r(&tt, &tm)) return "";
#endif

    char buf[32] = {0};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) return "";
    return std::string(buf);
}

json workspace_to_user_json(const WorkspaceRec& w,
                            const WorkspaceMemberRec& actor_member,
                            const std::string& users_path) {
    json out = json::object();

    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["notes"] = w.notes;
    out["status"] = w.status;

    out["role"] = actor_member.role;

    out["quota_bytes"] = w.quota_bytes;
    out["storage_state"] = w.storage_state;
    out["storage_pool_id"] = w.storage_pool_id;
    out["pool_id"] = w.storage_pool_id.empty() ? "default" : w.storage_pool_id;
    out["root_rel"] = w.root_rel;

    out["member_count"] = static_cast<unsigned long long>(w.members.size());

    std::uint64_t used_bytes = 0;
    if (w.storage_state == "allocated" && w.storage_pool_id.empty() && !w.root_rel.empty()) {
        const std::filesystem::path abs =
            default_data_root_from_users_path(users_path) / w.root_rel;
        used_bytes = dir_size_bytes_best_effort_local(abs);
    }
    out["storage_used_bytes"] = used_bytes;

    return out;
}
    json workspace_member_to_user_json(const WorkspaceMemberRec& m) {
    json out = json::object();

    out["fingerprint"] = m.fingerprint;
    out["role"] = m.role;
    out["status"] = m.status;
    out["added_at"] = m.added_at;
    out["added_by"] = m.added_by;
    out["responded_at"] = m.responded_at;
    out["responded_by"] = m.responded_by;

    return out;
}

    json workspace_invitation_to_user_json(const WorkspaceRec& w,
                                           const WorkspaceMemberRec& actor_member) {
    json out = json::object();

    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["notes"] = w.notes;
    out["status"] = actor_member.status;
    out["role"] = actor_member.role;
    out["added_at"] = actor_member.added_at;
    out["added_by"] = actor_member.added_by;

    return out;
}
std::filesystem::path workspace_dir_for_default_pool_only(const std::string& users_path,
                                                          const WorkspaceRec& w) {
    return default_data_root_from_users_path(users_path) / w.root_rel;
}
    std::string random_urlsafe_token(std::size_t n) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 63);

    std::string out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kAlphabet[dist(gen)]);
    }
    return out;
}

    bool any_file_ancestor_exists_physical(const std::filesystem::path& root,
                                           const std::string& rel_norm,
                                           std::string* found_rel) {
    if (found_rel) found_rel->clear();

    std::filesystem::path cur = root;
    std::filesystem::path relp(rel_norm);

    std::vector<std::filesystem::path> parts;
    for (const auto& p : relp) {
        if (!p.empty()) parts.push_back(p);
    }

    if (parts.size() <= 1) return false;

    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        cur /= parts[i];

        std::error_code ec;
        auto st = std::filesystem::status(cur, ec);
        if (ec) continue;

        if (std::filesystem::exists(st) && std::filesystem::is_regular_file(st)) {
            if (found_rel) {
                std::error_code ec2;
                *found_rel = cur.lexically_relative(root).string();
                if (ec2) *found_rel = cur.filename().string();
            }
            return true;
        }
    }

    return false;
}
} // namespace

void register_workspace_file_routes(httplib::Server& srv,
                                    const WorkspaceFileRouteDeps& deps) {
    srv.Get("/api/v4/workspaces",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        if (!deps.workspaces->load(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        json out;
        out["ok"] = true;
        out["actor_fp"] = actor_fp;
        out["workspaces"] = json::array();

        for (const auto& kv : deps.workspaces->snapshot()) {
            const auto& w = kv.second;

            if (w.status != "enabled") continue;

            auto mopt = enabled_member_for_actor(w, actor_fp);
            if (!mopt.has_value()) continue;

            out["workspaces"].push_back(
                workspace_to_user_json(w, *mopt, deps.users_path));
        }

        deps.reply_json(res, 200, out.dump());
    });

    srv.Get("/api/v4/workspaces/members",
        [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    if (!deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    const std::string workspace_id =
        req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

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

    const WorkspaceRec& w = *wopt;

    if (w.status != "enabled") {
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace disabled"}
        }.dump());
        return;
    }

    auto mopt = enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) {
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace access denied"}
        }.dump());
        return;
    }

    json out;
    out["ok"] = true;
    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["role"] = mopt->role;
    out["members"] = json::array();

    for (const auto& m : w.members) {
        out["members"].push_back(workspace_member_to_user_json(m));
    }

    deps.reply_json(res, 200, out.dump());
});
    srv.Get("/api/v4/workspaces/invitations",
        [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    if (!deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    json out;
    out["ok"] = true;
    out["actor_fp"] = actor_fp;
    out["invitations"] = json::array();

    for (const auto& kv : deps.workspaces->snapshot()) {
        const auto& w = kv.second;

        if (w.status != "enabled") continue;

        auto mopt = invited_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) continue;

        out["invitations"].push_back(
            workspace_invitation_to_user_json(w, *mopt));
    }

    deps.reply_json(res, 200, out.dump());
});
    srv.Post("/api/v4/workspaces/invitations/accept",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    auto audit_fail = [&](const std::string& workspace_id,
                          const std::string& reason,
                          int http,
                          const std::string& detail = "") {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
        f["reason"] = reason;
        f["http"] = std::to_string(http);
        if (!detail.empty()) f["detail"] = detail;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_accept_fail", "fail", f);
    };

    auto audit_ok = [&](const std::string& workspace_id) {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        f["workspace_id"] = workspace_id;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_accept_ok", "ok", f);
    };

    json j;
    try {
        j = req.body.empty() ? json::object() : json::parse(req.body);
    } catch (...) {
        audit_fail("", "bad_json", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        audit_fail("", "missing_workspace_id", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (!deps.workspaces->load(deps.workspaces_path)) {
        audit_fail(workspace_id, "workspaces_reload_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        audit_fail(workspace_id, "workspace_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    const WorkspaceRec& w = *wopt;
    if (w.status != "enabled") {
        audit_fail(workspace_id, "workspace_disabled", 403);
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace disabled"}
        }.dump());
        return;
    }

    auto mopt = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!mopt.has_value() || mopt->status != "invited") {
        audit_fail(workspace_id, "invitation_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace invitation not found"}
        }.dump());
        return;
    }

    const std::string now_iso =
        iso_utc_from_epoch_sec(deps.now_epoch_sec ? deps.now_epoch_sec() : 0);

    if (!deps.workspaces->set_member_status(workspace_id, actor_fp, "enabled", now_iso, actor_fp)) {
        audit_fail(workspace_id, "set_member_status_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to accept invitation"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_fail(workspace_id, "save_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    auto w2 = deps.workspaces->get(workspace_id);
    auto m2 = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!w2.has_value() || !m2.has_value()) {
        audit_fail(workspace_id, "reload_after_accept_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to reload accepted workspace"}
        }.dump());
        return;
    }

    audit_ok(workspace_id);

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace", workspace_to_user_json(*w2, *m2, deps.users_path)}
    }.dump());
});
    srv.Post("/api/v4/workspaces/invitations/decline",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    auto audit_fail = [&](const std::string& workspace_id,
                          const std::string& reason,
                          int http,
                          const std::string& detail = "") {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
        f["reason"] = reason;
        f["http"] = std::to_string(http);
        if (!detail.empty()) f["detail"] = detail;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_decline_fail", "fail", f);
    };

    auto audit_ok = [&](const std::string& workspace_id) {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        f["workspace_id"] = workspace_id;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_decline_ok", "ok", f);
    };

    json j;
    try {
        j = req.body.empty() ? json::object() : json::parse(req.body);
    } catch (...) {
        audit_fail("", "bad_json", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        audit_fail("", "missing_workspace_id", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (!deps.workspaces->load(deps.workspaces_path)) {
        audit_fail(workspace_id, "workspaces_reload_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        audit_fail(workspace_id, "workspace_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    auto mopt = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!mopt.has_value() || mopt->status != "invited") {
        audit_fail(workspace_id, "invitation_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace invitation not found"}
        }.dump());
        return;
    }

    const std::string now_iso =
        iso_utc_from_epoch_sec(deps.now_epoch_sec ? deps.now_epoch_sec() : 0);

    if (!deps.workspaces->set_member_status(workspace_id, actor_fp, "disabled", now_iso, actor_fp)) {
        audit_fail(workspace_id, "set_member_status_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to decline invitation"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_fail(workspace_id, "save_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    audit_ok(workspace_id);

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace_id", workspace_id},
        {"status", "disabled"}
    }.dump());
});

    // GET /api/v4/workspaces/files/list?workspace_id=...&path=relative/dir
    // v1: physical filesystem only, no metadata-index merge yet
    srv.Get("/api/v4/workspaces/files/list",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_list_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_dir,
                            std::size_t count) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_dir;
            f["count"] = std::to_string(static_cast<unsigned long long>(count));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_list_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail("workspace_not_found", 404, workspace_id);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail("workspace_disabled", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail("workspace_access_denied", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail("pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace list currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_dir;
        if (req.has_param("path")) rel_dir = req.get_param_value("path");

        std::string rel_dir_norm;
        std::filesystem::path abs_dir = workspace_dir_for_default_pool_only(deps.users_path, w);

        if (!rel_dir.empty()) {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_dir, &rel_dir_norm, &nerr)) {
                audit_fail("invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }

            std::string perr;
            const std::filesystem::path ws_root = workspace_dir_for_default_pool_only(deps.users_path, w);
            if (!pqnas::resolve_user_path_strict(ws_root, rel_dir_norm, &abs_dir, &perr)) {
                audit_fail("invalid_path", 400, perr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        struct ListedItem {
            std::string name;
            std::string type;
            std::uint64_t size_bytes = 0;
            long long mtime_unix = 0;
        };

        std::map<std::string, ListedItem> merged;

        bool dir_ok = false;
        {
            std::error_code ec;
            auto st = std::filesystem::status(abs_dir, ec);

            if (!ec && std::filesystem::exists(st) && std::filesystem::is_directory(st)) {
                dir_ok = true;

                for (std::filesystem::directory_iterator it(abs_dir, ec), end; it != end && !ec; it.increment(ec)) {
                    std::error_code ec2;

                    const auto name = it->path().filename().string();
                    if (name == "." || name == ".." || name.empty()) continue;
                    if (name == ".pqnas") continue;

                    std::string type = "other";
                    if (it->is_directory(ec2) && !ec2) {
                        type = "dir";
                    } else {
                        ec2.clear();
                        if (it->is_regular_file(ec2) && !ec2) {
                            type = "file";
                        } else {
                            continue;
                        }
                    }

                    std::uint64_t size_bytes = 0;
                    if (type == "file") {
                        ec2.clear();
                        auto sz = it->file_size(ec2);
                        if (!ec2) size_bytes = static_cast<std::uint64_t>(sz);
                    }

                    long long mtime_unix = 0;
                    ec2.clear();
                    auto ft = it->last_write_time(ec2);
                    if (!ec2) {
                        using namespace std::chrono;
                        auto sctp = time_point_cast<system_clock::duration>(
                            ft - decltype(ft)::clock::now() + system_clock::now()
                        );
                        mtime_unix = static_cast<long long>(
                            duration_cast<seconds>(sctp.time_since_epoch()).count());
                    }

                    merged[name] = ListedItem{
                        name,
                        type,
                        size_bytes,
                        mtime_unix
                    };
                }
            }
        }

        if (!dir_ok && !rel_dir_norm.empty()) {
            audit_fail("not_found", 404, rel_dir_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "directory not found"}
            }.dump());
            return;
        }

        json out;
        out["ok"] = true;
        out["workspace_id"] = workspace_id;
        out["path"] = rel_dir_norm.empty() ? rel_dir : rel_dir_norm;
        out["items"] = json::array();

        std::size_t count = 0;
        for (const auto& kv : merged) {
            out["items"].push_back(json{
                {"name", kv.second.name},
                {"type", kv.second.type},
                {"size_bytes", kv.second.size_bytes},
                {"mtime_unix", kv.second.mtime_unix}
            });
            ++count;
            if (count >= 5000) break;
        }

        audit_ok(workspace_id, rel_dir_norm.empty() ? rel_dir : rel_dir_norm, count);
        deps.reply_json(res, 200, out.dump());
    });
    // POST /api/v4/workspaces/files/mkdir?workspace_id=...&path=relative/dir
    srv.Post("/api/v4/workspaces/files/mkdir",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_mkdir_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_mkdir_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");

        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may create directories
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace mkdir currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_norm;
        std::string nerr;
        if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
            audit_fail(workspace_id, "invalid_path", 400, nerr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_dir;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_dir, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(abs_dir, ec);
        if (ec) {
            audit_fail(workspace_id, "mkdir_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create directory"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        audit_ok(workspace_id, rel_norm);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm}
        }.dump());
    });
        // PUT /api/v4/workspaces/files/put?workspace_id=...&path=relative/path.bin[&overwrite=1]
    // Body: raw bytes streamed to temp file, then renamed atomically
    srv.Put("/api/v4/workspaces/files/put",
            [&](const httplib::Request& req,
                httplib::Response& res,
                const httplib::ContentReader& content_reader) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto header_u64 = [&](const char* name, std::uint64_t* out) -> bool {
            if (!out) return false;
            auto it = req.headers.find(name);
            if (it == req.headers.end()) return false;
            const std::string& s = it->second;
            try {
                std::size_t idx = 0;
                unsigned long long v = std::stoull(s, &idx, 10);
                if (idx != s.size()) return false;
                *out = static_cast<std::uint64_t>(v);
                return true;
            } catch (...) {
                return false;
            }
        };

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_put_fail", "fail", f);
        };

        auto audit_quota_deny = [&](const std::string& workspace_id,
                                    const std::string& rel_path,
                                    std::uint64_t used_bytes,
                                    std::uint64_t quota_bytes,
                                    std::uint64_t incoming_bytes,
                                    std::uint64_t existing_bytes,
                                    std::uint64_t would_used_bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["used_bytes"] = std::to_string(static_cast<unsigned long long>(used_bytes));
            f["quota_bytes"] = std::to_string(static_cast<unsigned long long>(quota_bytes));
            f["incoming_bytes"] = std::to_string(static_cast<unsigned long long>(incoming_bytes));
            f["existing_bytes"] = std::to_string(static_cast<unsigned long long>(existing_bytes));
            f["would_used_bytes"] = std::to_string(static_cast<unsigned long long>(would_used_bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace_quota_exceeded", "deny", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_put_ok", "ok", f);
        };

        auto file_time_to_epoch_sec = [](const std::filesystem::file_time_type& ft) -> std::int64_t {
            using namespace std::chrono;
            const auto sctp = time_point_cast<system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now() + system_clock::now()
            );
            return static_cast<std::int64_t>(
                duration_cast<seconds>(sctp.time_since_epoch()).count());
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may upload
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace put currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        bool overwrite = false;
        if (req.has_param("overwrite")) {
            const std::string ov = req.get_param_value("overwrite");
            overwrite = (ov == "1" || ov == "true" || ov == "yes");
        }

        std::uint64_t cl = 0;
        if (!header_u64("Content-Length", &cl)) {
            audit_fail(workspace_id, "missing_content_length", 411);
            deps.reply_json(res, 411, json{
                {"ok", false},
                {"error", "length_required"},
                {"message", "Content-Length required"}
            }.dump());
            return;
        }

        const std::uint64_t incoming_bytes = cl;
        const std::uint64_t transport_max =
            (deps.transport_max_upload_bytes ? deps.transport_max_upload_bytes
                                             : deps.payload_max_upload_bytes);

        if (incoming_bytes > transport_max) {
            audit_fail(workspace_id, "transport_limit_exceeded", 413,
                       "Content-Length=" + std::to_string(static_cast<unsigned long long>(incoming_bytes)) +
                       " max=" + std::to_string(static_cast<unsigned long long>(transport_max)));
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "transport_limit_exceeded"},
                {"message", "Upload exceeds maximum allowed size"},
                {"content_length", incoming_bytes},
                {"max_bytes", transport_max},
                {"payload_max_upload_bytes", deps.payload_max_upload_bytes}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path out_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &out_abs, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        {
            std::string found_ancestor;
            if (any_file_ancestor_exists_physical(ws_root, rel_norm, &found_ancestor)) {
                audit_fail(workspace_id, "ancestor_is_file", 409, found_ancestor);
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "a parent path is an existing file"},
                    {"ancestor", found_ancestor}
                }.dump());
                return;
            }
        }

        // quota check
        const std::uint64_t used_bytes = dir_size_bytes_best_effort_local(ws_root);
        const std::uint64_t existing_bytes = pqnas::file_size_u64_safe(out_abs);

        std::uint64_t would_used_bytes = used_bytes;
        if (existing_bytes <= would_used_bytes) {
            would_used_bytes -= existing_bytes;
        }
        would_used_bytes += incoming_bytes;

        if (w.quota_bytes == 0) {
            if (incoming_bytes > 0) {
                audit_quota_deny(workspace_id, rel_norm, used_bytes, w.quota_bytes,
                                 incoming_bytes, existing_bytes, would_used_bytes);
                deps.reply_json(res, 413, json{
                    {"ok", false},
                    {"error", "quota_exceeded"},
                    {"message", "Quota exceeded"},
                    {"workspace_id", workspace_id},
                    {"used_bytes", used_bytes},
                    {"quota_bytes", w.quota_bytes},
                    {"incoming_bytes", incoming_bytes},
                    {"existing_bytes", existing_bytes},
                    {"would_used_bytes", would_used_bytes}
                }.dump());
                return;
            }
        } else if (would_used_bytes > w.quota_bytes) {
            audit_quota_deny(workspace_id, rel_norm, used_bytes, w.quota_bytes,
                             incoming_bytes, existing_bytes, would_used_bytes);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "Quota exceeded"},
                {"workspace_id", workspace_id},
                {"used_bytes", used_bytes},
                {"quota_bytes", w.quota_bytes},
                {"incoming_bytes", incoming_bytes},
                {"existing_bytes", existing_bytes},
                {"would_used_bytes", would_used_bytes}
            }.dump());
            return;
        }

        bool physical_exists = false;
        std::uint64_t physical_existing_size = 0;
        std::int64_t physical_existing_mtime = 0;

        {
            std::error_code ec;
            physical_exists = std::filesystem::exists(out_abs, ec);
            if (ec) {
                audit_fail(workspace_id, "target_exists_check_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "target existence check failed"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }

            if (physical_exists) {
                const bool is_reg = std::filesystem::is_regular_file(out_abs, ec);
                if (ec) {
                    audit_fail(workspace_id, "target_stat_failed", 500, ec.message());
                    deps.reply_json(res, 500, json{
                        {"ok", false},
                        {"error", "server_error"},
                        {"message", "target stat failed"},
                        {"detail", ec.message()}
                    }.dump());
                    return;
                }

                if (!is_reg) {
                    audit_fail(workspace_id, "target_not_regular_file", 409, out_abs.string());
                    deps.reply_json(res, 409, json{
                        {"ok", false},
                        {"error", "path_conflict"},
                        {"message", "target path exists and is not a regular file"},
                        {"path", rel_norm}
                    }.dump());
                    return;
                }

                physical_existing_size = pqnas::file_size_u64_safe(out_abs);
                auto ft = std::filesystem::last_write_time(out_abs, ec);
                if (!ec) {
                    physical_existing_mtime = file_time_to_epoch_sec(ft);
                }
            }
        }

        if (!overwrite && physical_exists) {
            json existing = json::object();
            existing["size_bytes"] = physical_existing_size;
            existing["mtime_epoch"] = physical_existing_mtime;
            existing["physical_path"] = out_abs.string();

            audit_fail(workspace_id, "file_exists", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "file_exists"},
                {"message", "file already exists"},
                {"path", rel_norm},
                {"existing", existing}
            }.dump());
            return;
        }

        {
            std::error_code ec;
            std::filesystem::create_directories(out_abs.parent_path(), ec);
            if (ec) {
                audit_fail(workspace_id, "mkdir_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to create directories"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
        }

        const std::filesystem::path tmp =
            out_abs.parent_path() /
            (out_abs.filename().string() + ".upload." + random_urlsafe_token(8) + ".tmp");

        std::uint64_t bytes_written = 0;
        bool stream_ok = true;
        std::string stream_err;

        try {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f.good()) {
                throw std::runtime_error("open tmp failed");
            }

            content_reader([&](const char* data, size_t len) {
                if (!stream_ok) return false;
                if (len == 0) return true;

                const std::uint64_t chunk = static_cast<std::uint64_t>(len);
                const std::uint64_t next = bytes_written + chunk;

                if (next < bytes_written) {
                    stream_ok = false;
                    stream_err = "byte_count_overflow";
                    return false;
                }

                if (next > incoming_bytes) {
                    stream_ok = false;
                    stream_err = "content_length_exceeded";
                    return false;
                }

                if (next > transport_max) {
                    stream_ok = false;
                    stream_err = "transport_limit_exceeded";
                    return false;
                }

                f.write(data, static_cast<std::streamsize>(len));
                if (!f.good()) {
                    stream_ok = false;
                    stream_err = "write_tmp_failed";
                    return false;
                }

                bytes_written = next;
                return true;
            });

            f.flush();
            if (!f.good()) {
                throw std::runtime_error("write tmp failed");
            }
            f.close();

            if (!stream_ok) {
                std::error_code ec;
                std::filesystem::remove(tmp, ec);

                const int http = (stream_err == "transport_limit_exceeded") ? 413 : 400;
                audit_fail(workspace_id, stream_err, http);

                deps.reply_json(res, http, json{
                    {"ok", false},
                    {"error", (stream_err == "transport_limit_exceeded") ? "transport_limit_exceeded" : "bad_request"},
                    {"message", stream_err},
                    {"content_length", incoming_bytes},
                    {"bytes_written", bytes_written}
                }.dump());
                return;
            }

            if (bytes_written != incoming_bytes) {
                std::error_code ec;
                std::filesystem::remove(tmp, ec);

                audit_fail(workspace_id, "content_length_mismatch", 400,
                           "Content-Length=" + std::to_string(static_cast<unsigned long long>(incoming_bytes)) +
                           " written=" + std::to_string(static_cast<unsigned long long>(bytes_written)));

                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "Content-Length mismatch"},
                    {"content_length", incoming_bytes},
                    {"bytes_written", bytes_written}
                }.dump());
                return;
            }

            std::error_code rename_ec;
            std::filesystem::rename(tmp, out_abs, rename_ec);
            if (rename_ec) {
                std::error_code rm_ec;
                std::filesystem::remove(tmp, rm_ec);
                throw std::runtime_error(std::string("rename failed: ") + rename_ec.message());
            }

            audit_ok(workspace_id, rel_norm, bytes_written);

            deps.reply_json(res, 200, json{
                {"ok", true},
                {"workspace_id", workspace_id},
                {"path", rel_norm},
                {"bytes", bytes_written},
                {"overwrite", overwrite}
            }.dump());
            return;

        } catch (const std::exception& e) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);

            audit_fail(workspace_id, "write_failed", 500, e.what());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "upload failed"},
                {"detail", e.what()}
            }.dump());
            return;
        }
    });
    // GET /api/v4/workspaces/files/get?workspace_id=...&path=relative/file.bin
    // v1: physical filesystem only, reads file into memory before reply
    srv.Get("/api/v4/workspaces/files/get",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_get_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_get_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace get currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_path;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!exists) {
            audit_fail(workspace_id, "not_found", 404, rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "file not found"}
            }.dump());
            return;
        }

        const bool is_reg = std::filesystem::is_regular_file(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!is_reg) {
            audit_fail(workspace_id, "not_regular_file", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "target path is not a regular file"},
                {"path", rel_norm}
            }.dump());
            return;
        }

        std::ifstream f(abs_path, std::ios::binary);
        if (!f.good()) {
            audit_fail(workspace_id, "open_failed", 500, abs_path.string());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to open file"}
            }.dump());
            return;
        }

        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        if (!f.good() && !f.eof()) {
            audit_fail(workspace_id, "read_failed", 500, abs_path.string());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read file"}
            }.dump());
            return;
        }

        const auto filename = abs_path.filename().string();
        res.set_header("Content-Disposition",
                       "inline; filename=\"" + filename + "\"");
        res.set_content(body, "application/octet-stream");

        audit_ok(workspace_id, rel_norm, static_cast<std::uint64_t>(body.size()));
    });
        // POST /api/v4/workspaces/files/delete?workspace_id=...&path=relative/path
    // v1: physical filesystem only, allows file delete and recursive directory delete
    srv.Post("/api/v4/workspaces/files/delete",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_delete_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t removed_count) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["removed_count"] = std::to_string(static_cast<unsigned long long>(removed_count));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_delete_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may delete
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace delete currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_path;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        // refuse deleting workspace root
        if (abs_path.lexically_normal() == ws_root.lexically_normal()) {
            audit_fail(workspace_id, "refuse_delete_root", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "refusing to delete workspace root"}
            }.dump());
            return;
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!exists) {
            audit_fail(workspace_id, "not_found", 404, rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "path not found"}
            }.dump());
            return;
        }

        std::uint64_t removed_count = 0;

        const bool is_dir = std::filesystem::is_directory(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (is_dir) {
            const auto removed = std::filesystem::remove_all(abs_path, ec);
            if (ec) {
                audit_fail(workspace_id, "remove_all_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to delete directory"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
            removed_count = static_cast<std::uint64_t>(removed);
        } else {
            const bool removed = std::filesystem::remove(abs_path, ec);
            if (ec) {
                audit_fail(workspace_id, "remove_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to delete file"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
            if (!removed) {
                audit_fail(workspace_id, "not_found", 404, rel_norm);
                deps.reply_json(res, 404, json{
                    {"ok", false},
                    {"error", "not_found"},
                    {"message", "path not found"}
                }.dump());
                return;
            }
            removed_count = 1;
        }

        audit_ok(workspace_id, rel_norm, removed_count);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"removed_count", removed_count}
        }.dump());
    });
        // POST /api/v4/workspaces/files/move?workspace_id=...&from=old/path&to=new/path
    // v1: physical filesystem only, same workspace only
    srv.Post("/api/v4/workspaces/files/move",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& from_rel = "",
                              const std::string& to_rel = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!from_rel.empty()) f["from"] = from_rel;
            if (!to_rel.empty())   f["to"]   = to_rel;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_move_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& from_rel,
                            const std::string& to_rel,
                            const std::string& type,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["from"] = from_rel;
            f["to"] = to_rel;
            f["type"] = type;
            if (type == "file") {
                f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            }
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_move_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string from_rel, to_rel;
        if (req.has_param("from")) from_rel = req.get_param_value("from");
        if (req.has_param("to"))   to_rel   = req.get_param_value("to");

        if (from_rel.empty() || to_rel.empty()) {
            audit_fail(workspace_id, "missing_from_or_to", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing from or to"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404, "", from_rel, to_rel);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may move
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role, from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace move currently supports default pool only"}
            }.dump());
            return;
        }

        std::string from_rel_norm, to_rel_norm;
        std::string nerr1, nerr2;

        if (!pqnas::normalize_user_rel_path_strict(from_rel, &from_rel_norm, &nerr1)) {
            audit_fail(workspace_id, "invalid_from_path", 400, nerr1, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid from path"}
            }.dump());
            return;
        }

        if (!pqnas::normalize_user_rel_path_strict(to_rel, &to_rel_norm, &nerr2)) {
            audit_fail(workspace_id, "invalid_to_path", 400, nerr2, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid to path"}
            }.dump());
            return;
        }

        if (from_rel_norm == to_rel_norm) {
            audit_fail(workspace_id, "same_path", 400, "", from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "from and to are the same"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path from_abs, to_abs;
        std::string perr1, perr2;

        if (!pqnas::resolve_user_path_strict(ws_root, from_rel_norm, &from_abs, &perr1)) {
            audit_fail(workspace_id, "invalid_from_path", 400, perr1, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid from path"}
            }.dump());
            return;
        }

        if (!pqnas::resolve_user_path_strict(ws_root, to_rel_norm, &to_abs, &perr2)) {
            audit_fail(workspace_id, "invalid_to_path", 400, perr2, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid to path"}
            }.dump());
            return;
        }

        {
            std::string found_ancestor;
            if (any_file_ancestor_exists_physical(ws_root, to_rel_norm, &found_ancestor)) {
                audit_fail(workspace_id, "dest_ancestor_is_file", 409, found_ancestor, from_rel, to_rel);
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "destination parent path is an existing file"},
                    {"ancestor", found_ancestor}
                }.dump());
                return;
            }
        }

        std::error_code ec;

        const bool from_exists = std::filesystem::exists(from_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "source_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "source stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!from_exists) {
            audit_fail(workspace_id, "not_found", 404, "", from_rel, to_rel);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "source not found"}
            }.dump());
            return;
        }

        const bool to_exists = std::filesystem::exists(to_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "dest_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "destination stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (to_exists) {
            audit_fail(workspace_id, "dest_exists", 409, "", from_rel, to_rel);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "dest_exists"},
                {"message", "destination already exists"}
            }.dump());
            return;
        }

        const bool src_is_dir = std::filesystem::is_directory(from_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "source_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "source stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        const bool src_is_file = std::filesystem::is_regular_file(from_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "source_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "source stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!src_is_dir && !src_is_file) {
            audit_fail(workspace_id, "unsupported_type", 400, "", from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "unsupported source type"}
            }.dump());
            return;
        }

        // Prevent moving directory into itself/subtree
        if (src_is_dir) {
            if (to_rel_norm == from_rel_norm ||
                to_rel_norm.rfind(from_rel_norm + "/", 0) == 0) {
                audit_fail(workspace_id, "dir_into_self", 400, "", from_rel, to_rel);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "cannot move a directory into itself"}
                }.dump());
                return;
            }
        }

        auto move_one_path = [&](const std::filesystem::path& src_path,
                                 const std::filesystem::path& dst_path,
                                 bool is_dir,
                                 std::string* move_err) -> bool {
            if (move_err) move_err->clear();

            std::error_code mec;
            std::filesystem::create_directories(dst_path.parent_path(), mec);
            if (mec) {
                if (move_err) *move_err = "mkdir failed: " + mec.message();
                return false;
            }

            mec.clear();
            std::filesystem::rename(src_path, dst_path, mec);
            if (!mec) return true;

            const bool is_exdev =
                (mec == std::make_error_code(std::errc::cross_device_link));

            if (!is_exdev) {
                if (move_err) *move_err = "rename failed: " + mec.message();
                return false;
            }

            std::error_code ec_copy;
            if (is_dir) {
                std::filesystem::copy(src_path, dst_path,
                                      std::filesystem::copy_options::recursive,
                                      ec_copy);
            } else {
                std::filesystem::copy_file(src_path, dst_path,
                                           std::filesystem::copy_options::none,
                                           ec_copy);
            }
            if (ec_copy) {
                if (move_err) *move_err = "copy fallback failed: " + ec_copy.message();
                return false;
            }

            std::error_code ec_rm;
            if (is_dir) std::filesystem::remove_all(src_path, ec_rm);
            else        std::filesystem::remove(src_path, ec_rm);

            if (ec_rm) {
                if (move_err) *move_err = "cleanup failed: " + ec_rm.message();
                return false;
            }

            return true;
        };

        const std::uint64_t bytes =
            src_is_file ? pqnas::file_size_u64_safe(from_abs) : 0;

        std::string move_err;
        if (!move_one_path(from_abs, to_abs, src_is_dir, &move_err)) {
            audit_fail(workspace_id, "move_failed", 500, move_err, from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "move failed"},
                {"detail", move_err}
            }.dump());
            return;
        }

        audit_ok(workspace_id, from_rel_norm, to_rel_norm, src_is_dir ? "dir" : "file", bytes);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"from", from_rel_norm},
            {"to", to_rel_norm},
            {"type", src_is_dir ? "dir" : "file"},
            {"bytes", bytes}
        }.dump());
    });
    // ---- Files API (user storage) ----

    // GET  /api/v4/workspaces/files/get
    // POST /api/v4/workspaces/files/delete
    
}

}