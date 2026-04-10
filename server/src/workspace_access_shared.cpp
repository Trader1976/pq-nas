#include "workspace_access_shared.h"

#include <cctype>

#include "user_quota.h"

namespace pqnas {
namespace {

std::string trim_copy_ws_local(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::filesystem::path default_data_root_from_users_path_local(const std::string& users_path) {
    const std::filesystem::path up(users_path);
    return up.parent_path().parent_path() / "data";
}

} // namespace

std::optional<WorkspaceMemberRec> workspace_enabled_member_for_actor(
    const WorkspaceRec& w,
    const std::string& actor_fp) {

    const std::string fp = trim_copy_ws_local(actor_fp);
    if (fp.empty()) return std::nullopt;

    for (const auto& m : w.members) {
        if (m.fingerprint == fp && m.status == "enabled") {
            return m;
        }
    }

    return std::nullopt;
}

bool workspace_member_can_write(const WorkspaceMemberRec& m) {
    return m.role == "owner" || m.role == "editor";
}

std::filesystem::path workspace_default_root_from_users_path(
    const std::string& users_path,
    const WorkspaceRec& w) {
    return default_data_root_from_users_path_local(users_path) / w.root_rel;
}

bool resolve_workspace_target_default_pool_only(
    const std::string& users_path,
    const WorkspaceRec& w,
    const std::string& path_rel,
    WorkspaceResolvedTarget* out,
    std::string* err) {

    if (out) *out = WorkspaceResolvedTarget{};
    if (err) err->clear();

    if (w.status != "enabled") {
        if (err) *err = "workspace disabled";
        return false;
    }

    if (w.storage_state != "allocated") {
        if (err) *err = "workspace storage not allocated";
        return false;
    }

    if (!w.storage_pool_id.empty()) {
        if (err) *err = "pool not supported yet";
        return false;
    }

    std::string rel_norm;
    std::string nerr;
    if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
        if (err) *err = "invalid path";
        return false;
    }

    const std::filesystem::path ws_root =
        workspace_default_root_from_users_path(users_path, w);

    std::filesystem::path abs_path;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
        if (err) *err = "invalid path";
        return false;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs_path, ec);
    if (ec || !std::filesystem::exists(st)) {
        if (err) *err = "path not found";
        return false;
    }

    if (std::filesystem::is_symlink(st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }

    const bool is_file = std::filesystem::is_regular_file(st);
    const bool is_dir = std::filesystem::is_directory(st);
    if (!is_file && !is_dir) {
        if (err) *err = "unsupported path type";
        return false;
    }

    if (out) {
        out->rel_norm = rel_norm;
        out->ws_root = ws_root;
        out->abs_path = abs_path;
        out->exists = true;
        out->is_file = is_file;
        out->is_dir = is_dir;
    }

    return true;
}

bool resolve_workspace_member_target_default_pool_only(
    const std::string& users_path,
    const WorkspaceRec& w,
    const std::string& actor_fp,
    bool require_write,
    const std::string& path_rel,
    WorkspaceResolvedTarget* out,
    std::string* err) {

    if (out) *out = WorkspaceResolvedTarget{};
    if (err) err->clear();

    auto mopt = workspace_enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) {
        if (err) *err = "workspace access denied";
        return false;
    }

    if (require_write && !workspace_member_can_write(*mopt)) {
        if (err) *err = "workspace write access denied";
        return false;
    }

    WorkspaceResolvedTarget tmp;
    if (!resolve_workspace_target_default_pool_only(users_path, w, path_rel, &tmp, err)) {
        return false;
    }

    tmp.member = *mopt;

    if (out) *out = std::move(tmp);
    return true;
}

} // namespace pqnas