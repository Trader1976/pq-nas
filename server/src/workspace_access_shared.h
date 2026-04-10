#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "storage_resolver.h"
#include "workspaces.h"

namespace pqnas {

struct WorkspaceResolvedTarget {
    WorkspaceMemberRec member{};
    std::string rel_norm;
    std::filesystem::path ws_root;
    std::filesystem::path abs_path;
    bool exists = false;
    bool is_file = false;
    bool is_dir = false;
};

std::optional<WorkspaceMemberRec> workspace_enabled_member_for_actor(
    const WorkspaceRec& w,
    const std::string& actor_fp);

bool workspace_member_can_write(const WorkspaceMemberRec& m);

std::filesystem::path workspace_default_root_from_users_path(
    const std::string& users_path,
    const WorkspaceRec& w);

// Resolves a workspace path without requiring a member check.
// Intended for public/share-token resolution.
bool resolve_workspace_target_default_pool_only(
    const std::string& users_path,
    const WorkspaceRec& w,
    const std::string& path_rel,
    WorkspaceResolvedTarget* out,
    std::string* err);

// Resolves a workspace path and also checks enabled membership.
// If require_write=true, actor must be owner/editor.
bool resolve_workspace_member_target_default_pool_only(
    const std::string& users_path,
    const WorkspaceRec& w,
    const std::string& actor_fp,
    bool require_write,
    const std::string& path_rel,
    WorkspaceResolvedTarget* out,
    std::string* err);

} // namespace pqnas