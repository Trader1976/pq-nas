// ============================================================================
// server/src/workspaces.h
// ============================================================================

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas {

using json = nlohmann::json;

struct WorkspaceMemberRec {
    std::string fingerprint;
    std::string role;      // owner | editor | viewer
    std::string status;    // enabled | disabled
    std::string added_at;
    std::string added_by;
};

struct WorkspaceRec {
    std::string workspace_id;
    std::string name;
    std::string status;    // enabled | disabled
    std::string notes;

    std::string created_at;
    std::string created_by;

    std::string storage_state;     // allocated | unallocated
    std::string storage_pool_id;   // "" means default
    std::string root_rel;
    std::uint64_t quota_bytes = 0;
    std::string storage_set_at;
    std::string storage_set_by;

    std::vector<WorkspaceMemberRec> members;
};

class WorkspacesRegistry {
public:
    bool load(const std::string& path);
    bool save(const std::string& path) const;

    bool exists(const std::string& workspace_id) const;
    std::optional<WorkspaceRec> get(const std::string& workspace_id) const;

    bool upsert(const WorkspaceRec& rec);
    bool erase(const std::string& workspace_id);

    const std::map<std::string, WorkspaceRec>& snapshot() const;

    std::vector<WorkspaceRec> list_for_member(const std::string& fingerprint) const;
    std::optional<WorkspaceMemberRec> get_member(const std::string& workspace_id,
                                                 const std::string& fingerprint) const;

    bool add_or_update_member(const std::string& workspace_id,
                              const WorkspaceMemberRec& member);

    bool remove_member(const std::string& workspace_id,
                       const std::string& fingerprint);

    bool set_member_role(const std::string& workspace_id,
                         const std::string& fingerprint,
                         const std::string& role);

    bool has_enabled_owner(const std::string& workspace_id) const;
    std::size_t enabled_member_count(const std::string& workspace_id) const;

private:
    std::map<std::string, WorkspaceRec> by_id_;
};

// ----- normalization / conversion helpers -----------------------------------

std::string normalize_workspace_status_copy(const std::string& s);
std::string normalize_workspace_role_copy(const std::string& s);
std::string normalize_workspace_member_status_copy(const std::string& s);
std::string normalize_workspace_storage_state_copy(const std::string& s);

void normalize_workspace_member_v1(WorkspaceMemberRec* m);
void normalize_workspace_rec_v1(WorkspaceRec* w);
void ensure_workspaces_cfg_shape_v1(json* cfg);

WorkspaceMemberRec workspace_member_from_json_v1(const json& j);
json workspace_member_to_json_v1(const WorkspaceMemberRec& m);

WorkspaceRec workspace_from_json_v1(const json& j);
json workspace_to_json_v1(const WorkspaceRec& w);

// ----- id / root helpers -----------------------------------------------------

bool is_valid_workspace_id(const std::string& workspace_id);
std::string new_workspace_id();
std::string default_workspace_root_rel_for_id(const std::string& workspace_id);

// ----- accounting helpers ----------------------------------------------------

std::uint64_t sum_allocated_workspace_quota_on_pool(const WorkspacesRegistry& workspaces,
                                                    const std::string& want_pool_id,
                                                    const std::string& exclude_workspace_id);

} // namespace pqnas