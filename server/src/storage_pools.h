#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace pqnas {

    using nlohmann::json;

    // Load pools.json, migrate/normalize to v3 shape in memory.
    json load_or_init_pools_cfg_v3(const std::string& users_path);

    // Write pools.json atomically after normalizing to v3 shape.
    bool write_pools_cfg_v3(const std::string& users_path, const json& cfg, std::string* err);

    // Normalize root config / single pool entries to v3.
    void ensure_pools_cfg_shape_v3(json* cfg);
    void normalize_pool_entry_v3(json* pool_obj);

    // Lookup UI display name for a mount.
    std::string pools_display_name_for_mount_v3(const json& cfg, const std::string& mount);

    // Infer simple desired mode from runtime Btrfs profiles.
    std::string pool_mode_from_profiles_best_effort(const std::string& profile_data,
                                                    const std::string& profile_meta);

    // Extract runtime member parent disks from parsed btrfs-show JSON.
    std::vector<std::string> runtime_member_parent_disks_from_show_json(const json& btrfs_show_json);

    // If config pool has no slots yet, infer them from runtime members.
    void infer_slots_from_runtime_if_missing(json* cfg_pool,
                                             const std::vector<std::string>& runtime_member_parents);

    // Merge config pool + runtime pool into one UI-friendly JSON object.
    json merge_pool_runtime_and_config(const json& cfg_pool,
                                       const json& runtime_pool,
                                       const std::vector<std::string>& runtime_member_parents,
                                       bool busy,
                                       const std::string& busy_lock);

} // namespace pqnas