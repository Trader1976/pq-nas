#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace pqnas {

    // Builds the full system snapshot JSON used by GET /api/v4/system.
    // `repo_root` is used for disk stats (repo path section).
    nlohmann::json collect_system_snapshot(const std::string& repo_root);

} // namespace pqnas
