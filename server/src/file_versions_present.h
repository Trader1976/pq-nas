#pragma once

#include <string>

namespace pqnas {

    inline std::string version_actor_display(const std::string& actor_name_snapshot,
                                             const std::string& actor_fp) {
        if (!actor_name_snapshot.empty()) return actor_name_snapshot;
        if (actor_fp.empty()) return "";

        if (actor_fp.size() <= 16) return actor_fp;
        return actor_fp.substr(0, 16) + "...";
    }

} // namespace pqnas