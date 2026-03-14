#pragma once

#include "drive_health.h"

#include <functional>
#include <string>
#include <vector>

namespace pqnas {

    struct DriveHealthCache {
        std::string updated_iso;
        std::vector<DriveHealthInfo> drives;
        std::string last_error;
        bool ready = false;
    };

    using DriveHealthAuditFn = std::function<void(const DriveHealthInfo& drive,
                                                  const std::string& prev_status,
                                                  const std::string& new_status)>;

    void drive_health_monitor_start(DriveHealthAuditFn audit_cb);
    void drive_health_monitor_stop();

    bool drive_health_monitor_refresh_now(std::string* err);
    DriveHealthCache drive_health_monitor_snapshot();

} // namespace pqnas