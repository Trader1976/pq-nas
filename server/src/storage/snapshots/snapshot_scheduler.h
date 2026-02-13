#pragma once
#include <atomic>
#include <string>
#include <thread>

namespace pqnas::snapshots {
    std::thread start_snapshot_scheduler(
        const std::string& admin_settings_path,
        std::atomic<bool>& stop_flag);
}
