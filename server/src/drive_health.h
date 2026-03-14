#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pqnas {

    struct DriveHealthInfo {
        std::string name;
        std::string dev;
        std::string kind;       // "nvme" | "ssd" | "hdd" | "unknown"
        std::string transport;  // "nvme" | "sata" | "scsi" | ...
        bool rota = false;

        std::string model;
        std::string serial;
        std::string firmware;
        std::uint64_t size_bytes = 0;

        bool smart_available = false;
        bool smart_enabled = false;

        std::string health_status; // "ok" | "warn" | "fail" | "unknown"
        std::string health_text;

        int temperature_c = -1;
        long long power_on_hours = -1;

        long long percentage_used = -1;
        long long available_spare = -1;
        long long available_spare_threshold = -1;
        long long media_errors = -1;
        long long unsafe_shutdowns = -1;
        long long num_err_log_entries = -1;

        bool selftest_supported = false;
        std::string selftest_status; // "unsupported" | "idle" | "running" | "completed" | "failed" | "unknown"
        std::string selftest_text;

        std::string warning;
        std::vector<std::string> messages;
    };

    bool probe_drive_health(std::vector<DriveHealthInfo>* out, std::string* err);

} // namespace pqnas