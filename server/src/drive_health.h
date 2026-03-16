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
        long long data_units_read = -1;
        long long data_units_written = -1;
        long long host_reads = -1;
        long long host_writes = -1;

        long long reallocated_sectors = -1;
        long long current_pending_sectors = -1;
        long long offline_uncorrectable = -1;
        long long reported_uncorrect = -1;
        long long udma_crc_errors = -1;

        int selftest_short_minutes = -1;
        int selftest_extended_minutes = -1;

        bool selftest_supported = false;
        std::string selftest_status; // "unsupported" | "idle" | "running" | "completed" | "failed" | "unknown"
        std::string selftest_text;

        int selftest_progress_pct = -1; // 0..100 when known, else -1

        std::string warning;
        std::vector<std::string> messages;
    };

    // Starts a self-test for a known internal drive.
    // type: "short" | "extended"
    bool start_drive_selftest(const std::string& dev,
                              const std::string& type,
                              std::string* err);

    bool probe_drive_health(std::vector<DriveHealthInfo>* out, std::string* err);

} // namespace pqnas