#include "drive_health.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

// Drive health v1
//
// This module does three things:
//
// 1) Enumerates candidate physical disks via lsblk.
// 2) Probes each disk with smartctl JSON output.
// 3) Normalizes health / warning / self-test state into DriveHealthInfo.
//
// Design notes:
// - lsblk is used only for inventory / basic identity (name, path, model,
//   serial, transport hint, size, rotational flag).
// - smartctl JSON is the source of truth for SMART health and self-test data.
// - Bus classification intentionally prefers smartctl-reported device type over
//   lsblk TRAN, because some real SATA drives expose a blank TRAN field.
// - v1 intentionally ignores removable / virtual / USB devices and focuses on
//   internal NVMe and ATA/SATA disks.

namespace pqnas {
namespace {

using json = nlohmann::json;

// Small local helpers used throughout this file.
//
// These are intentionally tiny and dependency-light because this module shells
// out to system tools (lsblk / smartctl) and then performs straightforward JSON
// parsing and normalization on the results.

static std::string trim_ws(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) a++;
    while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

// Execute a shell command and capture stdout as a single string.
//
// Notes:
// - stderr redirection is controlled by the caller in the command string.
// - rc_out receives the raw pclose() result as used elsewhere in this file.
// - This helper is intentionally simple because the surrounding code already
//   handles command-specific validation and error messaging.
static bool run_command_capture(const std::string& cmd, std::string* out, int* rc_out) {
    if (out) out->clear();
    if (rc_out) *rc_out = -1;

    FILE* fp = ::popen(cmd.c_str(), "r");
    if (!fp) return false;

    std::string buf;
    std::array<char, 4096> tmp{};
    while (std::fgets(tmp.data(), (int)tmp.size(), fp)) {
        buf.append(tmp.data());
    }

    const int rc = ::pclose(fp);
    if (out) *out = std::move(buf);
    if (rc_out) *rc_out = rc;
    return true;
}

// Very small single-quote shell escaping helper.
//
// We only use this for device paths and similar values when building commands
// for popen(). The goal is to keep shell use narrowly scoped and avoid obvious
// quoting bugs when passing /dev/... paths to smartctl.
static std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

// JSON path helpers.
//
// smartctl JSON is nested and not every field exists on every drive / bus type.
// These helpers walk a fixed object path and return a typed default if any part
// of the path is missing or of the wrong type.
static std::string j_str(const json& j, std::initializer_list<const char*> path) {
    const json* cur = &j;
    for (const char* k : path) {
        if (!cur->is_object()) return "";
        auto it = cur->find(k);
        if (it == cur->end()) return "";
        cur = &(*it);
    }
    return cur->is_string() ? cur->get<std::string>() : "";
}

static long long j_i64(const json& j, std::initializer_list<const char*> path, long long def = -1) {
    const json* cur = &j;
    for (const char* k : path) {
        if (!cur->is_object()) return def;
        auto it = cur->find(k);
        if (it == cur->end()) return def;
        cur = &(*it);
    }
    if (cur->is_number_integer()) return cur->get<long long>();
    if (cur->is_number_unsigned()) return (long long)cur->get<unsigned long long>();
    return def;
}

static bool j_bool(const json& j, std::initializer_list<const char*> path, bool def = false) {
    const json* cur = &j;
    for (const char* k : path) {
        if (!cur->is_object()) return def;
        auto it = cur->find(k);
        if (it == cur->end()) return def;
        cur = &(*it);
    }
    return cur->is_boolean() ? cur->get<bool>() : def;
}

// Extract raw ATA SMART attribute values by attribute ID.
//
// We use raw values for health/warning heuristics because the normalized VALUE /
// WORST / THRESH fields are vendor-specific and less useful for the user-facing
// summary we want to present.
static long long ata_attr_raw_value(const json& j, int attr_id, long long def = -1) {
    auto it = j.find("ata_smart_attributes");
    if (it == j.end() || !it->is_object()) return def;

    auto it_tbl = it->find("table");
    if (it_tbl == it->end() || !it_tbl->is_array()) return def;

    for (const auto& row : *it_tbl) {
        if (!row.is_object()) continue;

        auto it_id = row.find("id");
        if (it_id == row.end() || !it_id->is_number_integer()) continue;
        if (it_id->get<int>() != attr_id) continue;

        auto it_raw = row.find("raw");
        if (it_raw == row.end() || !it_raw->is_object()) return def;

        auto it_val = it_raw->find("value");
        if (it_val == it_raw->end()) return def;

        if (it_val->is_number_integer()) return it_val->get<long long>();
        if (it_val->is_number_unsigned()) return (long long)it_val->get<unsigned long long>();
        return def;
    }

    return def;
}

static bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

// Filter out pseudo / virtual block devices that should not appear in the
// internal drive-health UI.
static bool should_skip_disk_name(const std::string& name) {
    if (name.empty()) return true;
    if (starts_with(name, "loop")) return true;
    if (starts_with(name, "ram"))  return true;
    if (starts_with(name, "zram")) return true;
    if (starts_with(name, "dm-"))  return true;
    if (starts_with(name, "md"))   return true;
    return false;
}

// Minimal inventory record gathered from lsblk before probing with smartctl.
//
// lsblk gives us stable device identity and a few hints (transport, rotational,
// size), but it is not authoritative for SMART support or bus classification.
struct LsblkDisk {
    std::string name;
    std::string path;
    std::string model;
    std::string serial;
    std::string tran;
    std::uint64_t size_bytes = 0;
    bool rota = false;
};

// Build the candidate disk inventory from lsblk.
//
// We intentionally request only top-level disks (-d) and skip known virtual /
// removable devices. v1 also excludes USB so the UI focuses on internal drives.
static bool collect_lsblk_disks(std::vector<LsblkDisk>* out, std::string* err) {
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    out->clear();
    if (err) err->clear();

    std::string txt;
    int rc = -1;
    const std::string cmd = "lsblk -J -d -b -o NAME,PATH,MODEL,SERIAL,SIZE,ROTA,TYPE,TRAN";
    if (!run_command_capture(cmd, &txt, &rc)) {
        if (err) *err = "failed to execute lsblk";
        return false;
    }

    json j;
    try {
        j = json::parse(txt);
    } catch (const std::exception& e) {
        if (err) *err = std::string("failed to parse lsblk JSON: ") + e.what();
        return false;
    }

    if (!j.contains("blockdevices") || !j["blockdevices"].is_array()) {
        if (err) *err = "lsblk JSON missing blockdevices";
        return false;
    }

    for (const auto& d : j["blockdevices"]) {
        if (!d.is_object()) continue;

        const std::string type = d.contains("type") && d["type"].is_string() ? d["type"].get<std::string>() : "";
        if (type != "disk") continue;

        LsblkDisk x;
        x.name   = d.contains("name")   && d["name"].is_string()   ? d["name"].get<std::string>() : "";
        x.path   = d.contains("path")   && d["path"].is_string()   ? d["path"].get<std::string>() : "";
        x.model  = d.contains("model")  && d["model"].is_string()  ? trim_ws(d["model"].get<std::string>()) : "";
        x.serial = d.contains("serial") && d["serial"].is_string() ? trim_ws(d["serial"].get<std::string>()) : "";
        x.tran   = d.contains("tran")   && d["tran"].is_string()   ? trim_ws(d["tran"].get<std::string>()) : "";

        if (should_skip_disk_name(x.name)) continue;
        if (x.tran == "usb") continue; // v1: internal disks only

        if (d.contains("size")) {
            if (d["size"].is_number_unsigned()) x.size_bytes = d["size"].get<std::uint64_t>();
            else if (d["size"].is_number_integer()) {
                long long v = d["size"].get<long long>();
                if (v > 0) x.size_bytes = (std::uint64_t)v;
            }
        }

        if (d.contains("rota") && d["rota"].is_boolean()) x.rota = d["rota"].get<bool>();
        else if (d.contains("rota") && d["rota"].is_number_integer()) x.rota = (d["rota"].get<int>() != 0);

        if (!x.path.empty()) out->push_back(std::move(x));
    }

    return true;
}

// Preserve human-readable smartctl messages so the UI / API can expose extra
// context beyond the normalized health fields.
static void collect_smart_messages(const json& j, DriveHealthInfo* d) {
    if (!d) return;
    auto it_sc = j.find("smartctl");
    if (it_sc == j.end() || !it_sc->is_object()) return;

    auto it_msg = it_sc->find("messages");
    if (it_msg == it_sc->end() || !it_msg->is_array()) return;

    for (const auto& m : *it_msg) {
        if (!m.is_object()) continue;
        auto it_s = m.find("string");
        if (it_s != m.end() && it_s->is_string()) {
            d->messages.push_back(it_s->get<std::string>());
        }
    }
}

// Parse smartctl JSON for NVMe devices.
//
// This normalizes the NVMe-specific health model (critical warnings, spare,
// percentage used, media errors, self-test log, etc.) into the shared
// DriveHealthInfo structure used by the rest of PQ-NAS.
static void parse_nvme_smart_json(const json& j, const LsblkDisk& inv, DriveHealthInfo* d) {
    if (!d) return;

    d->name      = !inv.name.empty() ? inv.name : j_str(j, {"device", "name"});
    d->dev       = !inv.path.empty() ? inv.path : j_str(j, {"device", "name"});
    d->kind      = "nvme";
    d->transport = "nvme";
    d->rota      = false;

    d->model     = !inv.model.empty() ? inv.model : j_str(j, {"model_name"});
    d->serial    = !inv.serial.empty() ? inv.serial : j_str(j, {"serial_number"});
    d->firmware  = j_str(j, {"firmware_version"});

    long long cap = j_i64(j, {"user_capacity", "bytes"}, -1);
    if (cap < 0) cap = j_i64(j, {"nvme_total_capacity"}, -1);
    if (cap >= 0) d->size_bytes = (std::uint64_t)cap;
    else d->size_bytes = inv.size_bytes;

    d->smart_available = j_bool(j, {"smart_support", "available"}, false);
    d->smart_enabled   = j_bool(j, {"smart_support", "enabled"}, false);

    const bool passed = j_bool(j, {"smart_status", "passed"}, false);
    const long long critical_warning = j_i64(j, {"nvme_smart_health_information_log", "critical_warning"}, -1);

    d->temperature_c = (int)j_i64(j, {"temperature", "current"}, -1);
    if (d->temperature_c < 0) {
        d->temperature_c = (int)j_i64(j, {"nvme_smart_health_information_log", "temperature"}, -1);
    }

    d->power_on_hours = j_i64(j, {"power_on_time", "hours"}, -1);
    if (d->power_on_hours < 0) {
        d->power_on_hours = j_i64(j, {"nvme_smart_health_information_log", "power_on_hours"}, -1);
    }

    d->percentage_used           = j_i64(j, {"nvme_smart_health_information_log", "percentage_used"}, -1);
    d->available_spare           = j_i64(j, {"nvme_smart_health_information_log", "available_spare"}, -1);
    d->available_spare_threshold = j_i64(j, {"nvme_smart_health_information_log", "available_spare_threshold"}, -1);
    d->media_errors              = j_i64(j, {"nvme_smart_health_information_log", "media_errors"}, -1);
    d->unsafe_shutdowns          = j_i64(j, {"nvme_smart_health_information_log", "unsafe_shutdowns"}, -1);
    d->num_err_log_entries       = j_i64(j, {"nvme_smart_health_information_log", "num_err_log_entries"}, -1);
    d->data_units_read           = j_i64(j, {"nvme_smart_health_information_log", "data_units_read"}, -1);
    d->data_units_written        = j_i64(j, {"nvme_smart_health_information_log", "data_units_written"}, -1);
    d->host_reads                = j_i64(j, {"nvme_smart_health_information_log", "host_reads"}, -1);
    d->host_writes               = j_i64(j, {"nvme_smart_health_information_log", "host_writes"}, -1);

    collect_smart_messages(j, d);

    // NVMe self-test status is reported through nvme_self_test_log. We normalize
    // it into a simple status/text/progress model for the UI.
    if (j.contains("nvme_self_test_log") && j["nvme_self_test_log"].is_object()) {
        d->selftest_supported = true;
        d->selftest_progress_pct = -1;

        const auto& st = j["nvme_self_test_log"];
        const std::string cur =
            j_str(j, {"nvme_self_test_log", "current_self_test_operation", "string"});

        if (cur.empty()) {
            d->selftest_status = "unknown";
            d->selftest_text = "Self-test state unavailable";
        } else if (cur == "No self-test in progress") {
            d->selftest_status = "idle";
            d->selftest_text = "No self-test in progress";

            // If available, summarize the latest completed self-test result.
            if (st.contains("table") && st["table"].is_array() &&
                !st["table"].empty() && st["table"][0].is_object()) {
                const auto& row = st["table"][0];

                std::string code;
                std::string result;

                if (row.contains("self_test_code") && row["self_test_code"].is_object()) {
                    auto it = row["self_test_code"].find("string");
                    if (it != row["self_test_code"].end() && it->is_string()) {
                        code = it->get<std::string>();
                    }
                }

                if (row.contains("self_test_result") && row["self_test_result"].is_object()) {
                    auto it = row["self_test_result"].find("string");
                    if (it != row["self_test_result"].end() && it->is_string()) {
                        result = it->get<std::string>();
                    }
                }

                if (!result.empty()) {
                    d->selftest_text =
                        "Last " + (code.empty() ? std::string("self-test") : code + " test") +
                        ": " + result;
                }
            }
        } else {
            d->selftest_status = "running";

            long long remaining = -1;

            if (st.contains("current_self_test_completion_percent") &&
                st["current_self_test_completion_percent"].is_number_integer()) {
                remaining = st["current_self_test_completion_percent"].get<long long>();
            } else if (st.contains("current_self_test_completion_percent") &&
                       st["current_self_test_completion_percent"].is_object()) {
                auto it_val = st["current_self_test_completion_percent"].find("value");
                if (it_val != st["current_self_test_completion_percent"].end() &&
                    it_val->is_number_integer()) {
                    remaining = it_val->get<long long>();
                }
            }

            if (remaining >= 0 && remaining <= 100) {
                int done = 100 - static_cast<int>(remaining);
                if (done < 0) done = 0;
                if (done > 100) done = 100;
                d->selftest_progress_pct = done;
                d->selftest_text = cur + " (" + std::to_string(done) + "%)";
            } else {
                d->selftest_text = cur;
            }
        }
    } else {
        d->selftest_supported = false;
        d->selftest_status = "unsupported";
        d->selftest_text = "Self-test log unavailable";
        d->selftest_progress_pct = -1;
    }

    // Health policy for NVMe:
    // - fail for explicit SMART failure, critical warnings, media errors, or
    //   severe wear / spare thresholds
    // - warn for elevated temperature or notable wear
    d->health_status = "ok";
    d->health_text = "Healthy";

    if (!d->smart_available || !d->smart_enabled || !passed) {
        d->health_status = "fail";
        d->health_text = "SMART/NVMe health failed";
    } else if (critical_warning > 0) {
        d->health_status = "fail";
        d->health_text = "Critical warning reported";
    } else if (d->media_errors > 0) {
        d->health_status = "fail";
        d->health_text = "Media errors reported";
    } else if (d->temperature_c >= 65) {
        d->health_status = "fail";
        d->health_text = "Drive temperature too high";
    } else if ((d->percentage_used >= 90) ||
               (d->available_spare >= 0 && d->available_spare <= 10)) {
        d->health_status = "fail";
        d->health_text = "Drive health degraded";
    } else if ((d->temperature_c >= 55) ||
               (d->percentage_used >= 80) ||
               (d->available_spare >= 0 && d->available_spare <= 15)) {
        d->health_status = "warn";
        d->health_text = "Warning";
    }

    d->warning.clear();
    if (d->temperature_c >= 65) {
        d->warning = "Drive temperature is critically high";
    } else if (d->temperature_c >= 55) {
        d->warning = "Drive temperature is elevated";
    } else if (d->percentage_used >= 90) {
        d->warning = "SSD wear is critically high";
    } else if (d->percentage_used >= 80) {
        d->warning = "SSD wear is high";
    } else if (d->available_spare >= 0 && d->available_spare <= 10) {
        d->warning = "Available spare is critically low";
    } else if (d->available_spare >= 0 && d->available_spare <= 15) {
        d->warning = "Available spare is low";
    } else if (d->media_errors > 0) {
        d->warning = "Media errors reported";
    } else if (critical_warning > 0) {
        d->warning = "NVMe critical warning is non-zero";
    }
}

// Parse smartctl JSON for ATA / SATA devices.
//
// ATA devices rely heavily on per-attribute raw values (pending sectors,
// offline uncorrectable, reallocated sectors, etc.), so the health policy here
// focuses on those signals rather than vendor-normalized scores.
static void parse_ata_smart_json(const json& j, const LsblkDisk& inv, DriveHealthInfo* d) {
    if (!d) return;

    d->name      = !inv.name.empty() ? inv.name : j_str(j, {"device", "name"});
    d->dev       = !inv.path.empty() ? inv.path : j_str(j, {"device", "name"});
    d->transport = !inv.tran.empty() ? inv.tran : "sata";
    d->rota      = inv.rota;
    d->kind      = inv.rota ? "hdd" : "ssd";

    d->model     = !inv.model.empty() ? inv.model : j_str(j, {"model_name"});
    d->serial    = !inv.serial.empty() ? inv.serial : j_str(j, {"serial_number"});
    d->firmware  = j_str(j, {"firmware_version"});

    long long cap = j_i64(j, {"user_capacity", "bytes"}, -1);
    if (cap >= 0) d->size_bytes = static_cast<std::uint64_t>(cap);
    else d->size_bytes = inv.size_bytes;

    d->smart_available = j_bool(j, {"smart_support", "available"}, false);
    d->smart_enabled   = j_bool(j, {"smart_support", "enabled"}, d->smart_available);

    const bool passed = j_bool(j, {"smart_status", "passed"}, false);

    d->temperature_c = static_cast<int>(j_i64(j, {"temperature", "current"}, -1));
    d->power_on_hours = j_i64(j, {"power_on_time", "hours"}, -1);

    d->reallocated_sectors     = ata_attr_raw_value(j, 5, -1);
    d->reported_uncorrect      = ata_attr_raw_value(j, 187, -1);
    d->current_pending_sectors = ata_attr_raw_value(j, 197, -1);
    d->offline_uncorrectable   = ata_attr_raw_value(j, 198, -1);
    d->udma_crc_errors         = ata_attr_raw_value(j, 199, -1);

    collect_smart_messages(j, d);

    // ATA SMART self-test state. We prefer current state from ata_smart_data and
    // then enrich idle/completed state from the self-test log when available.
    d->selftest_supported = false;
    d->selftest_status = "unknown";
    d->selftest_text = "Self-test state unavailable";
    d->selftest_progress_pct = -1;

    if (j.contains("ata_smart_data") && j["ata_smart_data"].is_object()) {
        const auto& ata = j["ata_smart_data"];
        const bool selftests_supported =
            j_bool(j, {"ata_smart_data", "capabilities", "self_tests_supported"}, false);

        if (ata.contains("self_test") && ata["self_test"].is_object()) {
            const auto& st = ata["self_test"];
            d->selftest_supported = selftests_supported;

            if (st.contains("polling_minutes") && st["polling_minutes"].is_object()) {
                const auto& pm = st["polling_minutes"];
                if (pm.contains("short") && pm["short"].is_number_integer()) {
                    d->selftest_short_minutes = pm["short"].get<int>();
                }
                if (pm.contains("extended") && pm["extended"].is_number_integer()) {
                    d->selftest_extended_minutes = pm["extended"].get<int>();
                }
            }

            std::string st_text;
            if (st.contains("status") && st["status"].is_object()) {
                auto it = st["status"].find("string");
                if (it != st["status"].end() && it->is_string()) {
                    st_text = it->get<std::string>();
                }
            }

            long long remaining = -1;
            if (st.contains("remaining_percent") && st["remaining_percent"].is_number_integer()) {
                remaining = st["remaining_percent"].get<long long>();
            }

            if (!st_text.empty()) {
                std::string lower = st_text;
                for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (lower.find("in progress") != std::string::npos) {
                    d->selftest_status = "running";
                    d->selftest_text = st_text;

                    if (remaining >= 0 && remaining <= 100) {
                        int done = 100 - static_cast<int>(remaining);
                        if (done < 0) done = 0;
                        if (done > 100) done = 100;
                        d->selftest_progress_pct = done;
                    }
                } else if (lower.find("completed") != std::string::npos ||
                           lower.find("without error") != std::string::npos) {
                    d->selftest_status = "completed";
                    d->selftest_text = st_text;
                } else if (lower.find("failed") != std::string::npos ||
                           lower.find("aborted") != std::string::npos ||
                           lower.find("interrupted") != std::string::npos) {
                    d->selftest_status = "failed";
                    d->selftest_text = st_text;
                } else if (lower.find("never started") != std::string::npos ||
                           lower.find("no self-test") != std::string::npos) {
                    d->selftest_status = "idle";
                    d->selftest_text = st_text;
                } else {
                    d->selftest_status = "idle";
                    d->selftest_text = st_text;
                }
            }
        }
    }

    // Prefer explicit self-test log last entry if available, unless a test is
    // currently running and that live state would be overwritten.
    if (j.contains("ata_smart_self_test_log") &&
        j["ata_smart_self_test_log"].is_object()) {
        const auto& log = j["ata_smart_self_test_log"];
        if (log.contains("standard") && log["standard"].is_object()) {
            const auto& stdlog = log["standard"];
            if (stdlog.contains("table") && stdlog["table"].is_array() &&
                !stdlog["table"].empty() && stdlog["table"][0].is_object()) {
                const auto& row = stdlog["table"][0];

                std::string type;
                std::string status_text;

                if (row.contains("type") && row["type"].is_object()) {
                    auto it = row["type"].find("string");
                    if (it != row["type"].end() && it->is_string()) {
                        type = it->get<std::string>();
                    }
                }

                if (row.contains("status") && row["status"].is_object()) {
                    auto it = row["status"].find("string");
                    if (it != row["status"].end() && it->is_string()) {
                        status_text = it->get<std::string>();
                    }
                }

                if (!status_text.empty() && d->selftest_status != "running") {
                    d->selftest_supported = true;
                    d->selftest_text =
                        "Last " + (type.empty() ? std::string("self-test") : type + " test") +
                        ": " + status_text;

                    std::string lower = status_text;
                    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                    if (lower.find("completed") != std::string::npos ||
                        lower.find("without error") != std::string::npos) {
                        d->selftest_status = "completed";
                    } else if (lower.find("failed") != std::string::npos ||
                               lower.find("aborted") != std::string::npos ||
                               lower.find("interrupted") != std::string::npos) {
                        d->selftest_status = "failed";
                    } else {
                        d->selftest_status = "idle";
                    }
                }
            }
        }
    }

    // Health policy for ATA / SATA:
    // - fail for explicit SMART failure, pending sectors, offline uncorrectable,
    //   or reported uncorrectable errors
    // - warn for reallocated sectors or elevated temperature
    d->health_status = "ok";
    d->health_text = "Healthy";

    if (!d->smart_available || !d->smart_enabled || !passed) {
        d->health_status = "fail";
        d->health_text = "SMART health failed";
    } else if (d->current_pending_sectors > 0) {
        d->health_status = "fail";
        d->health_text = "Pending sectors reported";
    } else if (d->offline_uncorrectable > 0) {
        d->health_status = "fail";
        d->health_text = "Offline uncorrectable sectors reported";
    } else if (d->reported_uncorrect > 0) {
        d->health_status = "fail";
        d->health_text = "Reported uncorrectable errors";
    } else if (d->temperature_c >= 60) {
        d->health_status = "fail";
        d->health_text = "Drive temperature too high";
    } else if (d->reallocated_sectors > 0) {
        d->health_status = "warn";
        d->health_text = "Reallocated sectors reported";
    } else if (d->temperature_c >= 50) {
        d->health_status = "warn";
        d->health_text = "Warning";
    }

    d->warning.clear();
    if (d->current_pending_sectors > 0) {
        d->warning = "Current pending sectors detected";
    } else if (d->offline_uncorrectable > 0) {
        d->warning = "Offline uncorrectable sectors detected";
    } else if (d->reported_uncorrect > 0) {
        d->warning = "Reported uncorrectable errors detected";
    } else if (d->reallocated_sectors > 0) {
        d->warning = "Reallocated sectors detected";
    } else if (d->temperature_c >= 60) {
        d->warning = "Drive temperature is critically high";
    } else if (d->temperature_c >= 50) {
        d->warning = "Drive temperature is elevated";
    }
}

// Only expose self-test types that the current API / UI understands.
static bool is_supported_selftest_type(const std::string& type) {
    return type == "short" || type == "extended";
}

// Start a SMART self-test with smartctl.
//
// We return the captured smartctl text on failure because for start commands the
// textual error is usually more actionable than the raw exit code.
static bool start_smartctl_selftest(const std::string& dev,
                                    const std::string& type,
                                    std::string* err) {
    if (err) err->clear();

    // smartctl uses "short" and "long"
    const std::string smart_type = (type == "extended") ? "long" : "short";

    std::string txt;
    int rc = -1;
    const std::string cmd =
        "sudo -n /usr/sbin/smartctl -t " + smart_type + " " + shell_quote(dev) + " 2>&1";

    if (!run_command_capture(cmd, &txt, &rc)) {
        if (err) *err = "failed to execute smartctl self-test start";
        return false;
    }

    if (rc != 0) {
        std::string preview = trim_ws(txt);
        if (preview.size() > 400) preview = preview.substr(0, 400);
        if (err) {
            *err = preview.empty()
                ? ("smartctl self-test start failed rc=" + std::to_string(rc))
                : preview;
        }
        return false;
    }

    return true;
}

// Normalize drive bus classification from a combination of lsblk inventory and
// smartctl JSON.
//
// Why both?
// - lsblk TRAN is fast and useful, but can be blank on some real SATA systems.
// - smartctl device.type is usually more reliable once probe data exists.
// Using both keeps display and self-test-start paths consistent.
static void classify_drive_bus(const LsblkDisk& inv,
                               const json& j,
                               bool* is_nvme,
                               bool* is_sata) {
    if (is_nvme) *is_nvme = false;
    if (is_sata) *is_sata = false;

    const std::string dev_type = j_str(j, {"device", "type"});

    if (is_nvme) {
        *is_nvme = (dev_type == "nvme") ||
                   (inv.tran == "nvme") ||
                   starts_with(inv.name, "nvme");
    }

    if (is_sata) {
        *is_sata = (dev_type == "ata") ||
                   (dev_type == "sat") ||
                   (inv.tran == "sata");
    }
}

// Probe a single disk with smartctl JSON and dispatch to the correct parser.
//
// If the bus is not one of the currently normalized types, we still return a
// partially filled DriveHealthInfo so the caller can display "unsupported" data
// instead of silently dropping the device.
static bool probe_one_drive(const LsblkDisk& inv, DriveHealthInfo* out, std::string* err) {
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    if (err) err->clear();

    std::string txt;
    int rc = -1;
    const std::string cmd = "sudo -n /usr/sbin/smartctl -a -j " + shell_quote(inv.path) + " 2>&1";
    if (!run_command_capture(cmd, &txt, &rc)) {
        if (err) *err = "failed to execute smartctl for " + inv.path;
        return false;
    }

    json j;
    try {
        j = json::parse(txt);
    } catch (const std::exception& e) {
        if (err) {
            std::string preview = txt;
            if (preview.size() > 300) preview = preview.substr(0, 300);
            *err = "failed to parse smartctl JSON for " + inv.path +
                   ": " + e.what() +
                   "; output=" + preview;
        }
        return false;
    }

    bool is_nvme = false;
    bool is_sata = false;
    classify_drive_bus(inv, j, &is_nvme, &is_sata);

    if (is_nvme) {
        parse_nvme_smart_json(j, inv, out);
        return true;
    }

    if (is_sata) {
        parse_ata_smart_json(j, inv, out);
        return true;
    }

    // Fallback for buses we do not fully normalize yet. This keeps the device
    // visible and preserves whatever basic SMART state is available.
    out->name = inv.name;
    out->dev = inv.path;
    out->transport = inv.tran;
    out->rota = inv.rota;
    out->kind = inv.rota ? "hdd" : "ssd";
    out->model = inv.model;
    out->serial = inv.serial;
    out->size_bytes = inv.size_bytes;
    out->smart_available = j_bool(j, {"smart_support", "available"}, false);
    out->smart_enabled = j_bool(j, {"smart_support", "enabled"}, out->smart_available);
    out->temperature_c = static_cast<int>(j_i64(j, {"temperature", "current"}, -1));
    out->power_on_hours = j_i64(j, {"power_on_time", "hours"}, -1);
    out->health_status = "unknown";
    out->health_text = out->smart_available ? "Unsupported bus in v1" : "SMART unavailable";
    out->selftest_supported = false;
    out->selftest_status = "unsupported";
    out->selftest_text = out->smart_available ? "Self-test not implemented for this bus yet"
                                              : "SMART/self-test unavailable";
    collect_smart_messages(j, out);
    return true;
}

} // namespace

// Start a manual drive self-test.
//
// The device path is validated against the current lsblk inventory first so we
// only allow tests on known whole-disk devices. Bus support is then determined
// using smartctl JSON classification, not lsblk TRAN alone.
bool start_drive_selftest(const std::string& dev,
                          const std::string& type,
                          std::string* err) {
    if (err) err->clear();

    if (dev.empty()) {
        if (err) *err = "missing device path";
        return false;
    }
    if (!starts_with(dev, "/dev/")) {
        if (err) *err = "invalid device path";
        return false;
    }
    if (!is_supported_selftest_type(type)) {
        if (err) *err = "unsupported self-test type";
        return false;
    }

    std::vector<LsblkDisk> inv;
    std::string inv_err;
    if (!collect_lsblk_disks(&inv, &inv_err)) {
        if (err) *err = inv_err.empty() ? "failed to enumerate drives" : inv_err;
        return false;
    }

    const LsblkDisk* found = nullptr;
    for (const auto& d : inv) {
        if (d.path == dev) {
            found = &d;
            break;
        }
    }

    if (!found) {
        if (err) *err = "device not found";
        return false;
    }

    // Fetch only enough smartctl JSON to classify the bus consistently with the
    // main probe path before attempting the self-test start command.
    std::string txt;
    int rc = -1;
    const std::string info_cmd =
        "sudo -n /usr/sbin/smartctl -i -j " + shell_quote(found->path) + " 2>&1";

    if (!run_command_capture(info_cmd, &txt, &rc)) {
        if (err) *err = "failed to execute smartctl identify for self-test";
        return false;
    }
    if (rc != 0) {
        std::string preview = trim_ws(txt);
        if (preview.size() > 400) preview = preview.substr(0, 400);
        if (err) {
            *err = preview.empty()
                ? ("smartctl identify failed rc=" + std::to_string(rc))
                : preview;
        }
        return false;
    }

    json j;
    try {
        j = json::parse(txt);
    } catch (const std::exception& e) {
        if (err) *err = std::string("failed to parse smartctl identify JSON: ") + e.what();
        return false;
    }

    bool is_nvme = false;
    bool is_sata = false;
    classify_drive_bus(*found, j, &is_nvme, &is_sata);

    if (!is_nvme && !is_sata) {
        if (err) *err = "manual self-test start is currently implemented for NVMe and SATA drives only";
        return false;
    }

    return start_smartctl_selftest(dev, type, err);
}

// Probe all candidate internal drives and return normalized health information.
//
// Partial success is allowed:
// - if at least one probe succeeds, we return true and include the successful
//   entries
// - if inventory exists but all probes fail, we return false and surface the
//   first captured error for debugging / UI reporting
bool probe_drive_health(std::vector<DriveHealthInfo>* out, std::string* err) {
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    out->clear();
    if (err) err->clear();

    std::vector<LsblkDisk> inv;
    if (!collect_lsblk_disks(&inv, err)) return false;

    std::size_t ok_count = 0;
    std::string first_err;

    for (const auto& d : inv) {
        DriveHealthInfo one;
        std::string one_err;
        if (probe_one_drive(d, &one, &one_err)) {
            out->push_back(std::move(one));
            ok_count++;
        } else if (first_err.empty() && !one_err.empty()) {
            first_err = one_err;
        }
    }

    if (!inv.empty() && ok_count == 0) {
        if (err) *err = first_err.empty() ? "all drive probes failed" : first_err;
        return false;
    }

    return true;
}

} // namespace pqnas