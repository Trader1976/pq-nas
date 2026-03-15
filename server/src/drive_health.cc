#include "drive_health.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace pqnas {
namespace {

using json = nlohmann::json;

static std::string trim_ws(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) a++;
    while (b > a && std::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

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

static std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

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

static bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static bool should_skip_disk_name(const std::string& name) {
    if (name.empty()) return true;
    if (starts_with(name, "loop")) return true;
    if (starts_with(name, "ram"))  return true;
    if (starts_with(name, "zram")) return true;
    if (starts_with(name, "dm-"))  return true;
    if (starts_with(name, "md"))   return true;
    return false;
}

struct LsblkDisk {
    std::string name;
    std::string path;
    std::string model;
    std::string serial;
    std::string tran;
    std::uint64_t size_bytes = 0;
    bool rota = false;
};

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
        x.name  = d.contains("name")  && d["name"].is_string()  ? d["name"].get<std::string>()  : "";
        x.path  = d.contains("path")  && d["path"].is_string()  ? d["path"].get<std::string>()  : "";
        x.model = d.contains("model") && d["model"].is_string() ? trim_ws(d["model"].get<std::string>()) : "";
        x.serial= d.contains("serial")&& d["serial"].is_string()? trim_ws(d["serial"].get<std::string>()) : "";
        x.tran  = d.contains("tran")  && d["tran"].is_string()  ? trim_ws(d["tran"].get<std::string>()) : "";

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
    d->data_units_read        = j_i64(j, {"nvme_smart_health_information_log", "data_units_read"}, -1);
    d->data_units_written     = j_i64(j, {"nvme_smart_health_information_log", "data_units_written"}, -1);
    d->host_reads             = j_i64(j, {"nvme_smart_health_information_log", "host_reads"}, -1);
    d->host_writes            = j_i64(j, {"nvme_smart_health_information_log", "host_writes"}, -1);


    collect_smart_messages(j, d);

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

static bool is_supported_selftest_type(const std::string& type) {
    return type == "short" || type == "extended";
}

static bool start_nvme_selftest(const std::string& dev,
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

    // For the start command, smartctl output text is often more useful than rc.
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

    const std::string dev_type = j_str(j, {"device", "type"});
    if (dev_type == "nvme" || inv.tran == "nvme" || starts_with(inv.name, "nvme")) {
        parse_nvme_smart_json(j, inv, out);
        return true;
    }

    // v1: unsupported non-NVMe internal disk
    out->name = inv.name;
    out->dev = inv.path;
    out->transport = inv.tran;
    out->rota = inv.rota;
    out->kind = inv.rota ? "hdd" : "ssd";
    out->model = inv.model;
    out->serial = inv.serial;
    out->size_bytes = inv.size_bytes;
    out->health_status = "unknown";
    out->health_text = "Unsupported in v1";
    out->selftest_supported = false;
    out->selftest_status = "unknown";
    out->selftest_text = "Not implemented for this bus yet";
    collect_smart_messages(j, out);
    return true;
}

} // namespace

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

    // Phase 1: NVMe only, because full self-test handling is currently only
    // implemented/probed properly for NVMe in this module.
    const bool is_nvme = (found->tran == "nvme") || starts_with(found->name, "nvme");
    if (!is_nvme) {
        if (err) *err = "manual self-test start is currently implemented for NVMe drives only";
        return false;
    }

    return start_nvme_selftest(dev, type, err);
}

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