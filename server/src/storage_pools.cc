#include "storage_pools.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <system_error>

namespace pqnas {

namespace {

std::string getenv_str(const std::string& key) {
    const char* v = std::getenv(key.c_str());
    return v ? std::string(v) : std::string();
}

bool read_text_file(const std::string& path, std::string* out) {
    if (out) out->clear();

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::string s((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
    if (!f.good() && !f.eof()) return false;

    if (out) *out = std::move(s);
    return true;
}

bool write_text_file_atomic_raw(const std::string& path, const std::string& content) {
    const std::string tmp = path + ".tmp";

    std::ofstream f(tmp, std::ios::binary);
    if (!f) return false;

    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    f.close();
    if (!f) return false;

    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp);
        return false;
    }
    return true;
}

std::string iso8601_now_fallback() {
    // Minimal fallback only for config migration timestamps if needed.
    // If you already have iso8601_now() globally available, replace this helper
    // with that function call and delete this fallback.
    return "";
}

std::string trim_copy_safe(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string lower_ascii_copy(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::filesystem::path pools_cfg_path_from_users_path_local(const std::string& users_path) {
    std::string root = getenv_str("PQNAS_STORAGE_ROOT");
    if (root.empty()) root = "/srv/pqnas";

    std::filesystem::path p = std::filesystem::path(root) / "config" / "pools.json";

    std::error_code ec;
    auto st = std::filesystem::status(std::filesystem::path(root) / "config", ec);
    if (!ec && std::filesystem::is_directory(st)) return p;

    return std::filesystem::path(users_path).parent_path() / "pools.json";
}

json make_empty_slot(int index) {
    return json{
        {"index", index},
        {"device", nullptr}
    };
}

json make_slot(int index, const std::string& device) {
    return json{
        {"index", index},
        {"device", device.empty() ? json(nullptr) : json(device)}
    };
}

void normalize_slots_array(json* slots) {
    if (!slots || !slots->is_array()) {
        if (slots) *slots = json::array();
        return;
    }

    json out = json::array();
    std::set<std::string> seen_devices;
    int idx = 0;

    for (auto& s : *slots) {
        std::string dev;

        if (s.is_object() && s.contains("device") && s["device"].is_string()) {
            dev = trim_copy_safe(s["device"].get<std::string>());
        }

        if (!dev.empty() && dev.rfind("/dev/", 0) != 0) {
            dev.clear();
        }

        if (!dev.empty()) {
            if (!seen_devices.insert(dev).second) {
                dev.clear();
            }
        }

        out.push_back(make_slot(idx++, dev));
    }

    *slots = std::move(out);
}

} // namespace

void normalize_pool_entry_v3(json* pool_obj) {
    if (!pool_obj || !pool_obj->is_object()) {
        if (pool_obj) *pool_obj = json::object();
        return;
    }

    if (!pool_obj->contains("pool_id") || !(*pool_obj)["pool_id"].is_string())
        (*pool_obj)["pool_id"] = "";

    if (!pool_obj->contains("display_name") || !(*pool_obj)["display_name"].is_string())
        (*pool_obj)["display_name"] = "";

    if (!pool_obj->contains("created_ts") || !(*pool_obj)["created_ts"].is_string())
        (*pool_obj)["created_ts"] = "";

    if (!pool_obj->contains("managed") || !(*pool_obj)["managed"].is_boolean())
        (*pool_obj)["managed"] = true;

    if (!pool_obj->contains("fs_label") || !(*pool_obj)["fs_label"].is_string())
        (*pool_obj)["fs_label"] = "";

    if (!pool_obj->contains("fs_uuid") || !(*pool_obj)["fs_uuid"].is_string())
        (*pool_obj)["fs_uuid"] = "";

    if (!pool_obj->contains("mode") || !(*pool_obj)["mode"].is_string()) {
        (*pool_obj)["mode"] = "single";
    } else {
        const std::string mode = lower_ascii_copy(trim_copy_safe((*pool_obj)["mode"].get<std::string>()));
        (*pool_obj)["mode"] = (mode == "raid1") ? "raid1" : "single";
    }

    if (!pool_obj->contains("slots") || !(*pool_obj)["slots"].is_array()) {
        (*pool_obj)["slots"] = json::array();
    }

    normalize_slots_array(&(*pool_obj)["slots"]);

    int slot_count = static_cast<int>((*pool_obj)["slots"].size());
    if (pool_obj->contains("slot_count") && (*pool_obj)["slot_count"].is_number_integer()) {
        slot_count = std::max(slot_count, (*pool_obj)["slot_count"].get<int>());
    }

    if (slot_count < 0) slot_count = 0;

    while (static_cast<int>((*pool_obj)["slots"].size()) < slot_count) {
        (*pool_obj)["slots"].push_back(make_empty_slot(static_cast<int>((*pool_obj)["slots"].size())));
    }

    (*pool_obj)["slot_count"] = static_cast<int>((*pool_obj)["slots"].size());
}

void ensure_pools_cfg_shape_v3(json* cfg) {
    if (!cfg || !cfg->is_object()) {
        if (cfg) *cfg = json::object();
        return;
    }

    if (!cfg->contains("names_by_mount") || !(*cfg)["names_by_mount"].is_object()) {
        (*cfg)["names_by_mount"] = json::object();
    }

    if (!cfg->contains("pools") || !(*cfg)["pools"].is_object()) {
        (*cfg)["pools"] = json::object();
    }

    for (auto it = (*cfg)["pools"].begin(); it != (*cfg)["pools"].end(); ++it) {
        normalize_pool_entry_v3(&it.value());
    }

    (*cfg)["version"] = 3;
}

json load_or_init_pools_cfg_v3(const std::string& users_path) {
    const auto cfg_path = pools_cfg_path_from_users_path_local(users_path);

    std::string txt;
    json j;

    if (read_text_file(cfg_path.string(), &txt)) {
        try {
            j = json::parse(txt);
        } catch (...) {
            j = json::object();
        }
    }

    if (!j.is_object()) {
        j = json::object();
    }

    int version = j.value("version", 0);

    // init
    if (version == 0) {
        j["version"] = 3;
        j["names_by_mount"] = json::object();
        j["pools"] = json::object();
        ensure_pools_cfg_shape_v3(&j);
        return j;
    }

    // migrate v1 -> v2-ish shape first
    if (version == 1) {
        json pools = json::object();
        const auto names = j.value("names_by_mount", json::object());

        for (auto it = names.begin(); it != names.end(); ++it) {
            const std::string mount = it.key();
            const std::string display = it.value().is_string() ? it.value().get<std::string>() : "";

            pools[mount] = json{
                {"pool_id", ""},
                {"display_name", display},
                {"created_ts", iso8601_now_fallback()},
                {"managed", false},
                {"fs_label", ""},
                {"fs_uuid", ""},
                {"mode", "single"},
                {"slot_count", 0},
                {"slots", json::array()}
            };
        }

        j.clear();
        j["version"] = 3;
        j["names_by_mount"] = names.is_object() ? names : json::object();
        j["pools"] = pools;
        ensure_pools_cfg_shape_v3(&j);
        (void)write_text_file_atomic_raw(cfg_path.string(), j.dump(2) + "\n");
        return j;
    }

    // migrate v2 -> v3
    if (version == 2) {
        if (!j.contains("names_by_mount") || !j["names_by_mount"].is_object()) {
            j["names_by_mount"] = json::object();
        }
        if (!j.contains("pools") || !j["pools"].is_object()) {
            j["pools"] = json::object();
        }

        for (auto it = j["pools"].begin(); it != j["pools"].end(); ++it) {
            json& p = it.value();
            if (!p.is_object()) p = json::object();

            if (!p.contains("pool_id") || !p["pool_id"].is_string())
                p["pool_id"] = "";

            if (!p.contains("display_name") || !p["display_name"].is_string())
                p["display_name"] = "";

            if (!p.contains("created_ts") || !p["created_ts"].is_string())
                p["created_ts"] = "";

            if (!p.contains("managed") || !p["managed"].is_boolean())
                p["managed"] = false;

            if (!p.contains("fs_label") || !p["fs_label"].is_string())
                p["fs_label"] = "";

            if (!p.contains("fs_uuid") || !p["fs_uuid"].is_string())
                p["fs_uuid"] = "";

            if (!p.contains("mode") || !p["mode"].is_string())
                p["mode"] = "single";

            if (!p.contains("slot_count") || !p["slot_count"].is_number_integer())
                p["slot_count"] = 0;

            if (!p.contains("slots") || !p["slots"].is_array())
                p["slots"] = json::array();
        }

        ensure_pools_cfg_shape_v3(&j);
        (void)write_text_file_atomic_raw(cfg_path.string(), j.dump(2) + "\n");
        return j;
    }

    ensure_pools_cfg_shape_v3(&j);
    return j;
}

bool write_pools_cfg_v3(const std::string& users_path, const json& in_cfg, std::string* err) {
    if (err) err->clear();

    json cfg = in_cfg;
    ensure_pools_cfg_shape_v3(&cfg);

    const auto cfg_path = pools_cfg_path_from_users_path_local(users_path);
    if (!write_text_file_atomic_raw(cfg_path.string(), cfg.dump(2) + "\n")) {
        if (err) *err = "write_text_file_atomic failed for " + cfg_path.string();
        return false;
    }
    return true;
}

std::string pools_display_name_for_mount_v3(const json& cfg, const std::string& mount) {
    if (!cfg.is_object()) return "";

    if (cfg.contains("pools") && cfg["pools"].is_object()) {
        auto it = cfg["pools"].find(mount);
        if (it != cfg["pools"].end() && it->is_object()) {
            const std::string s = trim_copy_safe(it->value("display_name", ""));
            if (!s.empty()) return s;
        }
    }

    if (cfg.contains("names_by_mount") && cfg["names_by_mount"].is_object()) {
        auto it = cfg["names_by_mount"].find(mount);
        if (it != cfg["names_by_mount"].end() && it->is_string()) {
            return trim_copy_safe(it->get<std::string>());
        }
    }

    return "";
}

std::string pool_mode_from_profiles_best_effort(const std::string& profile_data,
                                                const std::string& profile_meta) {
    const std::string d = lower_ascii_copy(trim_copy_safe(profile_data));
    const std::string m = lower_ascii_copy(trim_copy_safe(profile_meta));

    if (d == "raid1" && m == "raid1") return "raid1";
    if (d == "single" || m == "single") return "single";

    return "single";
}

std::vector<std::string> runtime_member_parent_disks_from_show_json(const json& btrfs_show_json) {
    std::vector<std::string> out;
    std::set<std::string> seen;

    if (!btrfs_show_json.is_object()) return out;
    if (!btrfs_show_json.contains("devices") || !btrfs_show_json["devices"].is_array()) return out;

    for (const auto& d : btrfs_show_json["devices"]) {
        if (!d.is_object()) continue;

        const std::string pd = d.value("parent_disk", "");
        const std::string p  = d.value("path", "");

        const std::string chosen = !pd.empty() ? pd : p;
        if (chosen.empty()) continue;

        if (seen.insert(chosen).second) {
            out.push_back(chosen);
        }
    }

    return out;
}

void infer_slots_from_runtime_if_missing(json* cfg_pool,
                                         const std::vector<std::string>& runtime_member_parents) {
    if (!cfg_pool || !cfg_pool->is_object()) return;

    const bool has_slots =
        cfg_pool->contains("slots") &&
        (*cfg_pool)["slots"].is_array() &&
        !(*cfg_pool)["slots"].empty();

    if (has_slots) {
        normalize_pool_entry_v3(cfg_pool);
        return;
    }

    json slots = json::array();
    int idx = 0;
    for (const auto& d : runtime_member_parents) {
        slots.push_back(make_slot(idx++, d));
    }

    if (slots.empty()) {
        slots.push_back(make_empty_slot(0));
    }

    (*cfg_pool)["slots"] = std::move(slots);
    (*cfg_pool)["slot_count"] = static_cast<int>((*cfg_pool)["slots"].size());

    if (!cfg_pool->contains("mode") || !(*cfg_pool)["mode"].is_string()) {
        (*cfg_pool)["mode"] = "single";
    }

    normalize_pool_entry_v3(cfg_pool);
}

json merge_pool_runtime_and_config(const json& cfg_pool,
                                   const json& runtime_pool,
                                   const std::vector<std::string>& runtime_member_parents,
                                   bool busy,
                                   const std::string& busy_lock) {
    json out = json::object();

    const bool has_cfg = cfg_pool.is_object();
    const bool has_rt  = runtime_pool.is_object();

    // ----------------------------
    // Identity / mount
    // ----------------------------
    std::string mount;
    if (has_rt) mount = runtime_pool.value("mount", "");
    if (mount.empty() && has_cfg) mount = cfg_pool.value("mount", "");
    out["mount"] = mount;

    std::string pool_id;
    if (has_cfg) pool_id = cfg_pool.value("pool_id", "");
    if (pool_id.empty() && has_rt) pool_id = runtime_pool.value("pool_id", "");
    out["pool_id"] = pool_id;

    bool managed = has_cfg ? cfg_pool.value("managed", true) : false;
    out["managed"] = managed;

    // ----------------------------
    // Runtime info
    // ----------------------------
	if (has_rt) {
   		out["uuid"] = runtime_pool.value("uuid", "");
   		out["label"] = runtime_pool.value("label", "");
   		out["devices"] = runtime_pool.value("devices", 0);
   		out["profile_data"] = runtime_pool.value("profile_data", "");
   		out["profile_metadata"] = runtime_pool.value("profile_metadata", "");
   		out["size_bytes"] = runtime_pool.value("size_bytes", int64_t{0});
   		out["used_bytes"] = runtime_pool.value("used_bytes", int64_t{0});
   		out["resolved_source"] = runtime_pool.value("resolved_source", "");
   		out["resolved_disk"] = runtime_pool.value("resolved_disk", "");
   		out["fstype"] = "btrfs";
   		out["free_estimated_bytes"] = runtime_pool.value("free_estimated_bytes", int64_t{0});
   		out["usable_total_bytes"] = runtime_pool.value("usable_total_bytes", int64_t{0});
   		out["runtime_mode"] = runtime_pool.value("runtime_mode", "");
	} else {
   		out["uuid"] = "";
   		out["label"] = "";
   		out["devices"] = 0;
   		out["profile_data"] = "";
	    out["profile_metadata"] = "";
   		out["size_bytes"] = int64_t{0};
   		out["used_bytes"] = int64_t{0};
   		out["resolved_source"] = "";
   		out["resolved_disk"] = "";
   		out["fstype"] = "";
	    out["free_estimated_bytes"] = int64_t{0};
   		out["usable_total_bytes"] = int64_t{0};
	    out["runtime_mode"] = "";
	}

    // ----------------------------
    // Mode
    // Prefer config mode if present and non-empty.
    // Otherwise infer from runtime.
    // ----------------------------
    std::string mode;
    if (has_cfg && cfg_pool.contains("mode") && cfg_pool["mode"].is_string()) {
        mode = trim_copy_safe(cfg_pool["mode"].get<std::string>());
    }
    if (mode.empty()) {
        mode = pool_mode_from_profiles_best_effort(
            out.value("profile_data", ""),
            out.value("profile_metadata", "")
        );
    }
    if (mode != "raid1") mode = "single";
    out["mode"] = mode;

    // ----------------------------
    // Display name
    // Prefer config display_name, then runtime label, then pool_id.
    // ----------------------------
    std::string display_name;
    if (has_cfg && cfg_pool.contains("display_name") && cfg_pool["display_name"].is_string()) {
        display_name = trim_copy_safe(cfg_pool["display_name"].get<std::string>());
    }
    if (display_name.empty()) {
        display_name = trim_copy_safe(out.value("label", ""));
    }
    if (display_name.empty()) {
        display_name = pool_id;
    }
    out["display_name"] = display_name;

    // ----------------------------
    // Slots / membership
    // ----------------------------
    out["member_parent_disks"] = runtime_member_parents;

    std::set<std::string> runtime_set(runtime_member_parents.begin(), runtime_member_parents.end());
    std::set<std::string> desired_set;

    json slots = json::array();

    if (has_cfg && cfg_pool.contains("slots") && cfg_pool["slots"].is_array() && !cfg_pool["slots"].empty()) {
        for (const auto& s : cfg_pool["slots"]) {
            const int index = s.value("index", static_cast<int>(slots.size()));

            std::string dev;
            if (s.contains("device") && s["device"].is_string()) {
                dev = trim_copy_safe(s["device"].get<std::string>());
            }

            const bool assigned = !dev.empty();
            const bool present  = assigned && runtime_set.find(dev) != runtime_set.end();

            json one = {
                {"index", index},
                {"device", assigned ? json(dev) : json(nullptr)},
                {"assigned", assigned},
                {"present", present},
                {"member", present}
            };

            if (assigned) desired_set.insert(dev);
            slots.push_back(one);
        }
    } else {
        // No config slots: best-effort slots from runtime members
        int idx = 0;
        for (const auto& dev : runtime_member_parents) {
            slots.push_back(json{
                {"index", idx++},
                {"device", dev},
                {"assigned", true},
                {"present", true},
                {"member", true}
            });
            desired_set.insert(dev);
        }
    }

    out["slots"] = slots;
    out["slot_count"] = has_cfg
        ? std::max(cfg_pool.value("slot_count", static_cast<int>(slots.size())),
                   static_cast<int>(slots.size()))
        : static_cast<int>(slots.size());

    // ----------------------------
    // Status
    // ----------------------------
    const bool mounted = has_rt;
    const bool layout_drift = desired_set != runtime_set;
    const bool degraded = mounted && !desired_set.empty() && (runtime_set.size() < desired_set.size());

    out["status"] = json{
        {"mounted", mounted},
        {"busy", busy},
        {"busy_lock", busy_lock},
        {"degraded", degraded},
        {"layout_drift", layout_drift},
        {"runtime_missing", !mounted}
    };

    return out;
}

} // namespace pqnas