#include "snapshot_provider.h"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <climits>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <ctime>
#include <unordered_map>




#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace pqnas::snapshots {

using json = nlohmann::json;

// from snapshot_naming.cc
std::string make_snapshot_name_utc();

static json load_admin_settings_file(const std::string& path) {
    try {
        std::ifstream f(path);
        if (!f.good()) return json::object();
        json j;
        f >> j;
        if (!j.is_object()) return json::object();
        return j;
    } catch (...) {
        return json::object();
    }
}

static int try_lockfile(const std::string& path) {
    int fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static void unlockfile(const std::string& path, int fd) {
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        ::close(fd);
    }
    // best-effort cleanup
    ::unlink(path.c_str());
}

static bool parse_snapshot_epoch_utc(const std::string& name, long long& out_epoch) {
    // prefix: YYYY-MM-DDTHH-MM-SS
    if (name.size() < 19) return false;
    if (name[4] != '-' || name[7] != '-' || name[10] != 'T' ||
        name[13] != '-' || name[16] != '-') return false;

    int Y=0,M=0,D=0,h=0,m=0,s=0;
    try {
        Y = std::stoi(name.substr(0,4));
        M = std::stoi(name.substr(5,2));
        D = std::stoi(name.substr(8,2));
        h = std::stoi(name.substr(11,2));
        m = std::stoi(name.substr(14,2));
        s = std::stoi(name.substr(17,2));
    } catch (...) { return false; }

    std::tm tm{};
    tm.tm_year = Y - 1900;
    tm.tm_mon  = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min  = m;
    tm.tm_sec  = s;

#if defined(__GLIBC__)
    out_epoch = (long long)timegm(&tm); // UTC
#else
    out_epoch = (long long)std::mktime(&tm); // fallback
#endif
    return out_epoch > 0;
}

static void prune_snapshots(
    SnapshotProvider& prov,
    const std::string& root,
    int keep_days,
    int keep_min,
    int keep_max)
{
    if (keep_min < 0) keep_min = 0;
    if (keep_max < 1) keep_max = 1;
    if (keep_max < keep_min) keep_max = keep_min;

    struct Snap { std::string path; std::string name; long long epoch; };
    std::vector<Snap> snaps;

    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(root, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec))
    {
        if (ec) break;
        if (!it->is_directory(ec)) continue;

        const std::string name = it->path().filename().string();
        long long ep = 0;
        if (!parse_snapshot_epoch_utc(name, ep)) continue;

        snaps.push_back(Snap{ it->path().string(), name, ep });
    }

    std::sort(snaps.begin(), snaps.end(),
              [](const Snap& a, const Snap& b){ return a.epoch < b.epoch; });

    auto del_oldest = [&]() -> bool {
        if (snaps.empty()) return false;
        const auto victim = snaps.front();
        auto r = prov.delete_subvol(victim.path);
        if (!r.ok) {
            std::cerr << "[snapshots] prune FAILED path=" << victim.path
                      << " err=" << r.err << "\n";
            return false;
        }
        std::cerr << "[snapshots] prune deleted " << victim.name << "\n";
        snaps.erase(snaps.begin());
        return true;
    };

    const long long now = (long long)std::time(nullptr);
    const long long cutoff = (keep_days > 0)
        ? (now - (long long)keep_days * 86400LL)
        : LLONG_MIN;

    // 1) delete older-than-cutoff while staying above keep_min
    while ((int)snaps.size() > keep_min) {
        if (!(keep_days > 0 && snaps.front().epoch < cutoff)) break;
        if (!del_oldest()) break;
    }

    // 2) cap to keep_max but never below keep_min
    while ((int)snaps.size() > keep_max && (int)snaps.size() > keep_min) {
        if (!del_oldest()) break;
    }
}

static bool looks_like_snapshot_name(const std::string& s) {
    // We only need to recognize our own naming style:
    // "YYYY-MM-DDTHH-MM-SS" (then maybe ".msZ-rrrr" etc)
    if (s.size() < 19) return false;
    auto isd = [&](size_t i){ return i < s.size() && s[i] >= '0' && s[i] <= '9'; };
    return isd(0)&&isd(1)&&isd(2)&&isd(3) && s[4]=='-' &&
           isd(5)&&isd(6) && s[7]=='-' &&
           isd(8)&&isd(9) && s[10]=='T' &&
           isd(11)&&isd(12) && s[13]=='-' &&
           isd(14)&&isd(15) && s[16]=='-' &&
           isd(17)&&isd(18);
}

static long long parse_snapshot_name_epoch_utc(const std::string& name) {
    // Parses only: YYYY-MM-DDTHH-MM-SS (ignores .msZ-xxxx)
    if (!looks_like_snapshot_name(name)) return 0;

    auto to_i = [&](size_t pos, size_t len) -> int {
        return std::stoi(name.substr(pos, len));
    };

    try {
        const int Y  = to_i(0,4);
        const int Mo = to_i(5,2);
        const int D  = to_i(8,2);
        const int H  = to_i(11,2);
        const int Mi = to_i(14,2);
        const int S  = to_i(17,2);

        std::tm tm{};
        tm.tm_year = Y - 1900;
        tm.tm_mon  = Mo - 1;
        tm.tm_mday = D;
        tm.tm_hour = H;
        tm.tm_min  = Mi;
        tm.tm_sec  = S;
        tm.tm_isdst = 0;

        // Linux/glibc: timegm available (UTC)
        const time_t t = timegm(&tm);
        if (t < 0) return 0;
        return (long long)t;
    } catch (...) {
        return 0;
    }
}

static long long latest_snapshot_epoch_under_root(const std::string& snap_root) {
    // Find lexicographically newest snapshot name, then parse to epoch.
    // Your naming is fixed-width ISO-ish so lexicographic order == time order.
    std::error_code ec;
    if (!std::filesystem::exists(snap_root, ec) || ec) return 0;
    if (!std::filesystem::is_directory(snap_root, ec) || ec) return 0;

    std::string best_name;

    for (const auto& de : std::filesystem::directory_iterator(snap_root, ec)) {
        if (ec) break;
        if (!de.is_directory(ec) || ec) continue;

        const std::string nm = de.path().filename().string();
        if (!looks_like_snapshot_name(nm)) continue;

        if (best_name.empty() || nm > best_name) best_name = nm;
    }

    if (best_name.empty()) return 0;
    return parse_snapshot_name_epoch_utc(best_name);
}

static long long latest_snapshot_epoch_from_settings(const nlohmann::json& sn) {
    long long best = 0;
    const auto vols = sn.value("volumes", nlohmann::json::array());
    if (!vols.is_array()) return 0;

    for (const auto& v : vols) {
        if (!v.is_object()) continue;
        const std::string root = v.value("snap_root", "");
        if (root.empty()) continue;

        const long long t = latest_snapshot_epoch_under_root(root);
        if (t > best) best = t;
    }
    return best;
}


std::thread start_snapshot_scheduler(
    const std::string& admin_settings_path,
    std::atomic<bool>& stop_flag)
{
    return std::thread([admin_settings_path, &stop_flag]() {
        long long last_run_global = 0;
        std::unordered_map<std::string, long long> last_run_by_vol;


        std::mt19937 rng{std::random_device{}()};

        auto prov = make_btrfs_provider();

        for (;;) {
            if (stop_flag.load()) return;

            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (stop_flag.load()) return;

            json s = load_admin_settings_file(admin_settings_path);
            if (!s.is_object()) continue;

            if (!s.contains("snapshots") || !s["snapshots"].is_object()) continue;
            json sn = s["snapshots"];
            const bool per_vol = sn.value("per_volume_policy", false);


            if (!sn.value("enabled", false)) continue;
            if (sn.value("backend", std::string("btrfs")) != "btrfs") continue;

            const json sched = sn.value("schedule", json::object());
            int tpd = sched.value("times_per_day", 6);
            int jitter = sched.value("jitter_seconds", 120);
            if (tpd < 1) tpd = 1;
            if (tpd > 24) tpd = 24;
            if (jitter < 0) jitter = 0;
            if (jitter > 3600) jitter = 3600;

            const long long now = (long long)std::time(nullptr);
            const long long interval = 86400LL / (long long)tpd;

            // Stage 3: prevent restart-storm.
            if (!per_vol) {
                if (last_run_global == 0) {
                    const long long init = latest_snapshot_epoch_from_settings(sn);
                    if (init > 0) {
                        last_run_global = init;
                        std::cerr << "[snapshots] last_run init from disk epoch=" << last_run_global << "\n";
                    }
                }
            } else {
                const json vols0 = sn.value("volumes", json::array());
                if (vols0.is_array()) {
                    for (const auto& v : vols0) {
                        if (!v.is_object()) continue;
                        const std::string root = v.value("snap_root", "");
                        const std::string name = v.value("name", "");
                        const std::string src  = v.value("source_subvolume", "");
                        if (root.empty()) continue;

                        // stable key: prefer explicit name, else src, else root
                        const std::string key = !name.empty() ? name : (!src.empty() ? src : root);

                        if (last_run_by_vol.find(key) == last_run_by_vol.end()) {
                            const long long init = latest_snapshot_epoch_under_root(root);
                            if (init > 0) last_run_by_vol[key] = init;
                        }
                    }
                }
            }


            bool any_due = false;

            if (!per_vol) {
                if (last_run_global != 0 && (now - last_run_global) < interval) continue;
                any_due = true; // due for whole batch
            } else {
                // Determine if ANY volume is due; otherwise skip this loop iteration
                const json vols0 = sn.value("volumes", json::array());
                if (!vols0.is_array()) continue;

                for (const auto& v : vols0) {
                    if (!v.is_object()) continue;
                    const std::string root = v.value("snap_root", "");
                    const std::string name = v.value("name", "");
                    const std::string src  = v.value("source_subvolume", "");
                    if (root.empty() || src.empty()) continue;

                    const std::string key = !name.empty() ? name : (!src.empty() ? src : root);
                    const long long lr = last_run_by_vol.count(key) ? last_run_by_vol[key] : 0;

                    // interval for this volume: use v.schedule if present else global
                    const json vs = v.value("schedule", json::object());
                    int v_tpd = vs.value("times_per_day", tpd);
                    if (v_tpd < 1) v_tpd = 1;
                    if (v_tpd > 24) v_tpd = 24;
                    const long long v_interval = 86400LL / (long long)v_tpd;

                    if (lr == 0 || (now - lr) >= v_interval) { any_due = true; break; }
                }

                if (!any_due) continue;
            }


            // jitter (best-effort)
            // A: apply once per batch. B: applied per-volume later.
            if (!per_vol && jitter > 0) {
                std::uniform_int_distribution<int> dist(0, jitter);
                std::this_thread::sleep_for(std::chrono::seconds(dist(rng)));
                if (stop_flag.load()) return;
            }


            // lock (single runner)
            std::string lock_path = "/run/pqnas_snapshot.lock";
            int lock_fd = try_lockfile(lock_path);
            if (lock_fd < 0) {
                lock_path = "/tmp/pqnas_snapshot.lock";
                lock_fd = try_lockfile(lock_path);
            }
            if (lock_fd < 0) continue;

            try {
                const json vols = sn.value("volumes", json::array());

                const json ret_g = sn.value("retention", json::object());
                int keep_days_g = ret_g.value("keep_days", 7);
                int keep_min_g  = ret_g.value("keep_min", 12);
                int keep_max_g  = ret_g.value("keep_max", 500);

                for (const auto& v : vols) {
                    if (stop_flag.load()) break;
                    if (!v.is_object()) continue;

                    const std::string src  = v.value("source_subvolume", "");
                    const std::string root = v.value("snap_root", "");
                    if (src.empty() || root.empty()) continue;

                    const std::string vname = v.value("name", "");
                    const std::string key = !vname.empty() ? vname : (!src.empty() ? src : root);

                    int keep_days = keep_days_g;
                    int keep_min  = keep_min_g;
                    int keep_max  = keep_max_g;

                    int v_tpd = tpd;
                    int v_jitter = jitter;

                    if (per_vol) {
                        const json vs = v.value("schedule", json::object());
                        if (vs.is_object()) {
                            v_tpd    = vs.value("times_per_day", v_tpd);
                            v_jitter = vs.value("jitter_seconds", v_jitter);
                        }

                        if (v_tpd < 1) v_tpd = 1;
                        if (v_tpd > 24) v_tpd = 24;
                        if (v_jitter < 0) v_jitter = 0;
                        if (v_jitter > 3600) v_jitter = 3600;

                        const long long now2 = (long long)std::time(nullptr);
                        const long long v_interval = 86400LL / (long long)v_tpd;
                        const long long lr = last_run_by_vol.count(key) ? last_run_by_vol[key] : 0;

                        if (lr != 0 && (now2 - lr) < v_interval) {
                            continue;
                        }

                        const json vr = v.value("retention", json::object());
                        if (vr.is_object()) {
                            keep_days = vr.value("keep_days", keep_days);
                            keep_min  = vr.value("keep_min", keep_min);
                            keep_max  = vr.value("keep_max", keep_max);
                        }

                        if (v_jitter > 0) {
                            std::uniform_int_distribution<int> dist(0, v_jitter);
                            std::this_thread::sleep_for(std::chrono::seconds(dist(rng)));
                            if (stop_flag.load()) break;
                        }
                    }


                    std::error_code ec;
                    std::filesystem::create_directories(root, ec);
                    if (ec) {
                        std::cerr << "[snapshots] mkdir root failed root=" << root
                                  << " err=" << ec.message() << "\n";
                        continue;
                    }
                    std::cerr << "[snapshots] root=" << root << "\n";

                    const std::string name = make_snapshot_name_utc();
                    const std::string dst  = (std::filesystem::path(root) / name).string();

                    // Ensure dst does not exist (btrfs requires this)
                    {
                        std::error_code ecx;
                        if (std::filesystem::exists(dst, ecx) && !ecx) {
                            (void)prov->delete_subvol(dst); // best-effort
                            std::error_code ec_rm;
                            std::filesystem::remove_all(dst, ec_rm);

                            std::error_code ecx2;
                            if (std::filesystem::exists(dst, ecx2) && !ecx2) {
                                std::cerr << "[snapshots] dst still exists after cleanup, skipping dst=" << dst << "\n";
                                continue;
                            }
                        }
                    }

                    auto r = prov->snapshot_ro(src, dst);
                    if (!r.ok) {
                        std::cerr << "[snapshots] snapshot FAILED src=" << src
                                  << " dst=" << dst << " err=" << r.err << "\n";
                        continue;
                    }

                    std::cerr << "[snapshots] snapshot OK src=" << src << " dst=" << dst << "\n";
                    if (per_vol) {
                        last_run_by_vol[key] = (long long)std::time(nullptr);
                    }


                    // prune after each successful snapshot (your choice)
                    prune_snapshots(*prov, root, keep_days, keep_min, keep_max);
                }

                if (!per_vol) {
                    last_run_global = (long long)std::time(nullptr);
                }

            } catch (...) {}

            unlockfile(lock_path, lock_fd);
        }
    });
}

} // namespace pqnas::snapshots
