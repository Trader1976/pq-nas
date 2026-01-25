#include "system_metrics.h"

/*
 * system_metrics.cc
 *
 * Collects host / OS / CPU / memory / disk / process / network metrics
 * for the PQ-NAS admin UI endpoint:
 *
 *      GET /api/v4/system
 *
 * Linux-only implementation. Relies heavily on:
 *   - /proc
 *   - /etc/os-release
 *   - statvfs()
 *   - uname()
 *
 * All metrics are read-only and safe for unprivileged users.
 *
 * Network throughput is sampled server-side and cached in a small
 * rolling window so the frontend can draw charts without computing
 * deltas itself.
 */

// -----------------------------------------------------------------------------
// STL
// -----------------------------------------------------------------------------
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <limits>
#include <cstdio>
#include <cstdlib>

// -----------------------------------------------------------------------------
// Linux / POSIX
// -----------------------------------------------------------------------------
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <time.h>
#include <linux/limits.h>

// -----------------------------------------------------------------------------
// Forward declarations
//
// collect_system_snapshot() is intentionally placed before the helper
// implementations below so the top of the file reads as:
//
//   - public entrypoint
//   - JSON contract
//   - then implementation details
// -----------------------------------------------------------------------------
static bool parse_proc_loadavg(double& one, double& five, double& fifteen);
static bool parse_proc_uptime(double& uptime_s);
static std::string cpu_model_string();
static bool os_release_pretty(std::string& pretty, std::string& id, std::string& ver);
static bool parse_proc_meminfo_bytes(long long& total_bytes, long long& avail_bytes);
static bool statvfs_bytes(const std::string& path, long long& total, long long& free, long long& used);
static std::string uname_string();
static std::string proc_self_exe();
static bool proc_self_rss_bytes(long long& rss_bytes);
static bool proc_self_start_iso(std::string& started_iso);

// -----------------------------------------------------------------------------
// Network helpers (used by collect_system_snapshot)
//
// These support server-side sampling of network throughput.
// -----------------------------------------------------------------------------
static long long now_ms_utcish();
static void net_maybe_sample_locked(long long now_ms);

// -----------------------------------------------------------------------------
// Network types + globals
//
// MUST be declared before collect_system_snapshot() so the compiler
// knows about them when building the JSON.
//
// All globals here are protected by g_net_mu.
// -----------------------------------------------------------------------------

// Per-interface byte counters read from /proc/net/dev
struct NetCounters {
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
};

// Historical instantaneous rate sample for a single interface
struct NetRatePoint {
    long long t_ms = 0;
    double rx_bps = 0.0;
    double tx_bps = 0.0;
};

// Rolling aggregated sample (total across interfaces)
struct NetSample {
    long long t_ms = 0;
    double rx_bps = 0.0;
    double tx_bps = 0.0;
};

// Mutex protecting all globals below
static std::mutex g_net_mu;

// Last raw counters read per interface
static std::unordered_map<std::string, NetCounters> g_net_last;

// Timestamp of last sample (ms since epoch)
static long long g_net_last_ms = 0;

// Rolling throughput history exposed to UI
static std::vector<NetSample> g_net_series;

// Tuning parameters for chart resolution
static constexpr int NET_HISTORY_POINTS = 120; // ~2 minutes at 1Hz
static constexpr int NET_SAMPLE_MS      = 1000;

// -----------------------------------------------------------------------------
// Public entrypoint namespace
// -----------------------------------------------------------------------------
namespace pqnas {

// Returns ISO-8601 timestamp in UTC with millisecond resolution.
// Used for the sidebar "last updated" indicator.
static std::string now_iso_utc_ms() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);

    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  (int)ms.count());
    return std::string(buf);
}

/*
 * collect_system_snapshot()
 *
 * Builds the JSON payload returned by /api/v4/system.
 *
 * Schema highlights:
 *
 *  {
 *    ok: true,
 *    now_iso,
 *    kernel,
 *    host,
 *    os:{pretty,id,version_id},
 *    cpu:{model,cores,load:{one,five,fifteen}},
 *    uptime_s,
 *    mem:{total_bytes,available_bytes},
 *    disk:{
 *      root:{...},
 *      repo:{...}
 *    },
 *    process:{pid,exe,rss_bytes,started_iso},
 *    net:{
 *      sample_ms,
 *      history_points,
 *      series:[{t_ms,rx_bps,tx_bps}],
 *      counters:{rx_bytes,tx_bytes}
 *    }
 *  }
 */
nlohmann::json collect_system_snapshot(const std::string& repo_root) {
    nlohmann::json out;
    out["ok"] = true;

    // ---------------------------------------------------------------------
    // Timestamp
    // ---------------------------------------------------------------------
    out["now_iso"] = now_iso_utc_ms();

    // ---------------------------------------------------------------------
    // Kernel string from uname()
    // ---------------------------------------------------------------------
    out["kernel"] = uname_string();

    // ---------------------------------------------------------------------
    // Hostname
    // ---------------------------------------------------------------------
    {
        char host[256] = {0};
        if (::gethostname(host, sizeof(host) - 1) == 0)
            out["host"] = std::string(host);
        else
            out["host"] = "";
    }

    // ---------------------------------------------------------------------
    // OS identification from /etc/os-release
    // ---------------------------------------------------------------------
    {
        std::string pretty, id, ver;
        if (os_release_pretty(pretty, id, ver)) {
            out["os"] = {
                {"pretty", pretty},
                {"id", id},
                {"version_id", ver}
            };
        } else {
            out["os"] = {
                {"pretty", ""},
                {"id", ""},
                {"version_id", ""}
            };
        }
    }

    // ---------------------------------------------------------------------
    // CPU info + system load
    // ---------------------------------------------------------------------
    {
        out["cpu"] = nlohmann::json::object();
        out["cpu"]["model"] = cpu_model_string();

        double l1=0, l5=0, l15=0;
        if (parse_proc_loadavg(l1, l5, l15)) {
            out["cpu"]["load"] = {
                {"one", l1},
                {"five", l5},
                {"fifteen", l15}
            };
        } else {
            out["cpu"]["load"] = {
                {"one", nullptr},
                {"five", nullptr},
                {"fifteen", nullptr}
            };
        }

        long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
        if (cores < 1) cores = 1;
        out["cpu"]["cores"] = (int)cores;
    }

    // ---------------------------------------------------------------------
    // System uptime
    // ---------------------------------------------------------------------
    {
        double up = 0.0;
        if (parse_proc_uptime(up)) out["uptime_s"] = up;
        else out["uptime_s"] = nullptr;
    }

    // ---------------------------------------------------------------------
    // Memory totals from /proc/meminfo
    // ---------------------------------------------------------------------
    {
        long long total=0, avail=0;
        if (parse_proc_meminfo_bytes(total, avail)) {
            out["mem"] = {
                {"total_bytes", total},
                {"available_bytes", avail}
            };
        } else {
            out["mem"] = {
                {"total_bytes", nullptr},
                {"available_bytes", nullptr}
            };
        }
    }

    // ---------------------------------------------------------------------
    // Disk usage: root filesystem + repo path
    // ---------------------------------------------------------------------
    {
        out["disk"] = nlohmann::json::object();

        long long t=0,f=0,u=0;
        if (statvfs_bytes("/", t, f, u)) {
            out["disk"]["root"] = {
                {"path","/"},
                {"total_bytes",t},
                {"free_bytes",f},
                {"used_bytes",u}
            };
        } else {
            out["disk"]["root"] = {
                {"path","/"},
                {"total_bytes",nullptr},
                {"free_bytes",nullptr},
                {"used_bytes",nullptr}
            };
        }

        long long t2=0,f2=0,u2=0;
        if (statvfs_bytes(repo_root, t2, f2, u2)) {
            out["disk"]["repo"] = {
                {"path",repo_root},
                {"total_bytes",t2},
                {"free_bytes",f2},
                {"used_bytes",u2}
            };
        } else {
            out["disk"]["repo"] = {
                {"path",repo_root},
                {"total_bytes",nullptr},
                {"free_bytes",nullptr},
                {"used_bytes",nullptr}
            };
        }
    }

    // ---------------------------------------------------------------------
    // Process info for pqnas_server itself
    // ---------------------------------------------------------------------
    {
        out["process"] = nlohmann::json::object();
        out["process"]["pid"] = (int)::getpid();
        out["process"]["exe"] = proc_self_exe();

        long long rss=0;
        if (proc_self_rss_bytes(rss))
            out["process"]["rss_bytes"] = rss;
        else
            out["process"]["rss_bytes"] = nullptr;

        std::string started;
        if (proc_self_start_iso(started))
            out["process"]["started_iso"] = started;
        else
            out["process"]["started_iso"] = nullptr;
    }

    // ---------------------------------------------------------------------
    // Network: server-side sampled throughput + total counters
    //
    // All globals accessed here are protected by g_net_mu.
    // ---------------------------------------------------------------------
    {
        const long long now_ms = now_ms_utcish();

        nlohmann::json net = nlohmann::json::object();
        net["sample_ms"] = NET_SAMPLE_MS;
        net["history_points"] = NET_HISTORY_POINTS;

        {
            std::lock_guard<std::mutex> lk(g_net_mu);

            // Update sampling ring if needed
            net_maybe_sample_locked(now_ms);

            // Build JSON series for UI chart
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : g_net_series) {
                nlohmann::json row = nlohmann::json::object();
                row["t_ms"]  = p.t_ms;
                row["rx_bps"] = p.rx_bps;
                row["tx_bps"] = p.tx_bps;
                arr.push_back(std::move(row));
            }
            net["series"] = std::move(arr);

            // Aggregate counters across interfaces
            unsigned long long rx=0, tx=0;
            for (const auto& kv : g_net_last) {
                rx += kv.second.rx_bytes;
                tx += kv.second.tx_bytes;
            }
            net["counters"] = {
                {"rx_bytes", (uint64_t)rx},
                {"tx_bytes", (uint64_t)tx}
            };
        }

        out["net"] = std::move(net);
    }

    return out;
}

} // namespace pqnas
