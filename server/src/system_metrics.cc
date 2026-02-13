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
#include <iomanip>
#include <cstdint>
#include <algorithm>
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
static bool list_filesystems(std::vector<std::string>& mountpoints,
                             std::unordered_map<std::string, std::string>& mp_source,
                             std::unordered_map<std::string, std::string>& mp_fstype);
static bool is_pseudo_fstype(const std::string& fs);
static bool is_hidden_mount(const std::string& mp);
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
namespace {

// ---- /proc/stat per-core usage sampler ---------------------------------
struct CpuJiffies {
    std::string name; // "cpu", "cpu0", ...
    uint64_t user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
};

static bool read_proc_stat(std::vector<CpuJiffies>& out) {
    out.clear();
    std::ifstream f("/proc/stat");
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu", 0) != 0) break; // stop after cpu lines

        CpuJiffies c;
        std::istringstream iss(line);
        iss >> c.name;
        if (c.name.empty()) continue;

        // cpuN user nice system idle iowait irq softirq steal ...
        iss >> c.user >> c.nice >> c.system >> c.idle >> c.iowait >> c.irq >> c.softirq;
        if (!(iss >> c.steal)) c.steal = 0;

        out.push_back(c);
    }
    return !out.empty();
}

static inline uint64_t idle_all(const CpuJiffies& c) { return c.idle + c.iowait; }
static inline uint64_t nonidle_all(const CpuJiffies& c) { return c.user + c.nice + c.system + c.irq + c.softirq + c.steal; }
static inline uint64_t total_all(const CpuJiffies& c) { return idle_all(c) + nonidle_all(c); }

struct CpuUsage {
    bool ok = false;
    int64_t window_ms = 0;
    double total_pct = 0.0;
    std::vector<double> per_core_pct; // cpu0.. in order
};

static CpuUsage cpu_usage_from_cached_delta() {
    static std::mutex mu;
    static bool have_prev = false;
    static std::vector<CpuJiffies> prev;
    static std::chrono::steady_clock::time_point prev_t;

    std::lock_guard<std::mutex> lock(mu);

    std::vector<CpuJiffies> cur;
    if (!read_proc_stat(cur)) return {};

    const auto now = std::chrono::steady_clock::now();

    CpuUsage out;

    if (!have_prev) {
        prev = std::move(cur);
        prev_t = now;
        have_prev = true;
        return out; // ok=false
    }

    out.window_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - prev_t).count();
    if (out.window_ms < 0) out.window_ms = 0;

    const size_t n = std::min(prev.size(), cur.size());
    if (n == 0) return {};

    auto pct_usage = [](const CpuJiffies& a, const CpuJiffies& b) -> double {
        const uint64_t totald = total_all(b) - total_all(a);
        const uint64_t idled  = idle_all(b)  - idle_all(a);
        if (totald == 0) return 0.0;
        double pct = (double)(totald - idled) * 100.0 / (double)totald;
        if (pct < 0.0) pct = 0.0;
        if (pct > 100.0) pct = 100.0;
        return pct;
    };

    // aggregate "cpu" is index 0
    out.total_pct = pct_usage(prev[0], cur[0]);

    out.per_core_pct.clear();
    for (size_t i = 1; i < n; i++) {
        // accept only cpuN
        if (cur[i].name.rfind("cpu", 0) == 0 && cur[i].name != "cpu") {
            out.per_core_pct.push_back(pct_usage(prev[i], cur[i]));
        }
    }

    out.ok = true;

    prev = std::move(cur);
    prev_t = now;
    return out;
}

} // namespace

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
    // Per-core CPU usage (sampled from /proc/stat deltas)
    {
        auto u = cpu_usage_from_cached_delta();

        nlohmann::json usage;
        usage["ok"] = u.ok;
        usage["window_ms"] = u.window_ms;

        if (u.ok) {
            usage["total_pct"] = u.total_pct;

            nlohmann::json arr = nlohmann::json::array();
            for (double p : u.per_core_pct) arr.push_back(p);
            usage["per_core_pct"] = arr;
        }

        out["cpu"]["usage"] = usage;
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
// Disk usage: root filesystem + repo path + mounted filesystems list
// ---------------------------------------------------------------------
{
    out["disk"] = nlohmann::json::object();
    out["disk"]["repo_root"] = repo_root;

    // Back-compat: root filesystem
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

    // Back-compat: repo path
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

    // New: mounted filesystems list (mountpoints)
    std::vector<std::string> mps;
    std::unordered_map<std::string, std::string> mp_src;
    std::unordered_map<std::string, std::string> mp_fs;

    nlohmann::json arr = nlohmann::json::array();

    if (list_filesystems(mps, mp_src, mp_fs)) {
        for (const auto& mp : mps) {
            if (is_hidden_mount(mp)) continue;

            long long tt=0, ff=0, uu=0;
            if (!statvfs_bytes(mp, tt, ff, uu)) continue;

            const std::string src = mp_src.count(mp) ? mp_src[mp] : "";
            const std::string fs  = mp_fs.count(mp)  ? mp_fs[mp]  : "";

            // Skip pseudo filesystems (proc, sysfs, tmpfs, overlay, …)
            if (is_pseudo_fstype(fs)) continue;

            arr.push_back({
                {"mountpoint", mp},
                {"source", src},
                {"fstype", fs},
                {"total_bytes", tt},
                {"free_bytes", ff},
                {"used_bytes", uu}
            });
        }
    }

    out["disk"]["filesystems"] = std::move(arr);
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


// -----------------------------------------------------------------------------
// Helper implementations
// -----------------------------------------------------------------------------

static std::string trim_ws(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

static std::string unquote(const std::string& s) {
    if (s.size() >= 2) {
        if ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\'')) {
            return s.substr(1, s.size() - 2);
        }
    }
    return s;
}

static bool parse_proc_loadavg(double& one, double& five, double& fifteen) {
    std::ifstream f("/proc/loadavg");
    if (!f.good()) return false;
    f >> one >> five >> fifteen;
    return f.good();
}

static bool parse_proc_uptime(double& uptime_s) {
    std::ifstream f("/proc/uptime");
    if (!f.good()) return false;
    f >> uptime_s;
    return f.good();
}

static std::string cpu_model_string() {
    std::ifstream f("/proc/cpuinfo");
    if (!f.good()) return "";

    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string key = trim_ws(line.substr(0, pos));
        if (key == "model name" || key == "Hardware" || key == "Processor") {
            return trim_ws(line.substr(pos + 1));
        }
    }
    return "";
}

static bool os_release_pretty(std::string& pretty, std::string& id, std::string& ver) {
    std::ifstream f("/etc/os-release");
    if (!f.good()) return false;

    std::string pretty_v, id_v, ver_v;

    std::string line;
    while (std::getline(f, line)) {
        line = trim_ws(line);
        if (line.empty() || line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string k = trim_ws(line.substr(0, eq));
        std::string v = unquote(trim_ws(line.substr(eq + 1)));

        if (k == "PRETTY_NAME") pretty_v = v;
        else if (k == "ID") id_v = v;
        else if (k == "VERSION_ID") ver_v = v;
    }

    pretty = pretty_v;
    id = id_v;
    ver = ver_v;
    return !(pretty.empty() && id.empty() && ver.empty());
}

static bool parse_proc_meminfo_bytes(long long& total_bytes, long long& avail_bytes) {
    std::ifstream f("/proc/meminfo");
    if (!f.good()) return false;

    long long total_kb = -1;
    long long avail_kb = -1;

    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("MemTotal:", 0) == 0) {
            std::istringstream iss(line);
            std::string k;
            iss >> k >> total_kb;
        } else if (line.rfind("MemAvailable:", 0) == 0) {
            std::istringstream iss(line);
            std::string k;
            iss >> k >> avail_kb;
        }
        if (total_kb >= 0 && avail_kb >= 0) break;
    }

    if (total_kb < 0 || avail_kb < 0) return false;
    total_bytes = total_kb * 1024LL;
    avail_bytes = avail_kb * 1024LL;
    return true;
}

static bool statvfs_bytes(const std::string& path, long long& total, long long& free, long long& used) {
    struct statvfs v {};
    if (::statvfs(path.c_str(), &v) != 0) return false;

    const unsigned long long bs = (v.f_frsize ? v.f_frsize : v.f_bsize);
    const unsigned long long tot = bs * (unsigned long long)v.f_blocks;
    const unsigned long long fre = bs * (unsigned long long)v.f_bavail; // available to non-root
    const unsigned long long usd = (tot >= fre) ? (tot - fre) : 0ULL;

    total = (long long)tot;
    free  = (long long)fre;
    used  = (long long)usd;
    return true;
}

static std::string uname_string() {
    struct utsname u {};
    if (::uname(&u) != 0) return "";
    std::ostringstream ss;
    ss << u.sysname << " " << u.release << " " << u.version << " " << u.machine;
    return ss.str();
}

static std::string proc_self_exe() {
    char buf[PATH_MAX + 1];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}

static bool proc_self_rss_bytes(long long& rss_bytes) {
    std::ifstream f("/proc/self/status");
    if (!f.good()) return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            // VmRSS:   12345 kB
            std::istringstream iss(line);
            std::string k;
            long long kb = 0;
            std::string unit;
            iss >> k >> kb >> unit;
            if (kb <= 0) return false;
            rss_bytes = kb * 1024LL;
            return true;
        }
    }
    return false;
}

static bool proc_self_start_iso(std::string& started_iso) {
    // Derive process start time using:
    //   boot time (btime) from /proc/stat + starttime ticks from /proc/self/stat
    std::ifstream f("/proc/self/stat");
    if (!f.good()) return false;

    std::string stat;
    std::getline(f, stat);
    if (stat.empty()) return false;

    // comm is "(...)" and may contain spaces, so find the last ')'
    auto rp = stat.rfind(')');
    if (rp == std::string::npos) return false;

    // After ") " we start at field 3 (state)
    std::istringstream iss(stat.substr(rp + 2));
    std::vector<std::string> fields;
    std::string tok;
    while (iss >> tok) fields.push_back(tok);

    // Need up to overall field 22 (starttime). In this shifted list:
    // index = 22 - 3 = 19
    const int start_idx = 22 - 3;
    if ((int)fields.size() <= start_idx) return false;

    long long start_ticks = 0;
    try { start_ticks = std::stoll(fields[start_idx]); }
    catch (...) { return false; }

    long long hz = ::sysconf(_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    double start_s_since_boot = (double)start_ticks / (double)hz;

    // Read btime (boot time epoch seconds)
    std::ifstream fs("/proc/stat");
    if (!fs.good()) return false;

    long long btime = 0;
    std::string line;
    while (std::getline(fs, line)) {
        if (line.rfind("btime ", 0) == 0) {
            std::istringstream ls(line);
            std::string k;
            ls >> k >> btime;
            break;
        }
    }
    if (btime <= 0) return false;

    long long start_epoch = btime + (long long)start_s_since_boot;

    std::time_t tt = (std::time_t)start_epoch;
    std::tm tm {};
    gmtime_r(&tt, &tm);

    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    started_iso = out.str();
    return true;
}

static long long now_ms_utcish() {
    using namespace std::chrono;
    auto now = time_point_cast<milliseconds>(system_clock::now());
    return (long long)now.time_since_epoch().count();
}

// --- network internals ---

static bool read_proc_net_dev(std::unordered_map<std::string, NetCounters>& out) {
    std::ifstream f("/proc/net/dev");
    if (!f.good()) return false;

    std::string line;
    // skip headers (2 lines)
    std::getline(f, line);
    std::getline(f, line);

    while (std::getline(f, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string iface = trim_ws(line.substr(0, colon));
        std::string rest  = line.substr(colon + 1);

        if (iface.empty()) continue;
        if (iface == "lo") continue;

        // Format: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast
        //         tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed
        std::istringstream iss(rest);

        unsigned long long rx_bytes = 0;
        if (!(iss >> rx_bytes)) continue;

        // skip 7 rx fields to reach tx_bytes
        for (int i = 0; i < 7; i++) {
            unsigned long long dummy = 0;
            if (!(iss >> dummy)) { rx_bytes = 0; break; }
        }

        unsigned long long tx_bytes = 0;
        if (!(iss >> tx_bytes)) continue;

        NetCounters c;
        c.rx_bytes = rx_bytes;
        c.tx_bytes = tx_bytes;
        out[iface] = c;
    }
    return true;
}

static bool is_pseudo_fstype(const std::string& fs) {
    // Expand as you like; these are “not real disks”
    static const char* k[] = {
        "proc","sysfs","devtmpfs","devpts","tmpfs","cgroup","cgroup2","pstore",
        "securityfs","tracefs","debugfs","hugetlbfs","mqueue","fusectl",
        "overlay","squashfs","ramfs","autofs","binfmt_misc"
    };
    for (auto s : k) if (fs == s) return true;
    return false;
}

static bool is_hidden_mount(const std::string& mp) {
    // Hide noisy internals; keep / and “real” mounts
    if (mp.empty()) return true;
    if (mp == "/") return false;

    if (mp == "/boot" || mp == "/boot/efi") return true;

    // Common internal mount roots
    if (mp.rfind("/proc", 0) == 0) return true;
    if (mp.rfind("/sys", 0) == 0) return true;
    if (mp.rfind("/dev", 0) == 0) return true;
    if (mp.rfind("/run", 0) == 0) return true;

    // Remove unwanted noise
    if (mp.rfind("/snap", 0) == 0) return true;
    if (mp.rfind("/var/snap", 0) == 0) return true;
    if (mp.rfind("/var/lib/snapd", 0) == 0) return true;
    if (mp.rfind("/var/lib/flatpak", 0) == 0) return true;

    // Snap/flatpak noise (optional)
    if (mp.rfind("/snap", 0) == 0) return true;
    if (mp.rfind("/var/lib/snapd", 0) == 0) return true;

    return false;
}

static bool list_filesystems(std::vector<std::string>& mountpoints,
                             std::unordered_map<std::string, std::string>& mp_source,
                             std::unordered_map<std::string, std::string>& mp_fstype) {
    mountpoints.clear();
    mp_source.clear();
    mp_fstype.clear();

    std::ifstream f("/proc/self/mountinfo");
    if (!f.good()) return false;

    // mountinfo format:
    // id parent major:minor root mount_point options ... - fstype source superoptions
    std::string line;
    std::unordered_map<std::string, bool> seen;

    while (std::getline(f, line)) {
        if (line.empty()) continue;

        // split around " - "
        const std::string sep = " - ";
        auto pos = line.find(sep);
        if (pos == std::string::npos) continue;

        const std::string left = line.substr(0, pos);
        const std::string right = line.substr(pos + sep.size());

        // Left side tokens: we need token #5 = mount_point (1-based)
        // left: id(1) parent(2) major:minor(3) root(4) mount_point(5) ...
        std::istringstream lss(left);
        std::string tok;
        std::string mount_point;
        int idx = 0;
        while (lss >> tok) {
            idx++;
            if (idx == 5) { mount_point = tok; break; }
        }
        if (mount_point.empty()) continue;

        // Right side: fstype + source + superoptions...
        std::istringstream rss(right);
        std::string fstype, source;
        rss >> fstype >> source;
        if (fstype.empty()) fstype = "";
        if (source.empty()) source = "";

        if (!seen[mount_point]) {
            seen[mount_point] = true;
            mountpoints.push_back(mount_point);
        }

        mp_fstype[mount_point] = fstype;
        mp_source[mount_point] = source;
    }

    // Sort: show / first, then lexicographic
    std::sort(mountpoints.begin(), mountpoints.end(), [](const std::string& a, const std::string& b){
        if (a == "/") return true;
        if (b == "/") return false;
        return a < b;
    });

    return true;
}



static void net_maybe_sample_locked(long long now_ms) {
    // Called with g_net_mu held.
    if (g_net_last_ms != 0 && (now_ms - g_net_last_ms) < NET_SAMPLE_MS) return;

    std::unordered_map<std::string, NetCounters> cur;
    if (!read_proc_net_dev(cur)) return;

    // First-ever sample: just store counters; no rate yet.
    if (g_net_last_ms == 0 || g_net_last.empty()) {
        g_net_last = std::move(cur);
        g_net_last_ms = now_ms;
        return;
    }

    const long long dt_ms = now_ms - g_net_last_ms;
    if (dt_ms <= 0) {
        g_net_last = std::move(cur);
        g_net_last_ms = now_ms;
        return;
    }

    // Aggregate delta across interfaces present in current snapshot.
    unsigned long long d_rx = 0;
    unsigned long long d_tx = 0;

    for (const auto& kv : cur) {
        const auto& iface = kv.first;
        const auto& c = kv.second;

        auto it = g_net_last.find(iface);
        if (it == g_net_last.end()) continue;

        const auto& p = it->second;

        if (c.rx_bytes >= p.rx_bytes) d_rx += (c.rx_bytes - p.rx_bytes);
        if (c.tx_bytes >= p.tx_bytes) d_tx += (c.tx_bytes - p.tx_bytes);
    }

    const double dt_s = (double)dt_ms / 1000.0;

    NetSample s;
    s.t_ms = now_ms;
    s.rx_bps = dt_s > 0 ? ((double)d_rx / dt_s) : 0.0;
    s.tx_bps = dt_s > 0 ? ((double)d_tx / dt_s) : 0.0;

    g_net_series.push_back(s);
    if ((int)g_net_series.size() > NET_HISTORY_POINTS) {
        g_net_series.erase(g_net_series.begin(),
                           g_net_series.begin() + (g_net_series.size() - NET_HISTORY_POINTS));
    }

    g_net_last = std::move(cur);
    g_net_last_ms = now_ms;
}
