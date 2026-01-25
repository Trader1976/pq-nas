#include "system_metrics.h"

// STL
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

// Linux / POSIX
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <time.h>
#include <linux/limits.h>

// Forward declarations (collect_system_snapshot is placed before the helpers below)
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

// Net helpers (used by collect_system_snapshot)
static long long now_ms_utcish();
static void net_maybe_sample_locked(long long now_ms);

// ----- Net types + globals MUST be declared before collect_system_snapshot ----
struct NetCounters {
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
};

struct NetRatePoint {
    long long t_ms = 0;
    double rx_bps = 0.0;
    double tx_bps = 0.0;
};

// a small rolling series of bps samples (total across interfaces)
struct NetSample {
    long long t_ms = 0;
    double rx_bps = 0.0;
    double tx_bps = 0.0;
};

// server-side history: iface -> ring of points
static std::mutex g_net_mu;
static std::unordered_map<std::string, std::deque<NetRatePoint>> g_net_hist;
static std::unordered_map<std::string, NetCounters> g_net_last;
static long long g_net_last_ms = 0;

static std::vector<NetSample> g_net_series;

// tuning
static constexpr int NET_HISTORY_POINTS = 120;     // e.g. 120 points
static constexpr int NET_SAMPLE_MS      = 1000;    // 1s sampling

// ---- End of net pre-decls ---------------------------------------------------

namespace pqnas {

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

nlohmann::json collect_system_snapshot(const std::string& repo_root) {
    nlohmann::json out;
    out["ok"] = true;

    // now_iso
    out["now_iso"] = now_iso_utc_ms();

    // kernel (uname)
    out["kernel"] = uname_string();

    // host (hostname)
    {
        char host[256] = {0};
        if (::gethostname(host, sizeof(host) - 1) == 0) out["host"] = std::string(host);
        else out["host"] = "";
    }

    // os.{pretty,id,version_id}
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

    // cpu.{model,load{one,five,fifteen},cores}
    {
        out["cpu"] = nlohmann::json::object();
        out["cpu"]["model"] = cpu_model_string();

        double l1=0, l5=0, l15=0;
        if (parse_proc_loadavg(l1, l5, l15)) {
            out["cpu"]["load"] = {{"one", l1}, {"five", l5}, {"fifteen", l15}};
        } else {
            out["cpu"]["load"] = {{"one", nullptr}, {"five", nullptr}, {"fifteen", nullptr}};
        }

        long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
        if (cores < 1) cores = 1;
        out["cpu"]["cores"] = (int)cores;
    }

    // uptime_s
    {
        double up = 0.0;
        if (parse_proc_uptime(up)) out["uptime_s"] = up;
        else out["uptime_s"] = nullptr;
    }

    // mem.{total_bytes,available_bytes}
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

    // disk.{root{...},repo{...}}
    {
        out["disk"] = nlohmann::json::object();

        long long t=0,f=0,u=0;
        if (statvfs_bytes("/", t, f, u)) {
            out["disk"]["root"] = {{"path","/"},{"total_bytes",t},{"free_bytes",f},{"used_bytes",u}};
        } else {
            out["disk"]["root"] = {{"path","/"},{"total_bytes",nullptr},{"free_bytes",nullptr},{"used_bytes",nullptr}};
        }

        long long t2=0,f2=0,u2=0;
        if (statvfs_bytes(repo_root, t2, f2, u2)) {
            out["disk"]["repo"] = {{"path",repo_root},{"total_bytes",t2},{"free_bytes",f2},{"used_bytes",u2}};
        } else {
            out["disk"]["repo"] = {{"path",repo_root},{"total_bytes",nullptr},{"free_bytes",nullptr},{"used_bytes",nullptr}};
        }
    }

    // process.{pid,exe,rss_bytes,started_iso}
    {
        out["process"] = nlohmann::json::object();
        out["process"]["pid"] = (int)::getpid();
        out["process"]["exe"] = proc_self_exe();

        long long rss=0;
        if (proc_self_rss_bytes(rss)) out["process"]["rss_bytes"] = rss;
        else out["process"]["rss_bytes"] = nullptr;

        std::string started;
        if (proc_self_start_iso(started)) out["process"]["started_iso"] = started;
        else out["process"]["started_iso"] = nullptr;
    }

    // net (server-side rolling series + counters)
    // Shape: { sample_ms, history_points, series:[{t_ms,rx_bps,tx_bps}...], counters:{rx_bytes,tx_bytes} }
    {
        const long long now_ms = now_ms_utcish();

        nlohmann::json net = nlohmann::json::object();
        net["sample_ms"] = NET_SAMPLE_MS;
        net["history_points"] = NET_HISTORY_POINTS;

        {
            std::lock_guard<std::mutex> lk(g_net_mu);
            net_maybe_sample_locked(now_ms);

            // series
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : g_net_series) {
                nlohmann::json row = nlohmann::json::object();
                row["t_ms"]  = p.t_ms;
                row["rx_bps"] = p.rx_bps;
                row["tx_bps"] = p.tx_bps;
                arr.push_back(std::move(row));
            }
            net["series"] = std::move(arr);

            // counters (total across interfaces)
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



// ----- System metrics collectors (Linux) ------------------------------------
static bool read_first_line(const std::string& path, std::string& out) {
    std::ifstream f(path);
    if (!f.good()) return false;
    std::getline(f, out);
    return true;
}

static bool read_all_text(const std::string& path, std::string& out) {
    std::ifstream f(path);
    if (!f.good()) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static bool parse_proc_loadavg(double& one, double& five, double& fifteen) {
    std::string s;
    if (!read_first_line("/proc/loadavg", s)) return false;
    std::istringstream iss(s);
    iss >> one >> five >> fifteen;
    return iss.good();
}

static bool parse_proc_uptime(double& uptime_s) {
    std::string s;
    if (!read_first_line("/proc/uptime", s)) return false;
    std::istringstream iss(s);
    iss >> uptime_s;
    return iss.good();
}

static bool read_first_match_kv(const std::string& path,
                                const std::string& key_prefix,
                                std::string& out_value) {
    std::ifstream f(path);
    if (!f.good()) return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind(key_prefix, 0) == 0) {
            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            std::string v = line.substr(pos + 1);
            // trim
            while (!v.empty() && (v.front()==' ' || v.front()=='\t')) v.erase(v.begin());
            while (!v.empty() && (v.back()==' ' || v.back()=='\t' || v.back()=='\r' || v.back()=='\n')) v.pop_back();
            out_value = v;
            return true;
        }
    }
    return false;
}

static std::string cpu_model_string() {
    std::string model;
    if (read_first_match_kv("/proc/cpuinfo", "model name", model)) return model;
    return "";
}

static bool os_release_pretty(std::string& pretty, std::string& id, std::string& ver) {
    std::ifstream f("/etc/os-release");
    if (!f.good()) return false;

    auto unquote = [](std::string s) {
        if (s.size() >= 2 && ((s.front()=='"' && s.back()=='"') || (s.front()=='\'' && s.back()=='\'')))
            return s.substr(1, s.size()-2);
        return s;
    };

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0]=='#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = unquote(line.substr(eq + 1));

        if (k == "PRETTY_NAME") pretty = v;
        else if (k == "ID") id = v;
        else if (k == "VERSION_ID") ver = v;
    }
    return !pretty.empty() || !id.empty() || !ver.empty();
}

static bool parse_proc_meminfo_bytes(long long& total_bytes, long long& avail_bytes) {
    // MemTotal + MemAvailable (kB)
    std::ifstream f("/proc/meminfo");
    if (!f.good()) return false;

    long long mem_total_kb = -1;
    long long mem_avail_kb = -1;

    std::string key;
    long long val;
    std::string unit;

    while (f >> key >> val >> unit) {
        if (key == "MemTotal:") mem_total_kb = val;
        if (key == "MemAvailable:") mem_avail_kb = val;
        if (mem_total_kb >= 0 && mem_avail_kb >= 0) break;
    }

    if (mem_total_kb < 0 || mem_avail_kb < 0) return false;
    total_bytes = mem_total_kb * 1024LL;
    avail_bytes = mem_avail_kb * 1024LL;
    return true;
}

static bool statvfs_bytes(const std::string& path, long long& total, long long& free, long long& used) {
    struct statvfs v{};
    if (::statvfs(path.c_str(), &v) != 0) return false;

    const unsigned long long frsize = v.f_frsize ? v.f_frsize : v.f_bsize;
    const unsigned long long total_b = (unsigned long long)v.f_blocks * frsize;
    const unsigned long long free_b  = (unsigned long long)v.f_bavail * frsize;

    total = (long long)total_b;
    free  = (long long)free_b;
    used  = (long long)(total_b - free_b);
    return true;
}

static std::string uname_string() {
    struct utsname u{};
    if (::uname(&u) != 0) return "";
    return std::string(u.sysname) + " " + u.release;
}

static bool proc_self_rss_bytes(long long& rss_bytes) {
    // /proc/self/statm: size resident share text lib data dt
    std::ifstream f("/proc/self/statm");
    if (!f.good()) return false;

    long long size_pages = 0;
    long long resident_pages = 0;
    f >> size_pages >> resident_pages;
    if (!f.good()) return false;

    long long page = (long long)::sysconf(_SC_PAGESIZE);
    rss_bytes = resident_pages * page;
    return true;
}

static std::string proc_self_exe() {
    char buf[PATH_MAX] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    return std::string(buf, (size_t)n);
}

static bool proc_boot_time_epoch(long long& btime_epoch) {
    std::ifstream f("/proc/stat");
    if (!f.good()) return false;
    std::string k;
    long long v;
    while (f >> k >> v) {
        if (k == "btime") { btime_epoch = v; return true; }
        // skip rest of line quickly
        f.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    return false;
}

static bool proc_self_start_iso(std::string& started_iso) {
    // /proc/self/stat field 22 = starttime in clock ticks since boot
    std::string s;
    if (!read_all_text("/proc/self/stat", s)) return false;

    // stat format: pid (comm) state ppid ... starttime ...
    // comm can contain spaces, so find last ')' to skip it.
    auto rp = s.rfind(')');
    if (rp == std::string::npos) return false;

    // tokenise after ") "
    std::string after = s.substr(rp + 2);
    std::istringstream iss(after);

    // We need to find field #22 overall => after comm, fields start at 3.
    // starttime is field 22 => after comm it is field (22-2)=20 in this stream.
    // i.e. the 20th token in `after` (1-based).
    std::string tok;
    long long start_ticks = -1;
    for (int i = 1; i <= 20; i++) {
        if (!(iss >> tok)) return false;
        if (i == 20) {
            try { start_ticks = std::stoll(tok); } catch (...) { return false; }
        }
    }

    long long btime = 0;
    if (!proc_boot_time_epoch(btime)) return false;

    const long long hz = (long long)::sysconf(_SC_CLK_TCK);
    if (hz <= 0) return false;

    // process start epoch seconds ≈ boot_time + start_ticks/hz
    long long start_epoch = btime + (start_ticks / hz);

    std::time_t t = (std::time_t)start_epoch;
    std::tm tm{};
    gmtime_r(&t, &tm);

    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);

    started_iso = buf;
    return true;
}

static long long now_ms_utcish() {
    using namespace std::chrono;
    return (long long)duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static bool read_proc_net_dev(std::unordered_map<std::string, NetCounters>& out) {
    std::ifstream f("/proc/net/dev");
    if (!f.good()) return false;

    std::string line;
    // skip 2 header lines
    std::getline(f, line);
    std::getline(f, line);

    while (std::getline(f, line)) {
        // format: "  eth0: 123 0 0 0 0 0 0 0  456 0 0 0 0 0 0 0"
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string ifname = line.substr(0, colon);
        // trim spaces
        ifname.erase(0, ifname.find_first_not_of(" \t"));
        ifname.erase(ifname.find_last_not_of(" \t") + 1);

        std::istringstream iss(line.substr(colon + 1));
        unsigned long long rx_bytes=0, rx_packets=0, rx_err=0, rx_drop=0, rx_fifo=0, rx_frame=0, rx_comp=0, rx_mcast=0;
        unsigned long long tx_bytes=0, tx_packets=0, tx_err=0, tx_drop=0, tx_fifo=0, tx_colls=0, tx_carrier=0, tx_comp=0;

        if (!(iss >> rx_bytes >> rx_packets >> rx_err >> rx_drop >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast
                  >> tx_bytes >> tx_packets >> tx_err >> tx_drop >> tx_fifo >> tx_colls >> tx_carrier >> tx_comp)) {
            continue;
        }

        out[ifname] = NetCounters{rx_bytes, tx_bytes};
    }

    return true;
}

// Call with g_net_mu held.
// Samples at most once per ~1000ms, keeps last ~120 samples (≈2 minutes at 1Hz).
static void net_maybe_sample_locked(long long now_ms) {
    const long long min_interval_ms = 1000;

    if (g_net_last_ms != 0 && (now_ms - g_net_last_ms) < min_interval_ms) return;

    std::unordered_map<std::string, NetCounters> cur;
    if (!read_proc_net_dev(cur)) return;

    // sum across interfaces (you can later exclude lo if you want)
    unsigned long long cur_rx = 0, cur_tx = 0;
    for (const auto& kv : cur) {
        cur_rx += kv.second.rx_bytes;
        cur_tx += kv.second.tx_bytes;
    }

    unsigned long long last_rx = 0, last_tx = 0;
    if (!g_net_last.empty()) {
        for (const auto& kv : g_net_last) {
            last_rx += kv.second.rx_bytes;
            last_tx += kv.second.tx_bytes;
        }
    }

    double rx_bps = 0.0, tx_bps = 0.0;
    if (g_net_last_ms != 0) {
        const double dt = (double)(now_ms - g_net_last_ms) / 1000.0;
        if (dt > 0.0) {
            rx_bps = ((double)(cur_rx - last_rx) / dt);
            tx_bps = ((double)(cur_tx - last_tx) / dt);
        }
    }

    g_net_last = std::move(cur);
    g_net_last_ms = now_ms;

    g_net_series.push_back(NetSample{now_ms, rx_bps, tx_bps});
    if (g_net_series.size() > (size_t)NET_HISTORY_POINTS) {
        g_net_series.erase(g_net_series.begin(),
                           g_net_series.begin() + ((long long)g_net_series.size() - NET_HISTORY_POINTS));
    }
}
