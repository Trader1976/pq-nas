#include "drive_health_monitor.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace pqnas {
namespace {

static std::mutex g_mu;
static std::condition_variable g_cv;
static std::thread g_thr;
static std::atomic<bool> g_stop{false};
static bool g_started = false;

static DriveHealthCache g_cache;
static std::unordered_map<std::string, std::string> g_prev_status_by_dev;
static DriveHealthAuditFn g_audit_cb;

static constexpr int DRIVE_HEALTH_REFRESH_SEC = 600;

static std::string now_iso_utc_sec() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);

    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

static bool should_emit_transition(const std::string& prev_status,
                                   const std::string& new_status) {
    if (prev_status.empty()) return false;     // first observation: no audit spam
    if (prev_status == new_status) return false;
    return true;
}

static void refresh_once_lockedless(std::string* err) {
    if (err) err->clear();

    std::vector<DriveHealthInfo> drives;
    std::string probe_err;
    if (!probe_drive_health(&drives, &probe_err)) {
        std::lock_guard<std::mutex> lk(g_mu);
        g_cache.updated_iso = now_iso_utc_sec();
        g_cache.last_error = probe_err.empty() ? "drive probe failed" : probe_err;
        g_cache.ready = true;
        if (err) *err = g_cache.last_error;
        return;
    }

    // Emit transition audits outside lock
    if (g_audit_cb) {
        for (const auto& d : drives) {
            const std::string dev = d.dev;
            const std::string cur = d.health_status;

            std::string prev;
            {
                std::lock_guard<std::mutex> lk(g_mu);
                auto it = g_prev_status_by_dev.find(dev);
                if (it != g_prev_status_by_dev.end()) prev = it->second;
            }

            if (should_emit_transition(prev, cur)) {
                g_audit_cb(d, prev, cur);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_cache.updated_iso = now_iso_utc_sec();
        g_cache.drives = drives;
        g_cache.last_error.clear();
        g_cache.ready = true;

        g_prev_status_by_dev.clear();
        for (const auto& d : drives) {
            g_prev_status_by_dev[d.dev] = d.health_status;
        }
    }
}

static void worker_main() {
    refresh_once_lockedless(nullptr);

    std::unique_lock<std::mutex> lk(g_mu);
    while (!g_stop.load()) {
        g_cv.wait_for(lk, std::chrono::seconds(DRIVE_HEALTH_REFRESH_SEC), [] {
            return g_stop.load();
        });
        if (g_stop.load()) break;

        lk.unlock();
        refresh_once_lockedless(nullptr);
        lk.lock();
    }
}

} // namespace

void drive_health_monitor_start(DriveHealthAuditFn audit_cb) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_started) return;

    g_audit_cb = std::move(audit_cb);
    g_stop.store(false);
    g_started = true;
    g_thr = std::thread(worker_main);
}

void drive_health_monitor_stop() {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_started) return;
        g_stop.store(true);
    }
    g_cv.notify_all();
    if (g_thr.joinable()) g_thr.join();

    std::lock_guard<std::mutex> lk(g_mu);
    g_started = false;
}

bool drive_health_monitor_refresh_now(std::string* err) {
    refresh_once_lockedless(err);

    std::lock_guard<std::mutex> lk(g_mu);
    return g_cache.last_error.empty();
}

DriveHealthCache drive_health_monitor_snapshot() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_cache;
}

} // namespace pqnas