#include "path_lock_manager.h"

#include <algorithm>

namespace pqnas {

namespace {
PathLockManager g_path_lock_manager;
}

PathLockManager* get_path_lock_manager() {
    return &g_path_lock_manager;
}

PathLockManager::Guard::Guard(PathLockManager* mgr,
                              std::string fp,
                              std::vector<std::string> paths)
    : mgr_(mgr), fp_(std::move(fp)), paths_(std::move(paths)) {}

PathLockManager::Guard::Guard(Guard&& other) noexcept
    : mgr_(other.mgr_),
      fp_(std::move(other.fp_)),
      paths_(std::move(other.paths_)) {
    other.mgr_ = nullptr;
}

PathLockManager::Guard& PathLockManager::Guard::operator=(Guard&& other) noexcept {
    if (this != &other) {
        release();
        mgr_ = other.mgr_;
        fp_ = std::move(other.fp_);
        paths_ = std::move(other.paths_);
        other.mgr_ = nullptr;
    }
    return *this;
}

PathLockManager::Guard::~Guard() {
    release();
}

void PathLockManager::Guard::release() {
    if (!mgr_) return;
    mgr_->unlock_paths(fp_, paths_);
    mgr_ = nullptr;
}

bool PathLockManager::paths_conflict(const std::string& a, const std::string& b) {
    if (a == b) return true;
    if (a.size() < b.size() && b.rfind(a + "/", 0) == 0) return true;
    if (b.size() < a.size() && a.rfind(b + "/", 0) == 0) return true;
    return false;
}

std::vector<std::string> PathLockManager::canonicalize_paths(std::vector<std::string> paths) {
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    return paths;
}

PathLockManager::Guard PathLockManager::lock_paths(const std::string& fp,
                                                   std::vector<std::string> paths) {
    paths = canonicalize_paths(std::move(paths));

    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&]() {
        for (const auto& want : paths) {
            for (const auto& e : held_) {
                if (e.fp != fp) continue;
                if (paths_conflict(want, e.path)) return false;
            }
        }
        return true;
    });

    for (const auto& p : paths) {
        held_.push_back(Entry{fp, p, 1});
    }

    return Guard(this, fp, std::move(paths));
}

void PathLockManager::unlock_paths(const std::string& fp,
                                   const std::vector<std::string>& paths) {
    std::lock_guard<std::mutex> lk(mu_);

    for (const auto& p : paths) {
        auto it = std::find_if(held_.begin(), held_.end(), [&](const Entry& e) {
            return e.fp == fp && e.path == p;
        });
        if (it != held_.end()) {
            held_.erase(it);
        }
    }

    cv_.notify_all();
}

} // namespace pqnas