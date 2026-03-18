#pragma once

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pqnas {

    class PathLockManager {
    public:
        class Guard {
        public:
            Guard() = default;
            Guard(PathLockManager* mgr,
                  std::string fp,
                  std::vector<std::string> paths);
            Guard(const Guard&) = delete;
            Guard& operator=(const Guard&) = delete;
            Guard(Guard&& other) noexcept;
            Guard& operator=(Guard&& other) noexcept;
            ~Guard();

            explicit operator bool() const noexcept { return mgr_ != nullptr; }

        private:
            void release();

            PathLockManager* mgr_ = nullptr;
            std::string fp_;
            std::vector<std::string> paths_;
        };

        Guard lock_paths(const std::string& fp, std::vector<std::string> paths);

    private:
        struct Entry {
            std::string fp;
            std::string path;
            std::uint64_t holders = 0;
        };

        static bool paths_conflict(const std::string& a, const std::string& b);
        static std::vector<std::string> canonicalize_paths(std::vector<std::string> paths);

        void unlock_paths(const std::string& fp, const std::vector<std::string>& paths);

        std::mutex mu_;
        std::condition_variable cv_;
        std::vector<Entry> held_;
    };

    PathLockManager* get_path_lock_manager();

} // namespace pqnas