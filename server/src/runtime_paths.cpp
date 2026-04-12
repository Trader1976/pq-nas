#include "runtime_paths.h"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include <unistd.h>

namespace pqnas {
    namespace {

        std::string getenv_str_local(const char* key) {
            if (!key || !*key) return {};
            const char* v = std::getenv(key);
            return v ? std::string(v) : std::string{};
        }

        bool dir_exists_local(const std::filesystem::path& p) {
            std::error_code ec;
            return std::filesystem::is_directory(p, ec) && !ec;
        }

        std::string exe_dir_local() {
            std::vector<char> buf(1024);

            while (true) {
                const ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size());
                if (n < 0) return ".";

                if (static_cast<std::size_t>(n) < buf.size()) {
                    std::filesystem::path p(std::string(buf.data(), static_cast<std::size_t>(n)));
                    auto parent = p.parent_path();
                    return parent.empty() ? std::string(".") : parent.string();
                }

                buf.resize(buf.size() * 2);
            }
        }

    } // namespace

    std::string data_root_dir() {
        const std::string env = getenv_str_local("PQNAS_DATA_ROOT");
        if (!env.empty()) return env;

        const std::string srv = "/srv/pqnas/data";
        if (dir_exists_local(srv)) return srv;

        return exe_dir_local() + "/data";
    }

} // namespace pqnas