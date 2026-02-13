#include <chrono>
#include <random>
#include <string>
#include <cstdio>
#include <ctime>

namespace pqnas::snapshots {

    std::string make_snapshot_name_utc() {
        using namespace std::chrono;

        static thread_local std::mt19937 gen{std::random_device{}()};

        const auto now = system_clock::now();
        const auto t = system_clock::to_time_t(now);

        std::tm tm{};
        gmtime_r(&t, &tm);

        const auto ms = (int)(duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000);

        std::uniform_int_distribution<int> rnd(0, 9999);
        const int r = rnd(gen);

        char b[96];
        std::snprintf(b, sizeof(b),
            "%04d-%02d-%02dT%02d-%02d-%02d.%03dZ-%04d",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, ms, r);

        return std::string(b);
    }

} // namespace pqnas::snapshots
