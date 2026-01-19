#pragma once
#include <string>
#include <unordered_map>

namespace pqnas {

struct AllowEntry {
    bool admin = false;
    bool user  = false;
};

class Allowlist {
public:
    bool load(const std::string& path);
    bool is_allowed(const std::string& fp_hex) const;
    bool is_admin(const std::string& fp_hex) const;

private:
    std::unordered_map<std::string, AllowEntry> m_;
};

} // namespace pqnas
