#include "policy.h"
#include "allowlist.h"

#include <mutex>
#include <iostream>

namespace pqnas {

static std::mutex g_mu;
static Allowlist g_allow;

bool policy_load_allowlist(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.load(path);
}

bool policy_is_allowed(const std::string& fingerprint_hex) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.is_allowed(fingerprint_hex);
}

bool policy_is_admin(const std::string& fingerprint_hex) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.is_admin(fingerprint_hex);
}

} // namespace pqnas
