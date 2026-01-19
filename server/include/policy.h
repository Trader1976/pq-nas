#pragma once
#include <string>

namespace pqnas {

// Load allowlist once at startup (path to allowlist.json)
bool policy_load_allowlist(const std::string& path);

// Checks by fingerprint hex (lower/upper accepted)
bool policy_is_allowed(const std::string& fingerprint_hex);
bool policy_is_admin(const std::string& fingerprint_hex);

} // namespace pqnas