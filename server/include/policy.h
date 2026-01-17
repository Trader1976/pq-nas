#pragma once
#include <string>

bool policy_load_allowlist(const std::string& path);
bool policy_is_allowed(const std::string& fingerprint_b64);
