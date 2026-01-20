#pragma once

#include <string>

#include "httplib.h"

namespace pqnas {
class Allowlist;
}

// Returns true if request has a valid pqnas_session cookie AND it is admin.
// On failure, writes an HTTP error response (401/403) and returns false.
//
// allowlist_path is kept for logging / future fallback loading, but if allowlist != nullptr
// it will be used directly (preferred).
bool require_admin_cookie(const httplib::Request& req,
                          httplib::Response& res,
                          const unsigned char cookie_key[32],
                          const std::string& allowlist_path,
                          const pqnas::Allowlist* allowlist);
