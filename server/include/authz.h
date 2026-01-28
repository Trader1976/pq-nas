#pragma once

#include <string>

#include "httplib.h"

namespace pqnas {
class Allowlist;
}

namespace pqnas { class UsersRegistry; }


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


bool require_admin_cookie_users(const httplib::Request& req,
                                httplib::Response& res,
                                const unsigned char cookie_key[32],
                                const std::string& users_path,
                                const pqnas::UsersRegistry* users);


bool require_admin_cookie_users_actor(const httplib::Request& req,
                                      httplib::Response& res,
                                      const unsigned char cookie_key[32],
                                      const std::string& users_path,
                                      const pqnas::UsersRegistry* users,
                                      std::string* out_admin_fp_hex);

bool is_admin_cookie(const httplib::Request& req,
                     const unsigned char cookie_key[32],
                     const pqnas::Allowlist* allowlist,
                     std::string* out_fp_hex = nullptr);
