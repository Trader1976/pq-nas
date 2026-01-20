#pragma once
#include <string>
#include "httplib.h"

bool require_admin_cookie(const httplib::Request& req,
                          httplib::Response& res,
                          const unsigned char cookie_key[32],
                          const std::string& allowlist_path,
                          std::string* out_fingerprint_hex);

bool verify_mldsa87_signature_native(const std::vector<unsigned char>& pubkey,
                                     const std::vector<unsigned char>& msg,
                                     const std::vector<unsigned char>& sig);