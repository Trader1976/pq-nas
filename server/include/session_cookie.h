#pragma once
#include <string>

bool session_cookie_mint(const unsigned char key32[32],
                         const std::string& fingerprint_b64,
                         long iat, long exp,
                         std::string& out_cookie_value);

bool session_cookie_verify(const unsigned char key32[32],
                           const std::string& cookie_value,
                           std::string& out_fingerprint_b64,
                           long& out_exp);
