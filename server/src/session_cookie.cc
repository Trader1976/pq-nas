#include "session_cookie.h"
#include <sodium.h>
#include <cstdlib>
#include <cstring>

static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(strlen(out.c_str()));
    return out;
}

static bool b64url_dec(const std::string& s, std::string& outBin) {
    outBin.resize(s.size());
    size_t out_len = 0;
    if (sodium_base642bin((unsigned char*)outBin.data(), outBin.size(),
                          s.c_str(), s.size(),
                          nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return false;
    }
    outBin.resize(out_len);
    return true;
}

bool session_cookie_mint(const unsigned char key32[32],
                         const std::string& fingerprint_b64,
                         long iat, long exp,
                         std::string& out_cookie_value) {
    // compact JSON
    std::string claims = std::string("{")
        + "\"fp\":\"" + fingerprint_b64 + "\","
        + "\"iat\":" + std::to_string(iat) + ","
        + "\"exp\":" + std::to_string(exp)
        + "}";

    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key32, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)claims.data(), claims.size());
    crypto_auth_hmacsha256_final(&st, mac);

    out_cookie_value = b64url_enc((const unsigned char*)claims.data(), claims.size())
        + "." + b64url_enc(mac, sizeof(mac));
    return true;
}

bool session_cookie_verify(const unsigned char key32[32],
                           const std::string& cookie_value,
                           std::string& out_fingerprint_b64,
                           long& out_exp) {
    auto dot = cookie_value.find('.');
    if (dot == std::string::npos) return false;

    std::string c1 = cookie_value.substr(0, dot);
    std::string c2 = cookie_value.substr(dot + 1);

    std::string claims;
    if (!b64url_dec(c1, claims)) return false;

    std::string macBin;
    if (!b64url_dec(c2, macBin)) return false;
    if (macBin.size() != crypto_auth_hmacsha256_BYTES) return false;

    unsigned char mac2[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key32, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)claims.data(), claims.size());
    crypto_auth_hmacsha256_final(&st, mac2);

    if (sodium_memcmp(mac2, macBin.data(), crypto_auth_hmacsha256_BYTES) != 0) return false;

    // extract fp
    auto p = claims.find("\"fp\":\"");
    if (p == std::string::npos) return false;
    p += 6;
    auto q = claims.find('"', p);
    if (q == std::string::npos) return false;
    out_fingerprint_b64 = claims.substr(p, q - p);

    // extract exp
    auto e = claims.find("\"exp\":");
    if (e == std::string::npos) return false;
    out_exp = std::strtol(claims.c_str() + e + 6, nullptr, 10);
    return true;
}
