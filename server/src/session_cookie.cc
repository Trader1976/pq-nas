#include "session_cookie.h"

/*
 * session_cookie.cc
 *
 * PQ-NAS session cookie format (v4):
 *
 *   cookie_value := b64url_no_pad(claims_json) "." b64url_no_pad(hmac_sha256(claims_json, key32))
 *
 * Where claims_json is a compact JSON string like:
 *   {"fp":"<fingerprint_b64>","iat":<unix_sec>,"exp":<unix_sec>}
 *
 * Security properties:
 * - Integrity/authenticity: HMAC-SHA256 over the exact claims bytes.
 * - Tamper detection: any modification to claims invalidates MAC.
 *
 * Notes:
 * - This is NOT encryption: the claims are only base64url-encoded, so fp/iat/exp are visible.
 * - We intentionally use URLSAFE_NO_PADDING so the cookie value is header-safe.
 * - Parsing is intentionally minimal and assumes our minting format.
 *
 * Hard requirement:
 * - libsodium must be initialized (sodium_init()) somewhere early in process startup.
 */

#include <sodium.h>
#include <cstdlib>
#include <cstring>

// -----------------------------------------------------------------------------
// Base64url helpers (no padding)
// -----------------------------------------------------------------------------

// Encode arbitrary binary to URL-safe base64 without padding.
// We trim the trailing '\0' that libsodium writes into the output buffer.
static std::string b64url_enc(const unsigned char* data, size_t len) {
    const size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');

    sodium_bin2base64(out.data(), out.size(),
                      data, len,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    // libsodium guarantees a NUL-terminated string. Shrink to actual C-string length.
    out.resize(std::strlen(out.c_str()));
    return out;
}

// Decode URL-safe base64 (no padding) into binary bytes.
// `outBin` is resized to the actual decoded length.
static bool b64url_dec(const std::string& s, std::string& outBin) {
    // Decoded length is <= encoded length, so this is a safe upper bound.
    outBin.resize(s.size());

    size_t out_len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(outBin.data()), outBin.size(),
                          s.c_str(), s.size(),
                          /*ignore=*/nullptr,
                          /*out_len=*/&out_len,
                          /*b64_end=*/nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return false;
    }

    outBin.resize(out_len);
    return true;
}

// -----------------------------------------------------------------------------
// Mint cookie
// -----------------------------------------------------------------------------

bool session_cookie_mint(const unsigned char key32[32],
                         const std::string& fingerprint_b64,
                         long iat, long exp,
                         std::string& out_cookie_value) {
    /*
     * Build a compact JSON claim set.
     *
     * IMPORTANT:
     * - We generate JSON ourselves and later verify using string search.
     * - That means this exact key order and formatting is part of the cookie format.
     * - If you ever change this schema, update both mint + verify together.
     */
    std::string claims = std::string("{")
        + "\"fp\":\"" + fingerprint_b64 + "\","
        + "\"iat\":" + std::to_string(iat) + ","
        + "\"exp\":" + std::to_string(exp)
        + "}";

    // Compute HMAC-SHA256(claims, key32)
    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key32, 32);
    crypto_auth_hmacsha256_update(&st,
                                  reinterpret_cast<const unsigned char*>(claims.data()),
                                  claims.size());
    crypto_auth_hmacsha256_final(&st, mac);

    // Cookie payload is "<b64url(claims)>.<b64url(mac)>"
    out_cookie_value =
        b64url_enc(reinterpret_cast<const unsigned char*>(claims.data()), claims.size())
        + "."
        + b64url_enc(mac, sizeof(mac));

    return true;
}

// -----------------------------------------------------------------------------
// Verify cookie
// -----------------------------------------------------------------------------

bool session_cookie_verify(const unsigned char key32[32],
                           const std::string& cookie_value,
                           std::string& out_fingerprint_b64,
                           long& out_exp) {
    // Split "<claims_b64>.<mac_b64>"
    const auto dot = cookie_value.find('.');
    if (dot == std::string::npos) return false;

    const std::string c1 = cookie_value.substr(0, dot);
    const std::string c2 = cookie_value.substr(dot + 1);

    // Decode claims JSON bytes
    std::string claims;
    if (!b64url_dec(c1, claims)) return false;

    // Decode mac bytes
    std::string macBin;
    if (!b64url_dec(c2, macBin)) return false;
    if (macBin.size() != crypto_auth_hmacsha256_BYTES) return false;

    // Recompute expected MAC over claims
    unsigned char mac2[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key32, 32);
    crypto_auth_hmacsha256_update(&st,
                                  reinterpret_cast<const unsigned char*>(claims.data()),
                                  claims.size());
    crypto_auth_hmacsha256_final(&st, mac2);

    // Constant-time compare to avoid timing attacks on MAC verification
    if (sodium_memcmp(mac2, macBin.data(), crypto_auth_hmacsha256_BYTES) != 0) return false;

    /*
     * Minimal parsing:
     * We extract "fp" and "exp" using substring search.
     *
     * This is acceptable because:
     * - claims were minted by our own code (see mint format above)
     * - MAC verification guarantees claims are authentic and unmodified
     *
     * If you ever want a more flexible schema, switch this to proper JSON parsing,
     * but keep in mind: JSON parsing increases complexity and can allocate more.
     */

    // Extract fp: find `"fp":"..."`
    auto p = claims.find("\"fp\":\"");
    if (p == std::string::npos) return false;
    p += 6; // length of `"fp":"`
    auto q = claims.find('"', p);
    if (q == std::string::npos) return false;
    out_fingerprint_b64 = claims.substr(p, q - p);

    // Extract exp: find `"exp":12345`
    auto e = claims.find("\"exp\":");
    if (e == std::string::npos) return false;

    // strtol reads until non-digit; safe because we control mint format
    out_exp = std::strtol(claims.c_str() + e + 6, nullptr, 10);

    return true;
}
