// tools/test_admin_cookie.cpp
//
// Regression test: cookie + policy + admin guard must stay compatible.
//
// What it tests:
// 1) Load config/policy.json (admin fingerprint)
// 2) Mint pqnas_session cookie embedding fp_hex (as STANDARD base64 of UTF-8)
// 3) Call require_admin_cookie() with a fake httplib::Request containing that cookie
// 4) Assert admin access is granted (returns true)
//
// Build target should link authz.cc + session_cookie.cc.

#include <sodium.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "httplib.h"
#include "allowlist.h"
#include "authz.h"
#include "session_cookie.h"

static std::string b64std_enc(const unsigned char* data, size_t len) {
    // Standard base64 with padding (Variant ORIGINAL), matches server decoding.
    const size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str())); // trim trailing '\0'
    return out;
}

static std::string repo_root_from_file() {
    // __FILE__ ends with .../tools/test_admin_cookie.cpp
    // repo root is parent of tools/
    return std::filesystem::path(__FILE__).parent_path().parent_path().string();
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 2;
    }

    const std::string repo_root = repo_root_from_file();
    const std::string policy_path =
        (std::filesystem::path(repo_root) / "config" / "policy.json").string();

    pqnas::Allowlist allowlist;
    if (!allowlist.load(policy_path)) {
        std::cerr << "FAIL: could not load policy: " << policy_path << "\n";
        return 3;
    }

    // Deterministic cookie key for the test (do NOT randomize, we want stable behavior)
    unsigned char cookie_key[32];
    for (size_t i = 0; i < sizeof(cookie_key); i++) cookie_key[i] = (unsigned char)i;

    // Use the same admin fingerprint you placed in policy.json
    const std::string fp_hex =
        "a8885f40f4c12c85837807021a48d31c1ba657f5aebe809107eccb72ce600240"
        "76fd976c34109c78c68614c5d37702225397a3daba099fb16ed4738167bede39";

    // Sanity: policy says this should be admin
    if (!allowlist.is_admin(fp_hex)) {
        std::cerr << "FAIL: policy does not mark fp as admin\n";
        return 4;
    }

    // Mint cookie like the server: cookie stores STANDARD base64 of UTF-8 fingerprint hex string.
    const std::string fp_b64 = b64std_enc(
        reinterpret_cast<const unsigned char*>(fp_hex.data()),
        fp_hex.size()
    );

    // Deterministic "current time" that is safely in the future so the cookie won't expire.
    const long now = 1893456000; // 2030-01-01 00:00:00 UTC
    const long iat = now;
    const long exp = now + 3600; // 1 hour

    std::string cookieVal;
    if (!session_cookie_mint(cookie_key, fp_b64, iat, exp, cookieVal)) {
        std::cerr << "FAIL: session_cookie_mint failed\n";
        return 5;
    }

    // Fake request containing the session cookie
    httplib::Request req;
    httplib::Response res;

    req.remote_addr = "127.0.0.1";
    req.headers.emplace("Cookie", std::string("pqnas_session=") + cookieVal);

    // Call the real guard with allowlist pointer (so it doesn't re-load policy unexpectedly)
    const bool ok = require_admin_cookie(req, res, cookie_key, policy_path, &allowlist);

    if (!ok) {
        std::cerr << "FAIL: require_admin_cookie returned false\n";
        std::cerr << "HTTP status=" << res.status << "\n";
        std::cerr << "Body:\n" << res.body << "\n";
        return 6;
    }

    std::cout << "OK: admin cookie/policy regression test passed\n";
    return 0;
}
