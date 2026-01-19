#include "authz.h"

#include "session_cookie.h"
#include "pqnas_util.h"
#include "policy.h"

#include <string>

static bool get_cookie_value(const httplib::Request& req, const std::string& name, std::string& out) {
    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) return false;

    const std::string& hdr = it->second;
    const std::string k = name + "=";
    auto pos = hdr.find(k);
    if (pos == std::string::npos) return false;
    pos += k.size();

    auto end = hdr.find(';', pos);
    out = hdr.substr(pos, (end == std::string::npos) ? std::string::npos : (end - pos));
    return true;
}

bool require_admin_cookie(const httplib::Request& req,
                          httplib::Response& res,
                          const unsigned char cookie_key[32],
                          const std::string& allowlist_path,
                          std::string* out_fingerprint_hex) {
    (void)allowlist_path; // allowlist already loaded at startup (policy_load_allowlist)

    // 1) Extract pqnas_session cookie
    std::string cookieVal;
    if (!get_cookie_value(req, "pqnas_session", cookieVal) || cookieVal.empty()) {
        res.status = 401;
        res.set_content("missing pqnas_session", "text/plain");
        return false;
    }

    // 2) Verify cookie
    std::string fp_b64;
    long exp = 0;
    if (!session_cookie_verify(cookie_key, cookieVal, fp_b64, exp)) {
        res.status = 401;
        res.set_content("invalid session", "text/plain");
        return false;
    }

    if (pqnas::now_epoch() > exp) {
        res.status = 401;
        res.set_content("session expired", "text/plain");
        return false;
    }

    // 3) Decode fingerprint (base64 -> bytes -> ASCII hex string)
    // NOTE: fp_b64 is standard base64 of the UTF-8 fingerprint hex string.
    std::string fp_hex;
    try {
        auto fp_bytes = pqnas::b64decode_loose(fp_b64);
        fp_hex.assign(fp_bytes.begin(), fp_bytes.end());
        fp_hex = pqnas::lower_ascii(fp_hex);
    } catch (...) {
        res.status = 401;
        res.set_content("invalid fingerprint encoding", "text/plain");
        return false;
    }

    // 4) Policy check (admin)
    if (!pqnas::policy_is_admin(fp_hex)) {
        res.status = 403;
        res.set_content("admin required", "text/plain");
        return false;
    }

    if (out_fingerprint_hex) *out_fingerprint_hex = fp_hex;
    return true;
}
