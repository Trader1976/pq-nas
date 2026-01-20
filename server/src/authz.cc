#include "authz.h"

#include "session_cookie.h"
#include "pqnas_util.h"
#include "policy.h"

#include <string>

/*
Authorization helper for admin-only endpoints
=============================================

This file implements authorization checks *after* authentication has succeeded.

Important separation of concerns:
- Authentication (who are you?): handled by v4 QR auth + session cookies.
- Authorization (are you allowed?): handled here via policy checks.

This code assumes:
- The pqnas_session cookie was minted by this server.
- The cookie has already cryptographically bound the identity.
- Policy (allowlist) has been loaded at startup.
*/

/*
Extract a cookie value from the HTTP "Cookie" header.

Notes:
- httplib does not provide a structured cookie API, so we parse manually.
- This is a minimal parser sufficient for simple name=value cookies.
- We do not support quoted values or exotic attributes here.

Security note:
- Cookie integrity is NOT checked here.
- This function only extracts the raw value.
*/
static bool get_cookie_value(const httplib::Request& req,
                             const std::string& name,
                             std::string& out) {
    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) return false;

    const std::string& hdr = it->second;
    const std::string k = name + "=";
    auto pos = hdr.find(k);
    if (pos == std::string::npos) return false;
    pos += k.size();

    auto end = hdr.find(';', pos);
    out = hdr.substr(pos,
                     (end == std::string::npos)
                         ? std::string::npos
                         : (end - pos));
    return true;
}

/*
require_admin_cookie
====================

Enforces that the incoming request carries a valid, non-expired session cookie
belonging to an identity with admin privileges.

This is intended for:
- admin audit endpoints
- privileged control APIs
- any operation requiring elevated trust

Return value:
- true  : authorization succeeded
- false : response is already populated with an error

On success:
- out_fingerprint_hex (if non-null) receives the canonical fingerprint identity.
*/
bool require_admin_cookie(const httplib::Request& req,
                          httplib::Response& res,
                          const unsigned char cookie_key[32],
                          const std::string& allowlist_path,
                          std::string* out_fingerprint_hex) {
    (void)allowlist_path;
    // NOTE:
    // The allowlist is loaded once at startup via policy_load_allowlist().
    // This parameter is kept for API symmetry / future flexibility, but is
    // not used here.

    // ---------------------------------------------------------------------
    // 1) Extract pqnas_session cookie
    // ---------------------------------------------------------------------
    std::string cookieVal;
    if (!get_cookie_value(req, "pqnas_session", cookieVal) || cookieVal.empty()) {
        res.status = 401;
        res.set_content("missing pqnas_session", "text/plain");
        return false;
    }

    // ---------------------------------------------------------------------
    // 2) Verify session cookie
    // ---------------------------------------------------------------------
    // session_cookie_verify() must validate:
    // - integrity (MAC/signature under cookie_key)
    // - structure/decoding
    // - embedded identity value
    //
    // The cookie is a bearer credential; if verification fails, we fail closed.
    std::string fp_b64;
    long exp = 0;
    if (!session_cookie_verify(cookie_key, cookieVal, fp_b64, exp)) {
        res.status = 401;
        res.set_content("invalid session", "text/plain");
        return false;
    }

    // Explicit expiry check, even if expiry is also authenticated inside cookie.
    if (pqnas::now_epoch() > exp) {
        res.status = 401;
        res.set_content("session expired", "text/plain");
        return false;
    }

    // ---------------------------------------------------------------------
    // 3) Decode fingerprint identity
    // ---------------------------------------------------------------------
    // In the current design:
    // - The verifier exposes fingerprint_b64 as the canonical identity string.
    // - session_cookie embeds this fingerprint_b64 value.
    //
    // For policy checks, we convert it back to a normalized ASCII fingerprint
    // string (historically hex, hence the variable name).
    //
    // Encoding note:
    // - fp_b64 is standard base64 encoding of the UTF-8 fingerprint string.
    std::string fp_hex;
    try {
        auto fp_bytes = pqnas::b64decode_loose(fp_b64);
        fp_hex.assign(fp_bytes.begin(), fp_bytes.end());
        fp_hex = pqnas::lower_ascii(fp_hex);
    } catch (...) {
        // Any decode error is treated as authentication failure.
        res.status = 401;
        res.set_content("invalid fingerprint encoding", "text/plain");
        return false;
    }

    // ---------------------------------------------------------------------
    // 4) Policy check (admin role)
    // ---------------------------------------------------------------------
    // Authorization is separate from authentication:
    // - A valid session does not automatically imply admin privileges.
    // - policy_is_admin() is fail-closed for unknown identities.
    if (!pqnas::policy_is_admin(fp_hex)) {
        res.status = 403;
        res.set_content("admin required", "text/plain");
        return false;
    }

    // Success: return canonical fingerprint identity if requested.
    if (out_fingerprint_hex) *out_fingerprint_hex = fp_hex;
    return true;
}
