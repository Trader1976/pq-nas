#include "authz.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <ctime>

#include <sodium.h>

#include "allowlist.h"
#include "session_cookie.h"

namespace {

// Extract pqnas_session=<...> from Cookie header. Returns "" if missing.
static std::string extract_cookie_value(const httplib::Request& req, const std::string& name) {
    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) return "";

    const std::string& hdr = it->second;
    const std::string key = name + "=";

    auto pos = hdr.find(key);
    if (pos == std::string::npos) return "";
    pos += key.size();

    auto end = hdr.find(';', pos);
    if (end == std::string::npos) end = hdr.size();

    // trim spaces around value
    while (pos < end && (hdr[pos] == ' ' || hdr[pos] == '\t')) pos++;
    while (end > pos && (hdr[end - 1] == ' ' || hdr[end - 1] == '\t')) end--;

    return hdr.substr(pos, end - pos);
}

// Decode standard base64 (padded) -> bytes in out (string used as byte buffer)
static bool b64std_decode_to_bytes(const std::string& in, std::string& out) {
    out.clear();
    out.resize(in.size() * 3 / 4 + 8);
    size_t out_len = 0;

    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(),
                          in.c_str(), in.size(),
                          nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return false;
    }

    out.resize(out_len);
    return true;
}

static void reply_text(httplib::Response& res, int code, const std::string& msg) {
    res.status = code;
    res.set_header("Content-Type", "text/plain");
    res.body = msg;
}

} // namespace

bool require_admin_cookie(const httplib::Request& req,
                          httplib::Response& res,
                          const unsigned char cookie_key[32],
                          const std::string& /*allowlist_path*/,
                          const pqnas::Allowlist* allowlist)
{
    // Require cookie header + pqnas_session
    const std::string cookieVal = extract_cookie_value(req, "pqnas_session");
    if (cookieVal.empty()) {
        reply_text(res, 401, "missing pqnas_session");
        return false;
    }

    // Verify cookie MAC and extract identity (fp_b64) + expiry
    std::string fp_b64;
    long exp = 0;
    if (!session_cookie_verify(cookie_key, cookieVal, fp_b64, exp)) {
        reply_text(res, 401, "invalid session");
        return false;
    }

    // Expiry check
    const long now = std::time(nullptr);
    if (now > exp) {
        reply_text(res, 401, "session expired");
        return false;
    }

    // IMPORTANT: cookie stores fp_b64 = standard base64 of UTF-8 fingerprint HEX string
    std::string raw;
    if (!b64std_decode_to_bytes(fp_b64, raw)) {
        reply_text(res, 401, "invalid session");
        return false;
    }
    const std::string fp_hex(raw.begin(), raw.end());

    // Admin policy check (fail-closed)
    if (!allowlist || !allowlist->is_admin(fp_hex)) {
        reply_text(res, 403, "admin required");
        return false;
    }

    return true;
}
