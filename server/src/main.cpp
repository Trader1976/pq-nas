/*
PQ-NAS v4 QR Authentication Server
=================================

This server implements a device-mediated login flow:
- Browser requests a v4 "session token" (st) that is Ed25519-signed by this server.
- Mobile app approves by producing an ML-DSA-87 (Dilithium-class) signature over a canonical payload
  that binds: (st_hash, fingerprint/pubkey, origin, rp_id, challenge, timestamps).
- Server verifies all bindings and mints a short-lived browser session cookie.

Security goals (what v4 is designed to guarantee)
-------------------------------------------------
1) No shared secrets in the browser: the browser proves approval via a one-time consume + cookie.
2) Approval is cryptographic: PQ signature (ML-DSA-87) proves possession of the user's private key.
3) Strong binding:
   - Approval is bound to the exact session token via SHA-256(st) = st_hash.
   - Identity is bound via fingerprint <-> public key (SHA3-512(pubkey) hex).
   - Login is bound to origin + rp_id to prevent cross-site token reuse.
4) Replay resistance:
   - session token (st) has expiry and is server-signed (Ed25519).
   - approval is one-time consumable (consume endpoint) and/or st/checks enforce freshness.
5) Auditable: every security-relevant decision is logged to a hash-chained JSONL log.

Non-goals / limitations (explicit)
----------------------------------
- This does not hide metadata from Cloudflare Tunnel / hosting infrastructure.
- This does not replace WebAuthn; it provides a QR mediated flow with different UX and deployment tradeoffs.
- If allowlist.json is compromised, authorization policy can be bypassed even though crypto checks still pass.

Code responsibilities (separation of concerns)
----------------------------------------------
- Auth: cryptographic verification and cookie minting.
- Policy: allowlist roles (user/admin) and endpoint authorization checks.
- Audit: append-only hash-chained events describing what happened (not why the user intended it).

All verification is fail-closed: any parse/verify/binding mismatch returns an error and logs the failure.
*/

#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <cctype>
#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <mutex>
#include <qrencode.h>
#include <filesystem>
#include <deque>
#include <algorithm>
#include <array>
#include <iomanip>
#include "verify_v4_crypto.h"
#include <functional>
#include "audit_log.h"
#include "audit_fields.h"
#include <limits>
#include <cstdint>
extern "C" {
#include "qrauth_v4.h"
}

#include "pqnas_util.h"
#include "authz.h"
#include "session_cookie.h"
#include "policy.h"

// header-only HTTP server
#include "httplib.h"
#include "allowlist.h"
#include "v4_verify_shared.h"
#include "users_registry.h"

#include "system_metrics.h"
// JSON (header-only)
#include <nlohmann/json.hpp>

#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <chrono>

using json = nlohmann::json;

static void reply_json(httplib::Response& res, int code, const std::string& body_json);

// ---- config ----
static unsigned char SERVER_PK[32];
static unsigned char SERVER_SK[64];
static unsigned char COOKIE_KEY[32];

static std::string exe_dir();

// REPO_ROOT is derived from the running binary location:
// build/bin/pqnas_server  -> REPO_ROOT = build/bin/../../ = repo root
const std::string REPO_ROOT = std::filesystem::weakly_canonical(
    std::filesystem::path(exe_dir()) / ".." / ".."
).string();

const std::string STATIC_AUDIT_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_audit.html").string();
const std::string STATIC_AUDIT_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_audit.js").string();
const std::string STATIC_ADMIN_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin.html").string();
const std::string STATIC_ADMIN_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin.js").string();
const std::string STATIC_APP_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/app.html").string();
const std::string STATIC_APP_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/app.js").string();
const std::string STATIC_USERS_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_users.html").string();
const std::string STATIC_USERS_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_users.js").string();
static const std::string STATIC_WAIT_APPROVAL_HTML = "server/src/static/wait_approval.html";
static const std::string STATIC_WAIT_APPROVAL_JS   = "server/src/static/wait_approval.js";
static const std::string STATIC_SYSTEM_HTML = "server/src/static/system.html";
static const std::string STATIC_SYSTEM_JS   = "server/src/static/system.js";
const std::string STATIC_LOGIN =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/login.html").string();

const std::string STATIC_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/pqnas_v4.js").string();

const std::string STATIC_ADMIN_SETTINGS_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_settings.html").string();

const std::string STATIC_ADMIN_SETTINGS_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_settings.js").string();
static const char* STATIC_APPROVALS_HTML = "server/src/static/admin_approvals.html";
static const char* STATIC_APPROVALS_JS   = "server/src/static/admin_approvals.js";
static const char* STATIC_BADGES_JS = "server/src/static/admin_badges.js";





static std::string ORIGIN   = "https://nas.example.com";
static std::string ISS      = "pq-nas";
static std::string AUD      = "dna-messenger";
static std::string SCOPE    = "pqnas.login";
static std::string APP_NAME = "PQ-NAS";

// v4 app requires rp binding inside st payload
static std::string RP_ID    = "nas.example.com";  // relying party id (domain)

static int REQ_TTL      = 60;
static int SESS_TTL     = 8 * 3600;
static int LISTEN_PORT  = 8081; // use 8081 to avoid conflicts

struct ApprovalEntry {
    std::string cookie_val;   // pqnas_session cookie value (b64url.claims + "." + b64url.mac)
    std::string fingerprint;  // computed_fp (hex)
    long expires_at = 0;      // epoch seconds
};

static std::unordered_map<std::string, ApprovalEntry> g_approvals;
static std::mutex g_approvals_mu;

// --- pending admin approval (sid -> reason) ---
struct PendingEntry {
    std::string reason;   // e.g. "user_disabled"
    long expires_at = 0;  // unix epoch seconds
};

static std::unordered_map<std::string, PendingEntry> g_pending;
static std::mutex g_pending_mu;

static void pending_prune(long now) {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    for (auto it = g_pending.begin(); it != g_pending.end(); ) {
        if (now > it->second.expires_at)
            it = g_pending.erase(it);
        else
            ++it;
    }
}

static void pending_put(const std::string& sid, const PendingEntry& e) {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    g_pending[sid] = e;
}

static bool pending_get(const std::string& sid, PendingEntry& out) {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    auto it = g_pending.find(sid);
    if (it == g_pending.end()) return false;
    out = it->second;
    return true;
}




// ===================== Network sampling helpers (/proc/net/dev) =====================

#include <unordered_map>
#include <mutex>



// for audit log checking
static long long file_size_bytes_safe(const std::string& path) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    if (ec) return -1;
    return (long long)sz;
}

namespace {


static std::string iso_utc_from_filetime(const std::filesystem::file_time_type& ft) {
    try {
        using namespace std::chrono;

        auto sctp = time_point_cast<system_clock::duration>(
            ft - std::filesystem::file_time_type::clock::now()
            + system_clock::now()
        );

        std::time_t tt = system_clock::to_time_t(sctp);

        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &tt);
#else
        gmtime_r(&tt, &tm);
#endif

        char buf[64];
        const int n = std::snprintf(
            buf,
            sizeof(buf),
            "%04d-%02d-%02dT%02d:%02d:%02dZ",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        );

        if (n <= 0) {
            return "—";
        }
        if (n >= (int)sizeof(buf)) {
            return std::string(buf, buf + (sizeof(buf) - 1));
        }

        return std::string(buf, buf + n);
    } catch (...) {
        return "—";
    }
}

static std::string utc_day_yyyymmdd() {
    try {
        std::time_t tt = std::time(nullptr);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &tt);
#else
        gmtime_r(&tt, &tm);
#endif
        std::ostringstream oss;
        oss << std::setfill('0')
            << std::setw(4) << (tm.tm_year + 1900) << "-"
            << std::setw(2) << (tm.tm_mon + 1) << "-"
            << std::setw(2) << tm.tm_mday;
        return oss.str();
    } catch (...) {
        return "0000-00-00";
    }
}
static nlohmann::json load_admin_settings_safe(const std::string& path) {
    try {
        std::ifstream f(path);
        if (!f.good()) return nlohmann::json::object();
        nlohmann::json j;
        f >> j;
        if (!j.is_object()) return nlohmann::json::object();
        return j;
    } catch (...) {
        return nlohmann::json::object();
    }
}

struct AuditRotateCfg {
    long long max_active_bytes = 256LL * 1024LL * 1024LL; // default 256 MB
    bool daily_utc = true;
    int check_interval_sec = 10;
};

static AuditRotateCfg get_rotate_cfg_from_settings(const nlohmann::json& settings) {
    AuditRotateCfg c;

    if (settings.contains("audit_rotate") && settings["audit_rotate"].is_object()) {
        const auto& ar = settings["audit_rotate"];

        if (ar.contains("max_active_mb") && ar["max_active_mb"].is_number_integer()) {
            long long mb = ar["max_active_mb"].get<long long>();
            if (mb < 0) mb = 0;
            c.max_active_bytes = mb * 1024LL * 1024LL;
        }

        if (ar.contains("daily_utc") && ar["daily_utc"].is_boolean()) {
            c.daily_utc = ar["daily_utc"].get<bool>();
        }

        if (ar.contains("check_interval_sec") && ar["check_interval_sec"].is_number_integer()) {
            int s = ar["check_interval_sec"].get<int>();
            if (s < 1) s = 1;
            if (s > 3600) s = 3600;
            c.check_interval_sec = s;
        }
    }

    return c;
}

struct ArchivePair {
    std::string jsonl_path;
    std::string state_path; // optional
    std::string name;       // filename
    long long size_bytes = 0; // jsonl + state (if present)
    std::filesystem::file_time_type mtime{};
};

static std::vector<ArchivePair> list_rotated_archives_local(const std::string& audit_jsonl_path) {
    std::vector<ArchivePair> out;

    const std::filesystem::path active(audit_jsonl_path);
    const std::filesystem::path dir = active.parent_path();

    const std::string active_name = active.filename().string(); // pqnas_audit.jsonl
    const std::string prefix = "pqnas_audit-";
    const std::string jsonl_ext = ".jsonl";
    const std::string state_ext = ".state";

    std::error_code ec;
    for (auto& de : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!de.is_regular_file()) continue;

        const auto p = de.path();
        const std::string fn = p.filename().string();
        if (fn == active_name) continue;

        if (fn.rfind(prefix, 0) != 0) continue;
        if (fn.size() <= prefix.size() + jsonl_ext.size()) continue;
        if (fn.substr(fn.size() - jsonl_ext.size()) != jsonl_ext) continue;

        const std::string id = fn.substr(prefix.size(), fn.size() - prefix.size() - jsonl_ext.size());
        if (id.empty()) continue;

        ArchivePair ap;
        ap.jsonl_path = p.string();
        ap.name = fn;

        ap.size_bytes = file_size_bytes_safe(ap.jsonl_path);
        if (ap.size_bytes < 0) ap.size_bytes = 0;

        const std::filesystem::path st = dir / (prefix + id + state_ext);
        if (std::filesystem::exists(st)) {
            ap.state_path = st.string();
            long long s2 = file_size_bytes_safe(ap.state_path);
            if (s2 > 0) ap.size_bytes += s2;
        }

        std::error_code ec2;
        ap.mtime = std::filesystem::last_write_time(p, ec2);
        if (ec2) ap.mtime = std::filesystem::file_time_type::clock::now();

        out.push_back(std::move(ap));
    }

    std::sort(out.begin(), out.end(), [](const ArchivePair& a, const ArchivePair& b) {
        return a.mtime > b.mtime; // newest first
    });

    return out;
}


static nlohmann::json normalize_retention_or_default_local(const nlohmann::json& in_ret) {
    nlohmann::json ret = nlohmann::json::object();
    if (in_ret.is_object()) ret = in_ret;

    auto get_mode = [&]() -> std::string {
        if (ret.contains("mode") && ret["mode"].is_string()) return ret["mode"].get<std::string>();
        return "never";
    };
    auto clamp_int = [&](const char* k, int def, int lo, int hi) -> int {
        if (!ret.contains(k) || ret[k].is_null()) return def;
        if (!ret[k].is_number_integer()) return def;
        int v = ret[k].get<int>();
        if (v < lo) v = lo;
        if (v > hi) v = hi;
        return v;
    };

    std::string mode = get_mode();
    if (!(mode == "never" || mode == "days" || mode == "files" || mode == "size_mb")) mode = "never";

    const int days = clamp_int("days", 90, 1, 3650);
    const int max_files = clamp_int("max_files", 50, 1, 50000);
    const int max_total_mb = clamp_int("max_total_mb", 20480, 1, 10000000);

    return nlohmann::json{
        {"mode", mode},
        {"days", days},
        {"max_files", max_files},
        {"max_total_mb", max_total_mb},
    };
}

static nlohmann::json build_preview_local(const std::vector<ArchivePair>& archives, const nlohmann::json& policy) {
    const std::string mode = policy.value("mode", "never");
    const int days = policy.value("days", 90);
    const int max_files = policy.value("max_files", 50);
    const long long max_bytes = (long long)policy.value("max_total_mb", 20480) * 1024LL * 1024LL;

    long long total_bytes = 0;
    for (const auto& a : archives) total_bytes += std::max(0LL, a.size_bytes);

    std::vector<nlohmann::json> candidates;
    long long cand_bytes = 0;

    if (mode == "never") {
        // nothing
    } else if (mode == "files") {
        for (size_t i = 0; i < archives.size(); i++) {
            if ((int)i < max_files) continue;
            const auto& a = archives[i];
            candidates.push_back({
                {"name", a.name},
                {"size_bytes", a.size_bytes},
                {"mtime_iso", iso_utc_from_filetime(a.mtime)},
                {"reason", "exceeds max_files"}
            });
            cand_bytes += std::max(0LL, a.size_bytes);
        }
    } else if (mode == "days") {
        using namespace std::chrono;
        const auto now = std::filesystem::file_time_type::clock::now();
        const auto cutoff = now - hours(24 * days);

        for (const auto& a : archives) {
            if (a.mtime >= cutoff) continue;
            candidates.push_back({
                {"name", a.name},
                {"size_bytes", a.size_bytes},
                {"mtime_iso", iso_utc_from_filetime(a.mtime)},
                {"reason", "older than days"}
            });
            cand_bytes += std::max(0LL, a.size_bytes);
        }
    } else if (mode == "size_mb") {
        long long kept = 0;
        for (const auto& a : archives) {
            const long long sz = std::max(0LL, a.size_bytes);
            if (kept + sz <= max_bytes) {
                kept += sz;
                continue;
            }
            candidates.push_back({
                {"name", a.name},
                {"size_bytes", a.size_bytes},
                {"mtime_iso", iso_utc_from_filetime(a.mtime)},
                {"reason", "exceeds max_total_mb"}
            });
            cand_bytes += sz;
        }
    }

    nlohmann::json summary = {
        {"candidate_files", (int)candidates.size()},
        {"candidate_bytes", cand_bytes},
        {"total_archives", (int)archives.size()},
        {"total_bytes", total_bytes},
    };

    return nlohmann::json{
        {"ok", true},
        {"candidates", candidates},
        {"summary", summary}
    };
}

} // namespace


static void pending_pop(const std::string& sid) {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    g_pending.erase(sid);
}

static void approvals_prune(long now) {
    std::lock_guard<std::mutex> lk(g_approvals_mu);
    for (auto it = g_approvals.begin(); it != g_approvals.end();) {
        if (now > it->second.expires_at) it = g_approvals.erase(it);
        else ++it;
    }
}

static void approvals_put(const std::string& sid, const ApprovalEntry& e) {
    std::lock_guard<std::mutex> lk(g_approvals_mu);
    g_approvals[sid] = e;
}

static bool approvals_get(const std::string& sid, ApprovalEntry& out) {
    std::lock_guard<std::mutex> lk(g_approvals_mu);
    auto it = g_approvals.find(sid);
    if (it == g_approvals.end()) return false;
    out = it->second;
    return true;
}

static void approvals_pop(const std::string& sid) {
    std::lock_guard<std::mutex> lk(g_approvals_mu);
    g_approvals.erase(sid);
}

// Return directory that contains the running executable
static std::string exe_dir() {
    char buf[PATH_MAX] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    std::string p(buf, (size_t)n);
    return std::filesystem::path(p).parent_path().string();
}

// Decode standard base64 (with padding) -> bytes
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

// -----------------------------------------------------------------------------
// Shared helpers needed by verify_v4_shared.cc
// These MUST be link-visible (not static) and stable.
// -----------------------------------------------------------------------------
namespace pqnas {

// URL-safe base64 without padding
[[maybe_unused]] std::string b64url_enc_local(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

// Native PQ verifier loader symbol signature (libdna_lib.so)
using qgp_dsa87_verify_fn = int (*)(const uint8_t* sig, size_t siglen,
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t* pk);

} // namespace pqnas

// -----------------------------------------------------------------------------
// Server-local helpers
// -----------------------------------------------------------------------------
static bool read_file_to_string(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

// --- Static files (generic) --------------------------------------------------
// Serve arbitrary assets from server/src/static at /static/<file>.
// This is intentionally scoped + safe:
// - No path traversal
// - Fail-closed: only allows known extensions
// - No impact on crypto/auth/audit logic
static bool is_safe_static_relpath(const std::string& rel) {
    if (rel.empty()) return false;
    if (rel.find('\0') != std::string::npos) return false;

    // No absolute paths, no traversal, no backslashes (Windows), no "//"
    if (rel[0] == '/' || rel.find("..") != std::string::npos) return false;
    if (rel.find('\\') != std::string::npos) return false;
    if (rel.find("//") != std::string::npos) return false;

    // Only allow plain filenames or subdirs (static/img/foo.png etc)
    // Keep it simple: only [A-Za-z0-9._-/]
    for (char c : rel) {
        const bool ok =
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-' || c == '/' ;
        if (!ok) return false;
    }

    return true;
}

static std::string mime_for_ext(std::string ext) {
    // ext must be lowercase and include dot (".png")
    if (ext == ".html")  return "text/html; charset=utf-8";
    if (ext == ".js")    return "application/javascript; charset=utf-8";
    if (ext == ".css")   return "text/css; charset=utf-8";
    if (ext == ".svg")   return "image/svg+xml; charset=utf-8";
    if (ext == ".png")   return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".webp")  return "image/webp";
    if (ext == ".gif")   return "image/gif";
    if (ext == ".ico")   return "image/x-icon";
    if (ext == ".woff")  return "font/woff";
    if (ext == ".woff2") return "font/woff2";
    if (ext == ".ttf")   return "font/ttf";
    return "";
}

static bool has_allowed_static_ext(const std::filesystem::path& p) {
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return !mime_for_ext(ext).empty();
}


static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

static bool b64url_decode_to_bytes(const std::string& in, std::string& out) {
    out.clear();
    out.resize(in.size() * 3 / 4 + 8);
    size_t out_len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(),
                          in.c_str(), in.size(),
                          nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return false;
    }
    out.resize(out_len);
    return true;
}

static std::string url_encode(const std::string& s) {
    static const char *hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
    }
    return out;
}

[[maybe_unused]] static std::string trim_nl(std::string s) {
    while (!s.empty() && (s.back()=='\n' || s.back()=='\r')) s.pop_back();
    return s;
}

static std::string trim_ws(std::string s) {
    while (!s.empty() && (s.front()==' ' || s.front()=='\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()==' ' || s.back()=='\t')) s.pop_back();
    return s;
}

static std::string header_value(const httplib::Request& req, const char* name) {
    auto it = req.headers.find(name);
    return (it == req.headers.end()) ? "" : it->second;
}

static std::string first_xff_ip(const std::string& xff) {
    auto comma = xff.find(',');
    return trim_ws((comma == std::string::npos) ? xff : xff.substr(0, comma));
}

static std::string client_ip(const httplib::Request& req) {
    std::string cf = trim_ws(header_value(req, "CF-Connecting-IP"));
    if (!cf.empty()) return cf;

    std::string xff = header_value(req, "X-Forwarded-For");
    if (!xff.empty()) {
        std::string ip = first_xff_ip(xff);
        if (!ip.empty()) return ip;
    }
    return req.remote_addr.empty() ? "?" : req.remote_addr;
}

// ----- Cookie gate: user OR admin (UsersRegistry policy) ---------------------
// Mirrors /api/v4/me logic, but reusable for page + API gating.
// Returns actor_fp_hex + role ("admin"|"user") on success.
static bool require_user_cookie_users_actor(
    const httplib::Request& req,
    httplib::Response& res,
    const unsigned char cookie_key[32],
    pqnas::UsersRegistry* users,
    std::string* out_fp_hex,
    std::string* out_role
) {
    if (out_fp_hex) out_fp_hex->clear();
    if (out_role) out_role->clear();

    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) {
        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing cookie"}}).dump());
        return false;
    }

    const std::string& hdr = it->second;
    const std::string k = "pqnas_session=";
    auto pos = hdr.find(k);
    if (pos == std::string::npos) {
        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing pqnas_session"}}).dump());
        return false;
    }
    pos += k.size();
    auto end = hdr.find(';', pos);
    std::string cookieVal = hdr.substr(pos, (end == std::string::npos) ? std::string::npos : (end - pos));

    std::string fp_b64;
    long exp = 0;
    if (!session_cookie_verify(cookie_key, cookieVal, fp_b64, exp)) {
        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","invalid session"}}).dump());
        return false;
    }

    long now = pqnas::now_epoch();
    if (now > exp) {
        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","session expired"}}).dump());
        return false;
    }

    // Cookie stores *standard* base64 of UTF-8 fingerprint hex string
    std::string fp_hex;
    {
        std::string raw;
        if (!b64std_decode_to_bytes(fp_b64, raw)) {
            reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","invalid session"}}).dump());
            return false;
        }
        fp_hex.assign(raw.begin(), raw.end());
    }

    // Users policy (fail-closed)
    const bool is_admin = users && users->is_admin_enabled(fp_hex);
    const bool is_user  = users && (users->is_enabled_user(fp_hex) || is_admin);

    if (!is_user) {
        reply_json(res, 403, json({{"ok",false},{"error","forbidden"},{"message","policy denied"}}).dump());
        return false;
    }

    if (out_fp_hex) *out_fp_hex = fp_hex;
    if (out_role) *out_role = is_admin ? "admin" : "user";
    return true;
}


static std::string random_b64url(size_t nbytes) {
    std::string b(nbytes, '\0');
    randombytes_buf(b.data(), b.size());
    return b64url_enc(reinterpret_cast<const unsigned char*>(b.data()), b.size());
}

static void reply_json(httplib::Response& res, int code, const std::string& body_json) {
    res.status = code;
    res.set_header("Content-Type", "application/json");
    res.body = body_json;
}

static std::string qr_svg_from_text(const std::string& text,
                                   int module_px = 6,
                                   int margin_modules = 4) {
    QRcode* qr = QRcode_encodeString8bit(text.c_str(), 0, QR_ECLEVEL_M);
    if (!qr) throw std::runtime_error("QRcode_encodeString8bit failed");

    const int w = qr->width;
    const unsigned char* d = qr->data;

    const int size = (w + margin_modules * 2) * module_px;
    std::string svg;
    svg.reserve((size_t)size * 10);

    svg += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    svg += "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\"";
    svg += " width=\"" + std::to_string(size) + "\" height=\"" + std::to_string(size) + "\"";
    svg += " viewBox=\"0 0 " + std::to_string(size) + " " + std::to_string(size) + "\">\n";
    svg += "<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n";

    for (int y = 0; y < w; y++) {
        for (int x = 0; x < w; x++) {
            const int idx = y * w + x;
            const bool dark = (d[idx] & 1) != 0;
            if (!dark) continue;

            const int xx = (x + margin_modules) * module_px;
            const int yy = (y + margin_modules) * module_px;

            svg += "<rect x=\"" + std::to_string(xx) + "\" y=\"" + std::to_string(yy) + "\"";
            svg += " width=\"" + std::to_string(module_px) + "\" height=\"" + std::to_string(module_px) + "\"";
            svg += " fill=\"black\"/>\n";
        }
    }

    svg += "</svg>\n";
    QRcode_free(qr);
    return svg;
}

static bool load_env_key(const char* name, unsigned char* out, size_t outLenExpected) {
    const char* s = std::getenv(name);
    if (!s) return false;
    size_t out_len = 0;
    if (sodium_base642bin(out, outLenExpected, s, std::strlen(s),
                          nullptr, &out_len, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) return false;
    return out_len == outLenExpected;
}

// -----------------------------------------------------------------------------
// Build ST payload canonical JSON (string-built to lock order, matching Python)
// -----------------------------------------------------------------------------
static std::string build_req_payload_canonical(
    const std::string& sid,
    const std::string& chal,
    const std::string& nonce,
    long issued_at,
    long expires_at
) {
    std::string rp = pqnas::lower_ascii(RP_ID);
    std::string rp_id_hash = pqnas::sha256_b64_std_str(rp);

    return std::string("{")
        + "\"aud\":\"" + AUD + "\","
        + "\"chal\":\"" + chal + "\","
        + "\"expires_at\":" + std::to_string(expires_at) + ","
        + "\"issued_at\":" + std::to_string(issued_at) + ","
        + "\"iss\":\"" + ISS + "\","
        + "\"nonce\":\"" + nonce + "\","
        + "\"origin\":\"" + ORIGIN + "\","
        + "\"rp_id\":\"" + RP_ID + "\","
        + "\"rp_id_hash\":\"" + rp_id_hash + "\","
        + "\"scope\":\"" + SCOPE + "\","
        + "\"sid\":\"" + sid + "\","
        + "\"typ\":\"st\","
        + "\"v\":4"
        + "}";
}


static std::string slurp_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string sign_req_token(const std::string& payload_json) {
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long siglen = 0;

    crypto_sign_detached(
        sig, &siglen,
        reinterpret_cast<const unsigned char*>(payload_json.data()),
        (unsigned long long)payload_json.size(),
        SERVER_SK
    );

    std::string payload_b64 = b64url_enc(reinterpret_cast<const unsigned char*>(payload_json.data()), payload_json.size());
    std::string sig_b64     = b64url_enc(sig, crypto_sign_BYTES);
    return "v4." + payload_b64 + "." + sig_b64;
}

[[maybe_unused]]
static bool decode_st_payload_json(const std::string& st, std::string& payload_json_out) {
    size_t a = st.find('.');
    if (a == std::string::npos) return false;
    size_t b = st.find('.', a + 1);
    if (b == std::string::npos) return false;

    std::string payload_b64 = st.substr(a + 1, b - (a + 1));
    std::string payload_bytes;
    if (!b64url_decode_to_bytes(payload_b64, payload_bytes)) return false;

    payload_json_out.assign(payload_bytes.begin(), payload_bytes.end());
    return true;
}

static std::string sign_token_v4_ed25519(const json& payload_obj, const unsigned char sk[64]) {
    std::string payload = payload_obj.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr,
                         reinterpret_cast<const unsigned char*>(payload.data()),
                         (unsigned long long)payload.size(),
                         sk);

    std::string p64 = b64url_enc(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    std::string s64 = b64url_enc(sig, sizeof(sig));

    return std::string("v4.") + p64 + "." + s64;
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main()
{
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed" << std::endl;
        return 1;
    }

    if (!load_env_key("PQNAS_SERVER_PK_B64URL", SERVER_PK, 32) ||
        !load_env_key("PQNAS_SERVER_SK_B64URL", SERVER_SK, 64) ||
        !load_env_key("PQNAS_COOKIE_KEY_B64URL", COOKIE_KEY, 32)) {
        std::cerr << "Missing/invalid env keys. Run ./build/bin/pqnas_keygen > .env.pqnas then: source .env.pqnas" << std::endl;
        return 2;
        }

    if (const char* v = std::getenv("PQNAS_ORIGIN")) ORIGIN = v;
    if (const char* v = std::getenv("PQNAS_ISS")) ISS = v;
    if (const char* v = std::getenv("PQNAS_AUD")) AUD = v;
    if (const char* v = std::getenv("PQNAS_SCOPE")) SCOPE = v;
    if (const char* v = std::getenv("PQNAS_APP_NAME")) APP_NAME = v;
    if (const char* v = std::getenv("PQNAS_RP_ID")) RP_ID = v;
    if (const char* v = std::getenv("PQNAS_REQ_TTL")) REQ_TTL = std::atoi(v);
    if (const char* v = std::getenv("PQNAS_SESS_TTL")) SESS_TTL = std::atoi(v);
    if (const char* v = std::getenv("PQNAS_LISTEN_PORT")) LISTEN_PORT = std::atoi(v);

    httplib::Server srv;

    // ---- Audit log (hash-chained JSONL) ----
    const std::string audit_dir = exe_dir() + "/audit";
    try {
        std::filesystem::create_directories(audit_dir);
    } catch (const std::exception& e) {
        std::cerr << "[audit] WARNING: create_directories failed: " << e.what() << std::endl;
    }

    const std::string audit_jsonl_path = audit_dir + "/pqnas_audit.jsonl";
    const std::string audit_state_path = audit_dir + "/pqnas_audit.state";
    pqnas::AuditLog audit(audit_jsonl_path, audit_state_path);
    // declare early so routes can call it
    std::function<void(const pqnas::AuditEvent&)> audit_append;
    // ---- Admin settings path (must exist before any helpers use it) ----
    std::string admin_settings_path =
        (std::filesystem::path(REPO_ROOT) / "config" / "admin_settings.json").string();
    if (const char* p = std::getenv("PQNAS_ADMIN_SETTINGS_PATH")) {
        admin_settings_path = p;
    }

    // ---------------------------
    // Auto-rotation (checked before every audit.append)
    // ---------------------------

    // in-memory day marker helper (UTC)
    auto utc_day_yyyymmdd_local = [&]() -> std::string {
        try {
            std::time_t tt = std::time(nullptr);
            std::tm tm{};
#if defined(_WIN32)
            gmtime_s(&tm, &tt);
#else
            gmtime_r(&tt, &tm);
#endif
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
            return std::string(buf);
        } catch (...) {
            return "1970-01-01";
        }
    };

    // cache admin_settings.json reads so we don't hit disk on every audit line
    auto load_admin_settings_cached = [&](const std::string& path) -> json {
        using clock = std::chrono::steady_clock;

        static clock::time_point last_check = clock::now() - std::chrono::seconds(60);
        static std::filesystem::file_time_type last_mtime{};
        static bool last_mtime_valid = false;
        static json cached = json::object();

        const auto now = clock::now();
        if (now - last_check < std::chrono::seconds(2)) {
            return cached;
        }
        last_check = now;

        std::error_code ec;
        const auto mt = std::filesystem::last_write_time(path, ec);
        const bool mt_ok = !ec;

        const bool changed =
            !last_mtime_valid ||
            !mt_ok ||
            (mt != last_mtime);

        if (!changed) {
            return cached;
        }

        // reload
        json j = json::object();
        try {
            std::ifstream f(path);
            if (f.good()) {
                f >> j;
                if (!j.is_object()) j = json::object();
            }
        } catch (...) {
            j = json::object();
        }

        cached = j;
        last_mtime_valid = mt_ok;
        if (mt_ok) last_mtime = mt;
        return cached;
    };

    // rotate implementation (single place) — IMPORTANT: no recursion here
    auto rotate_audit_now_internal = [&](const std::string& reason_tag) -> bool {
        try {
            pqnas::AuditLog::RotateOptions opt;
            pqnas::AuditLog::RotateResult rr;
            const bool ok = audit.rotate(opt, &rr);
            if (!ok) return false;

            // Optional: log the rotation itself (best-effort) WITHOUT calling maybe_auto_rotate_before_append()
            try {
                pqnas::AuditEvent ev;
                ev.event = "audit.auto_rotated";
                ev.outcome = "ok";
                ev.f["reason"] = reason_tag;
                ev.f["rotated_jsonl_path"] = rr.rotated_jsonl_path;
                ev.f["ip"] = "local";
                audit_append(ev);
            } catch (...) {}

            return true;
        } catch (...) {
            return false;
        }
    };


    // the actual policy check: call this before audit.append(ev)
    auto maybe_auto_rotate_before_append = [&]() {
        json settings = load_admin_settings_cached(admin_settings_path);

        // Expect: settings["audit_rotation"] = { "mode": "...", "max_active_mb": N }
        json rot = json::object();
        if (settings.contains("audit_rotation") && settings["audit_rotation"].is_object()) {
            rot = settings["audit_rotation"];
        }

        const std::string mode = rot.value("mode", "off");
        const int max_mb = rot.value("max_active_mb", 512);

        if (mode == "off") return;

        static std::string last_rotated_day = utc_day_yyyymmdd_local();

        // daily trigger (UTC)
        if (mode == "daily" || mode == "size_or_daily") {
            const std::string today = utc_day_yyyymmdd_local();
            if (today != last_rotated_day) {
                if (rotate_audit_now_internal("daily")) {
                    last_rotated_day = today;
                    return; // done
                }
            }
        }

        // size trigger
        if (mode == "size_mb" || mode == "size_or_daily") {
            const long long bytes = file_size_bytes_safe(audit_jsonl_path);
            const long long limit = (long long)max_mb * 1024LL * 1024LL;
            if (bytes >= 0 && bytes >= limit) {
                (void)rotate_audit_now_internal("size_mb");
            }
        }
    };

    // OPTIONAL: use this wrapper everywhere instead of calling audit.append(ev) directly
    audit_append = [&](const pqnas::AuditEvent& ev) {
        maybe_auto_rotate_before_append();
        audit.append(ev);
    };


    // ---- Load admin settings once at startup (audit min level) ----
    try {
        std::ifstream f(admin_settings_path);
        if (f.good()) {
            json j = json::parse(f, nullptr, true);

            std::string lvl;
            auto it = j.find("audit_min_level");
            if (it != j.end() && it->is_string()) {
                lvl = it->get<std::string>();
            }

            if (!lvl.empty()) {
                if (!audit.set_min_level_str(lvl)) {
                    std::cerr << "[settings] WARNING: invalid audit_min_level in "
                              << admin_settings_path << std::endl;
                } else {
                    std::cerr << "[settings] audit_min_level=" << audit.min_level_str() << std::endl;
                }
            }
        } else {
            std::cerr << "[settings] no admin_settings.json, default audit_min_level="
                      << audit.min_level_str() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[settings] WARNING: failed to load " << admin_settings_path
                  << ": " << e.what() << std::endl;
    }

std::atomic<bool> audit_rotator_stop{false};
std::thread audit_rotator([&]() {
    std::string last_day = utc_day_yyyymmdd();

    while (!audit_rotator_stop.load()) {
        // Load settings each tick so admin changes apply without restart
        const nlohmann::json settings = load_admin_settings_safe(admin_settings_path);
        const AuditRotateCfg cfg = get_rotate_cfg_from_settings(settings);

        bool should_rotate = false;
        std::string reason;

        // 1) size trigger
        if (cfg.max_active_bytes > 0) {
            const long long sz = file_size_bytes_safe(audit_jsonl_path);
            if (sz >= 0 && sz >= cfg.max_active_bytes) {
                should_rotate = true;
                reason = "size";
            }
        }

        // 2) daily trigger (UTC day changed)
        if (!should_rotate && cfg.daily_utc) {
            const std::string today = utc_day_yyyymmdd();
            if (today != last_day) {
                should_rotate = true;
                reason = "daily";
            }
        }

        if (should_rotate) {
            pqnas::AuditLog::RotateOptions opt;
            pqnas::AuditLog::RotateResult rr;
            const bool ok = audit.rotate(opt, &rr);

            // best-effort audit event (don’t crash thread)
            try {
                pqnas::AuditEvent ev;
                ev.event = "audit.auto_rotated";
                ev.outcome = ok ? "ok" : "fail";
                ev.f["reason"] = reason;
                ev.f["rotated_jsonl_path"] = ok ? rr.rotated_jsonl_path : "";
                maybe_auto_rotate_before_append();
                audit_append(ev);
            } catch (...) {}

            // Update last_day ONLY when day-based rotate fired (or after any successful rotate)
            // so we don't rotate repeatedly in the same day.
            if (cfg.daily_utc) {
                last_day = utc_day_yyyymmdd();
            }
        }

        for (int i = 0; i < cfg.check_interval_sec * 10; i++) {
            if (audit_rotator_stop.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
});

// Generic static handler: /static/<anything>
// Must come AFTER specific /static/*.js handlers so those remain unchanged.
srv.Get(R"(/static/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
    // req.matches[1] is the captured path after /static/
    if (req.matches.size() < 2) {
        res.status = 400;
        res.set_header("Content-Type", "text/plain");
        res.body = "Bad static request";
        return;
    }

    const std::string rel = req.matches[1].str();

    if (!is_safe_static_relpath(rel)) {
        res.status = 403;
        res.set_header("Content-Type", "text/plain");
        res.body = "Forbidden";
        return;
    }

    const std::filesystem::path base = std::filesystem::path("server/src/static");
    const std::filesystem::path full = base / rel;

    // Fail-closed: only serve known safe extensions
    if (!has_allowed_static_ext(full)) {
        res.status = 404;
        res.set_header("Content-Type", "text/plain");
        res.body = "Not found";
        return;
    }

    std::string body;
    if (!read_file_to_string(full.string(), body) || body.empty()) {
        res.status = 404;
        res.set_header("Content-Type", "text/plain");
        res.body = "Missing static file: " + full.string();
        return;
    }

    std::string ext = full.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    const std::string ct = mime_for_ext(ext);
    res.status = 200;
    res.set_header("Content-Type", ct.c_str());
    // Most static assets can be cached; but if you want no-cache everywhere, change here.
    // res.set_header("Cache-Control", "no-store");
    res.body = std::move(body);
});



    // Option A: fixed policy location in repo, with optional env override
    std::string allowlist_path =
        (std::filesystem::path(REPO_ROOT) / "config" / "policy.json").string();
    if (const char* p = std::getenv("PQNAS_POLICY_PATH")) {
        allowlist_path = p;
    }

    pqnas::Allowlist allowlist;
    if (!allowlist.load(allowlist_path)) {
        std::cerr << "[policy] FATAL: failed to load allowlist: " << allowlist_path << std::endl;
        return 3;
    }

	std::string users_path =
    	(std::filesystem::path(REPO_ROOT) / "config" / "users.json").string();
	if (const char* p = std::getenv("PQNAS_USERS_PATH")) {
	    users_path = p;
	}

	pqnas::UsersRegistry users;
	if (!users.load(users_path)) {
    	std::cerr << "[users] FATAL: failed to load users registry: " << users_path << std::endl;
    	return 4;
	}

// ----- GET /api/v4/system (user+admin) --------------------------------------
srv.Get("/api/v4/system", [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &actor_fp, &role)) return;

    json out = pqnas::collect_system_snapshot(REPO_ROOT);

    // keep viewer here because it's auth/policy-level, not "system metrics"
    out["viewer"] = {
        {"fingerprint_hex", actor_fp},
        {"role", role}
    };

    res.set_header("Cache-Control", "no-store");
    reply_json(res, 200, out.dump());
});


srv.Get("/static/system.js", [&](const httplib::Request&, httplib::Response& res) {
    std::string body;
    if (!read_file_to_string(STATIC_SYSTEM_JS, body) || body.empty()) {
        res.status = 404;
        res.set_header("Content-Type", "text/plain");
        res.body = "Missing static file: " + STATIC_SYSTEM_JS;
        return;
    }
    res.status = 200;
    res.set_header("Content-Type", "application/javascript; charset=utf-8");
    res.body = body;
});

    srv.Get("/admin/audit", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        res.set_header("Cache-Control", "no-store");
        res.set_content(slurp_file(STATIC_AUDIT_HTML), "text/html; charset=utf-8");
    });


    srv.Get("/admin", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        const std::string body = slurp_file(STATIC_ADMIN_HTML);
        if (body.empty()) {
            res.status = 404;
            res.set_content("missing admin.html", "text/plain");
            return;
        }

        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "text/html; charset=utf-8");
    });

    srv.Get("/static/app.js", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_APP_JS);
        if (body.empty()) { res.status = 404; res.set_content("missing app.js","text/plain"); return; }
        res.set_content(body, "application/javascript; charset=utf-8");
    });

    srv.Get("/static/admin.js", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_ADMIN_JS);
        if (body.empty()) { res.status = 404; res.set_content("missing admin.js","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "application/javascript; charset=utf-8");
    });




    srv.Get("/static/admin_audit.js", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_AUDIT_JS);
        if (body.empty()) {
            std::cerr << "[/static/admin_audit.js] ERROR: empty body. path=" << STATIC_AUDIT_JS << std::endl;
            res.status = 404;
            res.set_content("missing admin_audit.js", "text/plain");
            return;
        }
        res.set_content(body, "application/javascript; charset=utf-8");
    });

    srv.Get("/static/pqnas_v4.js", [&](const httplib::Request&, httplib::Response& res) {
        std::string body;
        if (!read_file_to_string(STATIC_JS, body)) {
            res.status = 500;
            res.set_header("Content-Type", "text/plain");
            res.body = "Missing static file: " + STATIC_JS;
            return;
        }
        res.status = 200;
        res.set_header("Content-Type", "application/javascript; charset=utf-8");
        res.body = body;
    });

    // after successful consume, browser goes here
    srv.Get("/success", [&](const httplib::Request&, httplib::Response& res) {
        res.status = 302;
        res.set_header("Location", "/app");
    });

    srv.Get("/app", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_APP_HTML);
        if (body.empty()) {
            res.status = 404;
            res.set_content("missing app.html", "text/plain");
            return;
        }
        res.set_content(body, "text/html; charset=utf-8");
    });




    srv.Get("/", [&](const httplib::Request&, httplib::Response& res) {
        std::string body;
        if (!read_file_to_string(STATIC_LOGIN, body)) {
            res.status = 500;
            res.set_header("Content-Type", "text/plain");
            res.body = "Missing static file: " + STATIC_LOGIN;
            return;
        }
        res.status = 200;
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.body = body;
    });


    srv.Get("/api/v4/admin/ping", [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin_cookie_users(req, res, COOKIE_KEY, users_path, &users)) {
            return;
        }
        reply_json(res, 200, json({{"ok",true},{"admin",true}}).dump());
    });

// Polling endpoint (browser)
srv.Get("/api/v4/status", [&](const httplib::Request& req, httplib::Response& res) {
    // Prune both maps (approvals + pending) up-front so we don't leak memory
    const long now0 = pqnas::now_epoch();
    approvals_prune(now0);
    pending_prune(now0);

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& sid, const std::string& reason, int http_code) {
        pqnas::AuditEvent ev;
        ev.event = "v4.status_fail";
        ev.outcome = "fail";
        if (!sid.empty()) ev.f["sid"] = sid;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http_code);
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto sid = req.get_param_value("sid");
    if (sid.empty()) {
        audit_fail("", "missing_sid", 400);
        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing sid"}}).dump());
        return;
    }

    // 1) If we have an approval entry, the phone already verified and /consume can succeed.
    ApprovalEntry e;
    if (approvals_get(sid, e)) {
        const long now = pqnas::now_epoch();
        if (now > e.expires_at) {
            approvals_pop(sid);
            reply_json(res, 200, json({{"ok",true},{"approved",false},{"expired",true}}).dump());
            return;
        }

        reply_json(res, 200, json({{"ok",true},{"approved",true},{"fingerprint",e.fingerprint}}).dump());
        return;
    }

    // 2) Otherwise: if this sid was marked pending (unknown/disabled user), tell browser to show wait page.
    PendingEntry pe;
    if (pending_get(sid, pe)) {
        const long now = pqnas::now_epoch();
        if (now <= pe.expires_at) {
            json out = {
                {"ok", true},
                {"approved", false},
                {"pending_admin", true},
            };
            // Only include reason if you actually store one (optional)
            if (!pe.reason.empty()) out["reason"] = pe.reason;

            reply_json(res, 200, out.dump());
            return;
        } else {
            pending_pop(sid);
        }
    }

    // 3) Default: not approved (normal "still waiting for phone approval" case)
    reply_json(res, 200, json({{"ok",true},{"approved",false}}).dump());
});

    // POST /api/v4/consume
    srv.Post("/api/v4/consume", [&](const httplib::Request& req, httplib::Response& res) {
        approvals_prune(pqnas::now_epoch());

        auto audit_ua = [&]() -> std::string {
            auto it = req.headers.find("User-Agent");
            return pqnas::shorten(it == req.headers.end() ? "" : it->second);
        };

        auto audit_fail = [&](const std::string& sid, const std::string& reason, int http_code) {
            pqnas::AuditEvent ev;
            ev.event = "v4.consume_fail";
            ev.outcome = "fail";
            if (!sid.empty()) ev.f["sid"] = sid;
            ev.f["reason"] = reason;
            ev.f["http"] = std::to_string(http_code);
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            ev.f["ua"] = audit_ua();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        };

        try {
            json body = json::parse(req.body);
            std::string sid = body.value("sid", "");
            if (sid.empty()) {
                audit_fail("", "missing_sid", 400);
                reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing sid"}}).dump());
                return;
            }

            ApprovalEntry e;
            if (!approvals_get(sid, e)) {
                audit_fail(sid, "not_approved", 404);
                reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","not approved"}}).dump());
                return;
            }

            long now = pqnas::now_epoch();
            if (now > e.expires_at) {
                approvals_pop(sid);
                audit_fail(sid, "approval_expired", 410);
                reply_json(res, 410, json({{"ok",false},{"error","expired"},{"message","approval expired"}}).dump());
                return;
            }

            approvals_pop(sid);

            {
                pqnas::AuditEvent ev;
                ev.event = "v4.consume_ok";
                ev.outcome = "ok";
                ev.f["sid"] = sid;
                if (!e.fingerprint.empty()) ev.f["fingerprint"] = e.fingerprint;
                ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
                ev.f["ua"] = audit_ua();
                maybe_auto_rotate_before_append();
                audit_append(ev);
            }

            const bool secure = (ORIGIN.rfind("https://", 0) == 0);

            std::string cookie = "pqnas_session=" + e.cookie_val + "; Path=/; HttpOnly; SameSite=Lax";
            cookie += "; Max-Age=" + std::to_string(SESS_TTL);
            if (secure) cookie += "; Secure";

            {
                pqnas::AuditEvent ev;
                ev.event = "v4.cookie_set";
                ev.outcome = "ok";
                ev.f["sid"] = sid;
                if (!e.fingerprint.empty()) ev.f["fingerprint"] = e.fingerprint;
                ev.f["secure"] = secure ? "true" : "false";
                ev.f["max_age"] = std::to_string(SESS_TTL);

                ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

                auto it_cf = req.headers.find("CF-Connecting-IP");
                if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

                auto it_xff = req.headers.find("X-Forwarded-For");
                if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

                ev.f["ua"] = audit_ua();
                maybe_auto_rotate_before_append();
                audit_append(ev);
            }

            res.set_header("Set-Cookie", cookie);
            reply_json(res, 200, json({{"ok",true}}).dump());
        } catch (const std::exception& e) {
            audit_fail("", "bad_json", 400);
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"},{"detail",e.what()}}).dump());
        }
    });

     srv.Get("/api/v4/audit/tail", [&](const httplib::Request& req, httplib::Response& res) {
        int n = 200;
        if (req.has_param("n")) {
            try { n = std::stoi(req.get_param_value("n")); } catch (...) {}
        }
        n = std::max(1, std::min(1000, n));

        std::ifstream f(audit_jsonl_path);
        std::deque<json> q;
        std::string line;

        if (f.good()) {
            while (std::getline(f, line)) {
                if (line.empty()) continue;
                try {
                    q.push_back(json::parse(line));
                    if ((int)q.size() > n) q.pop_front();
                } catch (...) {}
            }
        }

        json out;
        out["ok"] = true;
        out["lines"] = json::array();
        for (auto& jj : q) out["lines"].push_back(jj);

        reply_json(res, 200, out.dump());
    });

    srv.Get("/api/v4/audit/verify", [&](const httplib::Request&, httplib::Response& res) {
        std::string state = trim_nl(slurp_file(audit_state_path));

        std::string last_hash;
        {
            std::ifstream f(audit_jsonl_path);
            std::string line, last;
            if (f.good()) {
                while (std::getline(f, line)) {
                    if (!line.empty()) last = line;
                }
            }
            if (!last.empty()) {
                try {
                    json jj = json::parse(last);
                    last_hash = jj.value("line_hash", "");
                } catch (...) {}
            }
        }

        bool ok = (!state.empty() && !last_hash.empty() && state == last_hash);

        reply_json(res, 200, json{
            {"ok", ok},
            {"state", state},
            {"last_line_hash", last_hash}
        }.dump());
    });

    // Admin Settings UI
    srv.Get("/admin/settings", [&](const httplib::Request& req, httplib::Response& res) {
        // Gate page itself (admin-only)
        if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

        std::string body;
        if (!read_file_to_string(STATIC_ADMIN_SETTINGS_HTML, body)) {
            res.status = 500;
            res.set_header("Content-Type", "text/plain");
            res.body = "Missing static file: " + STATIC_ADMIN_SETTINGS_HTML;
            return;
        }
        res.status = 200;
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.body = body;
    });

    // ---- Admin: rotate audit log ----
    srv.Post("/api/v4/admin/rotate-audit", [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) {
            return;
        }

        pqnas::AuditLog::RotateOptions opt;
        pqnas::AuditLog::RotateResult rr;

        const bool ok = audit.rotate(opt, &rr);

		nlohmann::json j;

		if (!ok) {
    		j["ok"] = false;
    		j["error"] = "rotate_failed";
    		res.status = 500;
    		res.set_content(j.dump(2), "application/json; charset=utf-8");
    		return;
		}

		j["ok"] = true;
		j["rotated_jsonl_path"] = rr.rotated_jsonl_path;
		j["rotated_state_path"] = rr.rotated_state_path;
		j["chain_start_prev_hash"] = rr.chain_start_prev_hash_hex;

		res.set_content(j.dump(2), "application/json; charset=utf-8");

    });

// ---- Admin: audit retention preview (dry-run) ----
srv.Post("/api/v4/admin/audit/preview-prune", [&](const httplib::Request& req, httplib::Response& res) {
    if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

    nlohmann::json in = nlohmann::json::object();
    if (!req.body.empty()) {
        in = nlohmann::json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) in = nlohmann::json::object();
    }

    // UI sends: { "audit_retention": { ... } }
    nlohmann::json pol = nlohmann::json::object();
    if (in.contains("audit_retention")) pol = in["audit_retention"];
    pol = normalize_retention_or_default_local(pol);

    const auto archives = list_rotated_archives_local(audit_jsonl_path);
    const auto out = build_preview_local(archives, pol);

    reply_json(res, 200, out.dump());
});

// ---- Admin: audit retention prune (delete candidates based on SAVED policy) ----
srv.Post("/api/v4/admin/audit/prune", [&](const httplib::Request& req, httplib::Response& res) {
    if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

    // Load saved retention policy from admin_settings_path
    nlohmann::json persisted = nlohmann::json::object();
    try {
        std::ifstream f(admin_settings_path);
        if (f.good()) f >> persisted;
        if (!persisted.is_object()) persisted = nlohmann::json::object();
    } catch (...) {
        persisted = nlohmann::json::object();
    }

    nlohmann::json pol = nlohmann::json::object();
    if (persisted.contains("audit_retention")) pol = persisted["audit_retention"];
    pol = normalize_retention_or_default_local(pol);

    const auto archives = list_rotated_archives_local(audit_jsonl_path);
    const auto preview = build_preview_local(archives, pol);

    long long deleted_bytes = 0;
    int deleted_files = 0;

    try {
        const auto cands = preview.value("candidates", nlohmann::json::array());

        // For each candidate archive name, delete both jsonl + state (if present)
        for (const auto& cj : cands) {
            const std::string name = cj.value("name", "");
            if (name.empty()) continue;

            auto it = std::find_if(archives.begin(), archives.end(),
                                   [&](const ArchivePair& a) { return a.name == name; });
            if (it == archives.end()) continue;

            std::error_code ec;

            if (!it->jsonl_path.empty()) {
                if (std::filesystem::remove(it->jsonl_path, ec)) deleted_files++;
                ec.clear();
            }
            if (!it->state_path.empty()) {
                if (std::filesystem::remove(it->state_path, ec)) deleted_files++;
                ec.clear();
            }

            deleted_bytes += std::max(0LL, it->size_bytes);
        }

        // Audit (best-effort)
        try {
            pqnas::AuditEvent ev;
            ev.event = "admin.audit_pruned";
            ev.outcome = "ok";
            ev.f["deleted_files"] = deleted_files;
            ev.f["deleted_bytes"] = deleted_bytes;
            ev.f["policy"] = pol;
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_ua = req.headers.find("User-Agent");
            ev.f["ua"] = pqnas::shorten(it_ua == req.headers.end() ? "" : it_ua->second);
            maybe_auto_rotate_before_append();
            audit_append(ev);
        } catch (...) {}

        reply_json(res, 200, nlohmann::json{
            {"ok", true},
            {"deleted_files", deleted_files},
            {"deleted_bytes", deleted_bytes},
        }.dump());

    } catch (...) {
        reply_json(res, 500, nlohmann::json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "prune failed"},
        }.dump());
    }
});



    srv.Get("/static/admin_settings.js", [&](const httplib::Request&, httplib::Response& res) {
        // You can leave JS ungated (like other static files), page is gated anyway.
        std::string body;
        if (!read_file_to_string(STATIC_ADMIN_SETTINGS_JS, body)) {
            res.status = 500;
            res.set_header("Content-Type", "text/plain");
            res.body = "Missing static file: " + STATIC_ADMIN_SETTINGS_JS;
            return;
        }
        res.status = 200;
        res.set_header("Content-Type", "application/javascript; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.body = body;
    });

    // Admin settings API
    srv.Get("/api/v4/admin/settings", [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

        auto load_settings_json = [&]() -> json {
            try {
                std::ifstream f(admin_settings_path);
                if (!f.good()) return json::object();
                json j;
                f >> j;
                if (!j.is_object()) return json::object();
                return j;
            } catch (...) {
                return json::object();
            }
        };

        // Defaults
        json persisted = load_settings_json();

        // Persisted min level (file), runtime min level (AuditLog)
        std::string persisted_lvl = audit.min_level_str();
        auto it = persisted.find("audit_min_level");
        if (it != persisted.end() && it->is_string()) {
            persisted_lvl = it->get<std::string>();
        }

        // Retention defaults (if absent)
        json retention = json::object();
        if (persisted.contains("audit_retention") && persisted["audit_retention"].is_object()) {
            retention = persisted["audit_retention"];
        } else {
            retention = json{
                {"mode", "never"},
                {"days", 90},
                {"max_files", 50},
                {"max_total_mb", 20480}
            };
        }
        // Rotation defaults (if absent)
        json rotation = json::object();
        if (persisted.contains("audit_rotation") && persisted["audit_rotation"].is_object()) {
            rotation = persisted["audit_rotation"];
        } else {
            rotation = json{
                {"mode", "manual"},        // manual | daily | size_mb | daily_or_size_mb
                {"max_active_mb", 256},    // used when size-based trigger is enabled
                {"rotate_utc_day", ""}     // optional: last-rotated UTC day tracker (YYYY-MM-DD)
            };
        }

		const long long active_bytes = file_size_bytes_safe(audit_jsonl_path);

		reply_json(res, 200, json{
    		{"ok", true},

    		{"audit_min_level", persisted_lvl},
    		{"audit_min_level_runtime", audit.min_level_str()},
    		{"allowed", json::array({"SECURITY","ADMIN","INFO","DEBUG"})},

		    {"audit_retention", retention},
            {"audit_rotation", rotation},
    		// NEW: active audit file info for UI
    		{"audit_active_path", audit_jsonl_path},
    		{"audit_active_bytes", active_bytes}
		}.dump());

    });

    srv.Post("/api/v4/admin/settings", [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

        auto load_settings_json = [&]() -> json {
            try {
                std::ifstream f(admin_settings_path);
                if (!f.good()) return json::object();
                json j;
                f >> j;
                if (!j.is_object()) return json::object();
                return j;
            } catch (...) {
                return json::object();
            }
        };

        // Merge patch into existing file, write atomically (tmp + rename)
        auto save_settings_patch = [&](const json& patch) -> bool {
            try {
                if (!patch.is_object()) return false;

                json merged = json::object();
                {
                    std::ifstream in(admin_settings_path);
                    if (in.good()) {
                        in >> merged;
                        if (!merged.is_object()) merged = json::object();
                    }
                }

                for (auto& it : patch.items()) {
                    merged[it.key()] = it.value();
                }

                const std::string tmp = admin_settings_path + ".tmp";
                {
                    std::ofstream f(tmp, std::ios::trunc);
                    if (!f.good()) return false;
                    f << merged.dump(2) << "\n";
                    f.flush();
                    if (!f.good()) return false;
                }

                std::error_code ec;
                std::filesystem::rename(tmp, admin_settings_path, ec);
                if (ec) {
                    std::filesystem::remove(tmp);
                    return false;
                }

                return true;
            } catch (...) {
                return false;
            }
        };

        auto is_allowed_level = [&](const std::string& lvl) -> bool {
            return (lvl == "SECURITY" || lvl == "ADMIN" || lvl == "INFO" || lvl == "DEBUG");
        };

        // SAFE accessor for audit_min_level (never throws)
        auto get_level_safe = [&](const json& j, const std::string& fallback) -> std::string {
            auto it2 = j.find("audit_min_level");
            if (it2 != j.end() && it2->is_string()) return it2->get<std::string>();
            return fallback;
        };
        auto is_allowed_rotation_mode = [&](const std::string& m) -> bool {
            return (m == "manual" || m == "daily" || m == "size_mb" || m == "daily_or_size_mb");
        };

        // Normalize rotation safely (never throws; returns null json on error + sets err)
        auto normalize_rotation = [&](const json& in_rot, std::string& err) -> json {
            err.clear();

            if (!in_rot.is_object()) {
                err = "audit_rotation must be an object";
                return json();
            }

            std::string mode = "manual";
            {
                auto it2 = in_rot.find("mode");
                if (it2 != in_rot.end() && !it2->is_null()) {
                    if (!it2->is_string()) {
                        err = "audit_rotation.mode must be string";
                        return json();
                    }
                    mode = it2->get<std::string>();
                }
            }
            if (!is_allowed_rotation_mode(mode)) {
                err = "audit_rotation.mode must be one of: manual, daily, size_mb, daily_or_size_mb";
                return json();
            }

            auto get_int = [&](const char* key, int def, int lo, int hi) -> int {
                auto it2 = in_rot.find(key);
                if (it2 == in_rot.end() || it2->is_null()) return def;

                if (!it2->is_number_integer()) {
                    err = std::string("audit_rotation.") + key + " must be integer";
                    return def;
                }
                int v = it2->get<int>();
                if (v < lo) v = lo;
                if (v > hi) v = hi;
                return v;
            };

            // only used for size-based modes
            int max_active_mb = get_int("max_active_mb", 256, 1, 10000000);
            if (!err.empty()) return json();

            // optional tracker field
            std::string rotate_utc_day = "";
            {
                auto it2 = in_rot.find("rotate_utc_day");
                if (it2 != in_rot.end() && it2->is_string()) rotate_utc_day = it2->get<std::string>();
            }

            return json{
                {"mode", mode},
                {"max_active_mb", max_active_mb},
                {"rotate_utc_day", rotate_utc_day},
            };
        };
        // Normalize retention safely (never throws; returns null json on error + sets err)
        auto normalize_retention = [&](const json& in_ret, std::string& err) -> json {
            err.clear();

            if (!in_ret.is_object()) {
                err = "audit_retention must be an object";
                return json();
            }

            // mode
            std::string mode = "never";
            {
                auto it2 = in_ret.find("mode");
                if (it2 != in_ret.end() && !it2->is_null()) {
                    if (!it2->is_string()) {
                        err = "audit_retention.mode must be string";
                        return json();
                    }
                    mode = it2->get<std::string>();
                }
            }

            if (!(mode == "never" || mode == "days" || mode == "files" || mode == "size_mb")) {
                err = "audit_retention.mode must be one of: never, days, files, size_mb";
                return json();
            }

            auto get_int = [&](const char* key, int def, int lo, int hi) -> int {
                auto it2 = in_ret.find(key);
                if (it2 == in_ret.end() || it2->is_null()) return def;

                if (!it2->is_number_integer()) {
                    err = std::string("audit_retention.") + key + " must be integer";
                    return def;
                }

                int v = it2->get<int>();
                if (v < lo) v = lo;
                if (v > hi) v = hi;
                return v;
            };

            int days         = get_int("days",         90,    1,       3650);
            if (!err.empty()) return json();
            int max_files    = get_int("max_files",    50,    1,      50000);
            if (!err.empty()) return json();
            int max_total_mb = get_int("max_total_mb", 20480, 1,   10000000);
            if (!err.empty()) return json();

            return json{
                {"mode", mode},
                {"days", days},
                {"max_files", max_files},
                {"max_total_mb", max_total_mb},
            };
        };

        try {
            if (req.body.empty()) {
                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "empty request body (expected JSON object)"}
                }.dump());
                return;
            }

            json in = json::parse(req.body, nullptr, false);
            if (in.is_discarded()) {
                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid json"}
                }.dump());
                return;
            }

            if (!in.is_object()) {
                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "json must be object"}
                }.dump());
                return;
            }

            json persisted = load_settings_json();
            if (!persisted.is_object()) persisted = json::object();

            const std::string before_runtime   = audit.min_level_str();
            const std::string before_persisted = get_level_safe(persisted, before_runtime);
            json before_rotation = json::object();
            if (persisted.contains("audit_rotation") && persisted["audit_rotation"].is_object()) {
                before_rotation = persisted["audit_rotation"];
            }

            json before_ret = json::object();
            if (persisted.contains("audit_retention") && persisted["audit_retention"].is_object()) {
                before_ret = persisted["audit_retention"];
            }

            bool changed_level = false;
            bool changed_ret   = false;
            bool changed_rotation = false;
            json patch = json::object();

            // ---- audit_min_level (optional) ----
            if (in.contains("audit_min_level")) {
                if (!in["audit_min_level"].is_string()) {
                    reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "audit_min_level must be string"}
                    }.dump());
                    return;
                }

                const std::string lvl = in["audit_min_level"].get<std::string>();
                if (!is_allowed_level(lvl) || !audit.set_min_level_str(lvl)) {
                    reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "invalid audit_min_level"}
                    }.dump());
                    return;
                }

                patch["audit_min_level"] = lvl;
                persisted["audit_min_level"] = lvl; // for response shaping
                changed_level = true;

                // Audit (best-effort)
                try {
                    pqnas::AuditEvent ev;
                    ev.event = "admin.settings_changed";
                    ev.outcome = "ok";
                    ev.f["audit_min_level_before"] = before_persisted;
                    ev.f["audit_min_level_after"] = lvl;
                    ev.f["audit_min_level_runtime_after"] = audit.min_level_str();
                    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
                    auto it_ua = req.headers.find("User-Agent");
                    ev.f["ua"] = pqnas::shorten(it_ua == req.headers.end() ? "" : it_ua->second);
                    maybe_auto_rotate_before_append();
                    audit_append(ev);
                } catch (...) {}
            }

            // ---- audit_retention (optional) ----
            if (in.contains("audit_retention")) {
                std::string err;
                json norm = normalize_retention(in["audit_retention"], err);
                if (!err.empty()) {
                    reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", err}
                    }.dump());
                    return;
                }

                patch["audit_retention"] = norm;
                persisted["audit_retention"] = norm; // for response shaping
                changed_ret = true;

                // Audit (best-effort)
                try {
                    pqnas::AuditEvent ev;
                    ev.event = "admin.settings_changed";
                    ev.outcome = "ok";
                    ev.f["audit_retention_before"] = before_ret.is_null() ? json::object() : before_ret;
                    ev.f["audit_retention_after"]  = norm;
                    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
                    auto it_ua = req.headers.find("User-Agent");
                    ev.f["ua"] = pqnas::shorten(it_ua == req.headers.end() ? "" : it_ua->second);
                    maybe_auto_rotate_before_append();
                    audit_append(ev);
                } catch (...) {}
            }
            // ---- audit_rotation (optional) ----
            if (in.contains("audit_rotation")) {
                std::string err;
                json norm = normalize_rotation(in["audit_rotation"], err);
                if (!err.empty()) {
                    reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", err}
                    }.dump());
                    return;
                }

                patch["audit_rotation"] = norm;
                persisted["audit_rotation"] = norm; // for response shaping
                changed_rotation = true;

                // Audit (best-effort)
                try {
                    pqnas::AuditEvent ev;
                    ev.event = "admin.settings_changed";
                    ev.outcome = "ok";
                    ev.f["audit_rotation_before"] = before_rotation.is_null() ? json::object() : before_rotation;
                    ev.f["audit_rotation_after"]  = norm;
                    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
                    auto it_ua = req.headers.find("User-Agent");
                    ev.f["ua"] = pqnas::shorten(it_ua == req.headers.end() ? "" : it_ua->second);
                    maybe_auto_rotate_before_append();
                    audit_append(ev);
                } catch (...) {}
            }

            if (!changed_level && !changed_ret && !changed_rotation) {

                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "nothing to update (provide audit_min_level and/or audit_retention and/or audit_rotation)"}
                }.dump());
                return;
            }

            if (!save_settings_patch(patch)) {
                reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to save settings"}
                }.dump());
                return;
            }

            // Reply with current state (defaults if missing)
            json retention = json::object();
            if (persisted.contains("audit_retention") && persisted["audit_retention"].is_object()) {
                retention = persisted["audit_retention"];
            } else {
                retention = json{
                    {"mode","never"},{"days",90},{"max_files",50},{"max_total_mb",20480}
                };
            }

		const long long active_bytes = file_size_bytes_safe(audit_jsonl_path);
        // ---- audit_rotation in response ----
        json rotation = json::object();
        if (persisted.contains("audit_rotation") && persisted["audit_rotation"].is_object()) {
            rotation = persisted["audit_rotation"];
        } else {
            rotation = json{
                {"mode","manual"},
                {"max_active_mb",256},
                {"rotate_utc_day",""}
            };
        }

        reply_json(res, 200, json{
            {"ok", true},

            {"audit_min_level", get_level_safe(persisted, audit.min_level_str())},
            {"audit_min_level_runtime", audit.min_level_str()},
            {"allowed", json::array({"SECURITY","ADMIN","INFO","DEBUG"})},

            {"audit_retention", retention},
            {"audit_rotation", rotation},   // <-- ADD THIS

            {"audit_active_path", audit_jsonl_path},
            {"audit_active_bytes", active_bytes}
        }.dump());

            return;

        } catch (const std::exception& e) {
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "exception while saving settings"},
                {"detail", e.what()}
            }.dump());
            return;
        }
    });

	// GET /api/v4/me  (returns role + decoded fingerprint)
	srv.Get("/api/v4/me", [&](const httplib::Request& req, httplib::Response& res) {
    	auto audit_ua = [&]() -> std::string {
	        auto it = req.headers.find("User-Agent");
        	return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    	};

    	auto audit_fail = [&](const std::string& reason) {
	        pqnas::AuditEvent ev;
        	ev.event = "v4.me_fail";
    	    ev.outcome = "fail";
	        ev.f["reason"] = reason;

    	    auto it_cf = req.headers.find("CF-Connecting-IP");
	        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

    	    auto it_xff = req.headers.find("X-Forwarded-For");
	        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

    	    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
	        ev.f["ua"] = audit_ua();
        	maybe_auto_rotate_before_append();
    	    audit_append(ev);
	    };

	    auto audit_ok = [&](const std::string& fp_b64, long exp, const std::string& role) {
        	pqnas::AuditEvent ev;
    	    ev.event = "v4.me_ok";
	        ev.outcome = "ok";
        	ev.f["fingerprint_b64"] = pqnas::shorten(fp_b64, 120);
    	    ev.f["exp"] = std::to_string(exp);
	        ev.f["role"] = role;

        	ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

    	    auto it_cf = req.headers.find("CF-Connecting-IP");
	        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        	auto it_xff = req.headers.find("X-Forwarded-For");
    	    if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

	        ev.f["ua"] = audit_ua();
        	maybe_auto_rotate_before_append();
    	    audit_append(ev);
	    };

    	auto it = req.headers.find("Cookie");
    	if (it == req.headers.end()) {
	        audit_fail("missing_cookie_header");
        	reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing cookie"}}).dump());
    	    return;
	    }

    	const std::string& hdr = it->second;
    	const std::string k = "pqnas_session=";
    	auto pos = hdr.find(k);
    	if (pos == std::string::npos) {
		    audit_fail("missing_pqnas_session");
        	reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing pqnas_session"}}).dump());
    	    return;
	    }
    	pos += k.size();
    	auto end = hdr.find(';', pos);
	    std::string cookieVal = hdr.substr(pos, (end == std::string::npos) ? std::string::npos : (end - pos));

    	std::string fp_b64;
    	long exp = 0;
    	if (!session_cookie_verify(COOKIE_KEY, cookieVal, fp_b64, exp)) {
    	    audit_fail("cookie_verify_failed");
	        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","invalid session"}}).dump());
        	return;
    	}

    	long now = pqnas::now_epoch();
    	if (now > exp) {
    	    audit_fail("session_expired");
	        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","session expired"}}).dump());
        	return;
    	}

    	// Decode cookie identity: cookie stores standard base64 of UTF-8 fingerprint hex string
	    std::string fp_hex;
    	{
    	    std::string raw;
	        if (!b64std_decode_to_bytes(fp_b64, raw)) {
            	audit_fail("fingerprint_b64_decode_failed");
        	    reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","invalid session"}}).dump());
    	        return;
	        }
        	fp_hex.assign(raw.begin(), raw.end());
    	}

    	// Policy check (fail-closed)
	    const bool is_admin = users.is_admin_enabled(fp_hex);
	   	const bool is_user  = users.is_enabled_user(fp_hex) || is_admin;

    	if (!is_user) {
    	    audit_fail("policy_denied");
	        reply_json(res, 403, json({{"ok",false},{"error","forbidden"},{"message","policy denied"}}).dump());
        	return;
    	}

    	const std::string role = is_admin ? "admin" : "user";
    	audit_ok(fp_b64, exp, role);

    	// Include storage status + profile metadata (if present)
    	std::string storage_state = "unallocated";
	    std::uint64_t quota_bytes = 0;
    	std::string root_rel;
	    std::string group;
    	if (auto u = users.get(fp_hex); u.has_value()) {
    	    if (!u->storage_state.empty()) storage_state = u->storage_state;
	        quota_bytes = u->quota_bytes;
        	root_rel = u->root_rel;
    	    group = u->group;
	    }

    	reply_json(res, 200, json({
    	    {"ok",true},
	        {"exp",exp},
        	{"fingerprint_b64",fp_b64},
    	    {"fingerprint_hex",fp_hex},
	        {"role", role},

        	{"storage_state", storage_state},
    	    {"quota_bytes", quota_bytes},
	        {"root_rel", root_rel},
        	{"group", group}
    	}).dump());
	});


    auto session_handler = [&](const httplib::Request& req, httplib::Response& res) {
        long issued_at  = pqnas::now_epoch();
        long expires_at = issued_at + REQ_TTL;

        std::string sid   = random_b64url(18);
        std::string chal  = random_b64url(32);
        std::string nonce = random_b64url(16);

        std::string payload  = build_req_payload_canonical(sid, chal, nonce, issued_at, expires_at);
        std::string st_token = sign_req_token(payload);

        std::string qr_uri =
            "dna://auth?v=4&st=" + url_encode(st_token) +
            "&origin=" + url_encode(ORIGIN) +
            "&app=" + url_encode(APP_NAME);

        json out = {
            {"v", 4},
            {"sid", sid},
            {"expires_at", expires_at},
            {"st", st_token},
            {"req", st_token},
            {"qr_uri", qr_uri}
        };

        {
            pqnas::AuditEvent ev;
            ev.event = "v4.session_issued";
            ev.outcome = "ok";
            ev.f["sid"] = sid;
            ev.f["issued_at"] = std::to_string(issued_at);
            ev.f["expires_at"] = std::to_string(expires_at);
            ev.f["origin"] = ORIGIN;
            ev.f["app"] = APP_NAME;
            ev.f["client_ip"] = client_ip(req);
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it = req.headers.find("User-Agent");
            ev.f["ua"] = pqnas::shorten(it == req.headers.end() ? "" : it->second);
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }

        reply_json(res, 200, out.dump());
    };

    srv.Get("/api/v4/session", session_handler);
    srv.Post("/api/v4/session", session_handler);

    // GET /api/v4/qr.svg?st=...
    srv.Get("/api/v4/qr.svg", [&](const httplib::Request& req, httplib::Response& res) {
        auto it = req.params.find("st");
        if (it == req.params.end() || it->second.empty()) {
            res.status = 400;
            res.set_header("Content-Type", "application/json");
            res.body = json({{"ok", false}, {"error", "bad_request"}, {"message", "missing st"}}).dump();
            return;
        }

        const std::string st = it->second;

        const std::string qr_uri =
            "dna://auth?v=4&st=" + url_encode(st) +
            "&origin=" + url_encode(ORIGIN) +
            "&app=" + url_encode(APP_NAME);

        try {
            const std::string svg = qr_svg_from_text(qr_uri, 6, 4);
            res.status = 200;
            res.set_header("Content-Type", "image/svg+xml; charset=utf-8");
            res.set_header("Cache-Control", "no-store");
            res.body = svg;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_header("Content-Type", "application/json");
            res.body = json({{"ok", false}, {"error", "server_error"}, {"message", e.what()}}).dump();
        }
    });

    // POST /api/v4/verify
    srv.Post("/api/v4/verify", [&](const httplib::Request& req, httplib::Response& res) {
        auto fail = [&](int code, const std::string& msg, const std::string& detail = "") {
            json out = {
                {"ok", false},
                {"error", (code == 400 ? "bad_request" : "not_authorized")},
                {"message", msg}
            };
            if (!detail.empty()) out["detail"] = detail;
            reply_json(res, code, out.dump());
        };

        // --- audit context (filled after verify_v4_json) ---
        std::string audit_sid;
        std::string audit_st_hash_b64;
        std::string audit_origin;
        std::string audit_rp_id_hash;
        std::string audit_fp;

        auto audit_ua = [&]() -> std::string {
            auto it = req.headers.find("User-Agent");
            return pqnas::shorten(it == req.headers.end() ? "" : it->second);
        };

        auto audit_fail = [&](const std::string& reason, const std::string& detail = "") {
            pqnas::AuditEvent ev;
            ev.event = "v4.verify_fail";
            ev.outcome = "fail";
            if (!audit_sid.empty()) ev.f["sid"] = audit_sid;
            if (!audit_st_hash_b64.empty()) ev.f["st_hash_b64"] = audit_st_hash_b64;
            if (!audit_origin.empty()) ev.f["origin"] = audit_origin;
            if (!audit_rp_id_hash.empty()) ev.f["rp_id_hash"] = audit_rp_id_hash;
            if (!audit_fp.empty()) ev.f["fingerprint"] = audit_fp;
            ev.f["reason"] = reason;
            if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

            ev.f["ua"] = audit_ua();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        };

        auto audit_info = [&](const std::string& event, const std::string& outcome,
                              const std::string& reason = "", const std::string& detail = "") {
            pqnas::AuditEvent ev;
            ev.event = event;
            ev.outcome = outcome;
            if (!audit_sid.empty()) ev.f["sid"] = audit_sid;
            if (!audit_st_hash_b64.empty()) ev.f["st_hash_b64"] = audit_st_hash_b64;
            if (!audit_origin.empty()) ev.f["origin"] = audit_origin;
            if (!audit_rp_id_hash.empty()) ev.f["rp_id_hash"] = audit_rp_id_hash;
            if (!audit_fp.empty()) ev.f["fingerprint"] = audit_fp;

            if (!reason.empty()) ev.f["reason"] = reason;
            if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

            ev.f["ua"] = audit_ua();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        };

        // ISO UTC helper (avoid relying on a missing pqnas::now_iso_utc())
        auto now_iso_utc = [&]() -> std::string {
            using namespace std::chrono;
            auto now = system_clock::now();
            auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

            std::time_t t = system_clock::to_time_t(now);
            std::tm tm{};
            gmtime_r(&t, &tm);

            char buf[64];
            std::snprintf(buf, sizeof(buf),
                          "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                          tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                          tm.tm_hour, tm.tm_min, tm.tm_sec,
                          (int)ms.count());
            return std::string(buf);
        };

        try {
            // ---- v4 shared verification (crypto + bindings) ----
            pqnas::VerifyV4Config cfg;
            cfg.now_unix_sec = 0;
            cfg.expected_origin = ORIGIN;
            cfg.expected_rp_id  = RP_ID;

            // Let crypto/bindings verify first; enforce users registry after we know who it is.
            cfg.enforce_allowlist = false;

            std::array<unsigned char, 32> server_pk{};
            std::memcpy(server_pk.data(), SERVER_PK, 32);

            auto vr = pqnas::verify_v4_json(req.body, server_pk, cfg);

            audit_sid         = vr.sid;
            audit_origin      = vr.origin;
            audit_rp_id_hash  = vr.rp_id_hash;
            audit_st_hash_b64 = vr.st_hash_b64;
            audit_fp          = vr.fingerprint_hex;

            if (!vr.ok) {
                int http = 400;
                switch (vr.rc) {
                    case pqnas::VerifyV4Rc::ST_EXPIRED:
                        http = 410;
                        break;
                    case pqnas::VerifyV4Rc::RP_ID_HASH_MISMATCH:
                    case pqnas::VerifyV4Rc::FINGERPRINT_MISMATCH:
                    case pqnas::VerifyV4Rc::PQ_SIG_INVALID:
                        http = 403;
                        break;
                    case pqnas::VerifyV4Rc::POLICY_DENY:
                        http = 403;
                        break;
                    default:
                        http = 400;
                        break;
                }

                audit_fail(std::string("v4_shared_rc_") + std::to_string((int)vr.rc), vr.detail);

                if (http == 410) return fail(410, "st expired");
                return fail(http, "verify failed", vr.detail);
            }

            const bool vectors_mode = (std::getenv("PQNAS_V4_VECTORS") != nullptr);
            const long at_ttl = vectors_mode ? (10L * 365 * 24 * 3600) : 60L;
            long now = pqnas::now_epoch();

            const std::string& st_hash     = vr.st_hash_b64;
            const std::string& computed_fp = vr.fingerprint_hex;

            // ---- Users registry policy (fail-closed) ----
            const std::string now_iso = now_iso_utc();

            // Unknown user: create disabled record, persist, mark as pending, deny.
            if (!users.exists(computed_fp)) {
                const bool created = users.ensure_present_disabled_user(computed_fp, now_iso);
                const bool saved   = created ? users.save(users_path) : false;

                audit_info("v4.user_auto_created_disabled", "ok",
                           created ? "created" : "already_exists_race",
                           saved ? "" : "users_save_failed");

                // Mark this sid as pending admin approval so /api/v4/status can surface it
                {
                    PendingEntry p;
                    p.expires_at = now + 120; // keep in sync with approvals TTL window
                    pending_put(vr.sid, p);
                }

                return fail(403, "user disabled");
            }

            // Known user must be enabled (role user/admin is fine; status must be enabled)
            if (!users.is_enabled_user(computed_fp)) {
                audit_info("v4.user_disabled", "fail", "not_enabled");

                // Mark this sid as pending admin approval so browser can show wait-approval UX
                {
                    PendingEntry p;
                    p.expires_at = now + 120; // keep in sync with approvals TTL window
                    pending_put(vr.sid, p);
                }

                return fail(403, "user disabled");
            }

            // Update last_seen on successful verify (best-effort persist)
            const bool touched = users.touch_last_seen(computed_fp, now_iso);
            const bool saved   = touched ? users.save(users_path) : false;

            if (touched && saved) {
                audit_info("v4.user_last_seen_updated", "ok");
            } else if (touched && !saved) {
                audit_info("v4.user_last_seen_updated", "fail", "users_save_failed");
            } else {
                audit_info("v4.user_last_seen_updated", "fail", "touch_failed");
            }

            // ---- vectors logging ----
            if (vectors_mode) {
                std::cerr << "[v4_vectors] FP_HEX " << computed_fp
                          << " SID " << vr.sid
                          << " ST_HASH " << st_hash
                          << "\n";
                std::cerr << "[v4_vectors] CANON_SHA256_B64 " << vr.canonical_sha256_b64 << "\n";
            }

            // ---- mint AT (short-lived) ----
            json at_payload = {
                {"v",4},
                {"typ","at"},
                {"sid", vr.sid},
                {"st_hash", st_hash},
                {"rp_id_hash", vr.rp_id_hash},
                {"fingerprint", computed_fp},
                {"issued_at", now},
                {"expires_at", now + at_ttl}
            };
            std::string at = sign_token_v4_ed25519(at_payload, SERVER_SK);

            if (vectors_mode) {
                std::cerr << "[v4_vectors] AT_ISSUED " << at << "\n";
            }

            // ---- mint browser session cookie (stored for /consume) ----
            std::string cookieVal;
            long sess_iat = now;
            long sess_exp = now + SESS_TTL;

            // Cookie embeds fingerprint as standard base64 of UTF-8 fingerprint hex string
            std::string fp_b64 = pqnas::b64_std(
                reinterpret_cast<const unsigned char*>(computed_fp.data()),
                computed_fp.size()
            );

            if (session_cookie_mint(COOKIE_KEY, fp_b64, sess_iat, sess_exp, cookieVal)) {
                ApprovalEntry e;
                e.cookie_val  = cookieVal;
                e.fingerprint = computed_fp;
                e.expires_at  = now + 120;
                approvals_put(vr.sid, e);

                {
                    pqnas::AuditEvent ev;
                    ev.event = "v4.cookie_minted";
                    ev.outcome = "ok";
                    ev.f["sid"] = vr.sid;
                    ev.f["st_hash_b64"] = st_hash;
                    ev.f["rp_id_hash"] = vr.rp_id_hash;
                    ev.f["fingerprint"] = computed_fp;
                    ev.f["sess_iat"] = std::to_string(sess_iat);
                    ev.f["sess_exp"] = std::to_string(sess_exp);

                    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

                    auto it_cf = req.headers.find("CF-Connecting-IP");
                    if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

                    auto it_xff = req.headers.find("X-Forwarded-For");
                    if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

                    ev.f["ua"] = audit_ua();
                    maybe_auto_rotate_before_append();
                    audit_append(ev);
                }
            } else {
                audit_fail("cookie_mint_failed");
            }

            // ---- verify ok audit ----
            {
                pqnas::AuditEvent ev;
                ev.event = "v4.verify_ok";
                ev.outcome = "ok";
                ev.f["sid"] = vr.sid;
                ev.f["st_hash_b64"] = st_hash;
                ev.f["origin"] = vr.origin;
                ev.f["rp_id_hash"] = vr.rp_id_hash;
                ev.f["fingerprint"] = computed_fp;

                ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

                auto it_cf = req.headers.find("CF-Connecting-IP");
                if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

                auto it_xff = req.headers.find("X-Forwarded-For");
                if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

                ev.f["ua"] = audit_ua();
                maybe_auto_rotate_before_append();
                audit_append(ev);
            }

            json out = {{"ok",true},{"v",4},{"at",at}};
            reply_json(res, 200, out.dump());
        }
        catch (const std::exception& e) {
            audit_fail("exception", e.what());
            return fail(400, "exception", e.what());
        }
    });

    // GET /wait-approval (static UI)
    srv.Get("/wait-approval", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_WAIT_APPROVAL_HTML);
        if (body.empty()) { res.status = 404; res.set_content("missing wait_approval.html","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "text/html; charset=utf-8");
    });

    // GET /static/wait_approval.js
    srv.Get("/static/wait_approval.js", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_WAIT_APPROVAL_JS);
        if (body.empty()) { res.status = 404; res.set_content("missing wait_approval.js","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "application/javascript; charset=utf-8");
    });

    srv.Get("/admin/users", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        const std::string body = slurp_file(STATIC_USERS_HTML);
        if (body.empty()) { res.status = 404; res.set_content("missing admin_users.html","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "text/html; charset=utf-8");
    });

    srv.Get("/static/admin_users.js", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_USERS_JS);
        if (body.empty()) { res.status = 404; res.set_content("missing admin_users.js","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "application/javascript; charset=utf-8");
    });

	srv.Get("/static/admin_badges.js", [&](const httplib::Request&, httplib::Response& res) {
    	const std::string body = slurp_file(STATIC_BADGES_JS);
    	if (body.empty()) { res.status = 404; res.set_content("missing admin_badges.js","text/plain"); return; }
    	res.set_header("Cache-Control", "no-store");
	    res.set_content(body, "application/javascript; charset=utf-8");
	});

    srv.Get("/api/v4/admin/users", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        res.set_header("Cache-Control", "no-store");

        json out;
        out["ok"] = true;
	    out["actor_fp"] = actor_fp;
        out["users"] = json::array();

        for (auto& kv : users.snapshot()) {
            auto& u = kv.second;
			out["users"].push_back({
    			{"fingerprint", u.fingerprint},
    			{"name", u.name},
    			{"role", u.role},
    			{"status", u.status},
    			{"added_at", u.added_at},
    			{"last_seen", u.last_seen},
			    {"notes", u.notes},

    			// New: profile
    			{"group", u.group},
    			{"email", u.email},
    			{"address", u.address},

    			// New: storage metadata
    			{"storage_state", u.storage_state},
			    {"quota_bytes", u.quota_bytes},
    			{"root_rel", u.root_rel},
    			{"storage_set_at", u.storage_set_at},
			    {"storage_set_by", u.storage_set_by}
			});

        }

        reply_json(res, 200, out.dump());
    });

	srv.Get("/admin/approvals", [&](const httplib::Request& req, httplib::Response& res) {
   		std::string actor_fp;
    	if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

    	const std::string body = slurp_file(STATIC_APPROVALS_HTML);
    	if (body.empty()) { res.status = 404; res.set_content("missing admin_approvals.html","text/plain"); return; }
    	res.set_header("Cache-Control", "no-store");
    	res.set_content(body, "text/html; charset=utf-8");
	});

	srv.Get("/static/admin_approvals.js", [&](const httplib::Request&, httplib::Response& res) {
    	const std::string body = slurp_file(STATIC_APPROVALS_JS);
	    if (body.empty()) { res.status = 404; res.set_content("missing admin_approvals.js","text/plain"); return; }
    	res.set_header("Cache-Control", "no-store");
	    res.set_content(body, "application/javascript; charset=utf-8");
	});

    auto now_iso_utc = []() -> std::string {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
        gmtime_r(&t, &tm);

        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec,
                      (int)ms.count());
        return std::string(buf);
    };

    // POST /api/v4/admin/users/status
    // Body: {"fingerprint":"...","status":"enabled|disabled|revoked"}
	srv.Post("/api/v4/admin/users/status", [&](const httplib::Request& req, httplib::Response& res) {
    	std::string actor_fp;
	    if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

    	json j;
    	try { j = json::parse(req.body); }
	    catch (...) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
        	return;
    	}

    	const std::string fp     = j.value("fingerprint", "");
	    const std::string status = j.value("status", "");

	    if (fp.empty()) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
    	    return;
	    }

    	if (status != "enabled" && status != "disabled" && status != "revoked") {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid status"}}).dump());
        	return;
    	}

    	// Prevent admin self-lockout: do not allow disabling/revoking your own fingerprint.
    	if (fp == actor_fp && status != "enabled") {
	        {
    	        pqnas::AuditEvent ev;
	            ev.event = "admin.self_lockout_blocked";
        	    ev.outcome = "fail";
    	        ev.f["action"] = "status";
	            ev.f["fingerprint"] = fp;
        	    ev.f["requested_status"] = status;
    	        ev.f["ts"] = now_iso_utc();
	            ev.f["actor_fp"] = actor_fp;
            	ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	    maybe_auto_rotate_before_append();
    	        audit_append(ev);
	        }

        	reply_json(res, 400, json({
        	    {"ok",false},
    	        {"error","bad_request"},
	            {"message","refusing to change your own status (prevents admin lockout)"}
        	}).dump());
    	    return;
	    }

    	if (!users.exists(fp)) {
        	reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","user not found"}}).dump());
	        return;
    	}

    	const bool ok_set  = users.set_status(fp, status);
    	const bool ok_save = ok_set ? users.save(users_path) : false;

    	{
	        pqnas::AuditEvent ev;
        	ev.event = "admin.user_status_set";
    	    ev.outcome = (ok_set && ok_save) ? "ok" : "fail";
	        ev.f["fingerprint"] = fp;
        	ev.f["status"] = status;
    	    ev.f["ts"] = now_iso_utc();
	        ev.f["actor_fp"] = actor_fp;
        	ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
    	    maybe_auto_rotate_before_append();
	        audit_append(ev);
    	}

	    if (!ok_set) {
        	reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","set_status failed"}}).dump());
    	    return;
	    }
    	if (!ok_save) {
	        reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
        	return;
    	}

    	reply_json(res, 200, json({{"ok",true}}).dump());
	});


	// POST /api/v4/admin/users/storage
	// Body: {"fingerprint":"...","quota_gb":10}
	// Action (metadata-only for now):
	//   - storage_state="allocated"
	//   - quota_bytes = quota_gb * 1024^3
	//   - root_rel = "users/<full fingerprint>"
	//   - storage_set_at = now ISO
	//   - storage_set_by = actor_fp
srv.Post("/api/v4/admin/users/storage", [&](const httplib::Request& req, httplib::Response& res) {
    	std::string actor_fp;
    	if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

    	json j;
    	try { j = json::parse(req.body); }
	    catch (...) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
        	return;
    	}

    	const std::string fp = j.value("fingerprint", "");
    	if (fp.empty()) {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
        	return;
    	}

    	if (!users.exists(fp)) {
        	reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","user not found"}}).dump());
        	return;
    	}

    	const bool force = j.value("force", false);

    	// quota_gb: accept integer or float; require >= 0
    	double quota_gb_d = 0.0;
    	try {
    	    if (j.contains("quota_gb")) {
	            const auto& v = j["quota_gb"];
            	if (v.is_number_integer()) quota_gb_d = (double)v.get<long long>();
        	    else if (v.is_number_unsigned()) quota_gb_d = (double)v.get<unsigned long long>();
    	        else if (v.is_number_float()) quota_gb_d = v.get<double>();
	            else {
            	    reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","quota_gb must be a number"}}).dump());
        	        return;
    	        }
	        } else {
            	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing quota_gb"}}).dump());
            	return;
        	}
    	} catch (...) {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid quota_gb"}}).dump());
        	return;
    	}

    	if (quota_gb_d < 0.0) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","quota_gb must be >= 0"}}).dump());
    	    return;
	    }

    	// Convert GB -> bytes using GiB (1024^3). Round to nearest byte.
    	// Also guard overflow into uint64_t.
    	const long double bytes_ld =
    	    (long double)quota_gb_d *
	        (long double)1024.0L * (long double)1024.0L * (long double)1024.0L;

    	if (bytes_ld > (long double)std::numeric_limits<std::uint64_t>::max()) {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","quota_gb too large"}}).dump());
        	return;
    	}
    	const std::uint64_t quota_bytes = (std::uint64_t)(bytes_ld + 0.5L);

    	const std::string now_iso = now_iso_utc();

    	// Load, modify, upsert (registry has no dedicated setters for these fields yet)
    	auto cur = users.get(fp);
	    if (!cur.has_value()) {
        	// Should not happen because exists(fp) checked, but fail closed.
        	reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","user lookup failed"}}).dump());
    	    return;
	    }

	    pqnas::UserRec u = *cur;

    	const std::string prev_state = u.storage_state;
    	const std::uint64_t prev_quota = u.quota_bytes;
	    const std::string prev_root = u.root_rel;

    	const bool already_allocated = (u.storage_state == "allocated");

    	if (already_allocated && !force) {
    	    {
	            pqnas::AuditEvent ev;
        	    ev.event = "admin.user_storage_allocate_refused";
    	        ev.outcome = "fail";
	            ev.f["fingerprint"] = fp;
        	    ev.f["reason"] = "already_allocated";
    	        ev.f["ts"] = now_iso;
	            ev.f["actor_fp"] = actor_fp;
            	ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	    maybe_auto_rotate_before_append();
    	        audit_append(ev);
	        }

        	reply_json(res, 409, json({
        	    {"ok", false},
    	        {"error", "already_allocated"},
	            {"message", "storage is already allocated; use force=true to change quota"},
            	{"storage_state", u.storage_state},
        	    {"quota_bytes", u.quota_bytes},
    	        {"root_rel", u.root_rel}
	        }).dump());
        	return;
    	}

    	u.storage_state = "allocated";
    	u.quota_bytes = quota_bytes;
	    u.root_rel = std::string("users/") + fp; // Option A: full fingerprint
    	u.storage_set_at = now_iso;
	    u.storage_set_by = actor_fp;

    	const bool ok_upsert = users.upsert(u);
	    const bool ok_save   = ok_upsert ? users.save(users_path) : false;

    	{
	        pqnas::AuditEvent ev;
        	ev.event = already_allocated ? "admin.user_storage_updated" : "admin.user_storage_allocated";
    	    ev.outcome = (ok_upsert && ok_save) ? "ok" : "fail";
	        ev.f["fingerprint"] = fp;
        	ev.f["ts"] = now_iso;
    	    ev.f["actor_fp"] = actor_fp;
	        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        	// Details (all metadata)
    	    ev.f["quota_gb"] = pqnas::shorten(std::to_string(quota_gb_d), 32);
	        ev.f["quota_bytes"] = pqnas::shorten(std::to_string((unsigned long long)quota_bytes), 32);
        	ev.f["root_rel"] = pqnas::shorten(u.root_rel, 160);
    	    if (force) ev.f["force"] = "true";

	        // previous values (useful for audits)
        	if (!prev_state.empty()) ev.f["prev_storage_state"] = pqnas::shorten(prev_state, 40);
    	    if (prev_quota != 0) ev.f["prev_quota_bytes"] = pqnas::shorten(std::to_string((unsigned long long)prev_quota), 32);
	        if (!prev_root.empty()) ev.f["prev_root_rel"] = pqnas::shorten(prev_root, 160);

        	maybe_auto_rotate_before_append();
    	    audit_append(ev);
	    }

    	if (!ok_upsert) {
        	reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","upsert failed"}}).dump());
        	return;
    	}
	    if (!ok_save) {
        	reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
    	    return;
	    }

	    reply_json(res, 200, json({
        	{"ok", true},
    	    {"fingerprint", fp},
	        {"storage_state", u.storage_state},
        	{"quota_bytes", u.quota_bytes},
    	    {"root_rel", u.root_rel},
	        {"storage_set_at", u.storage_set_at},
        	{"storage_set_by", u.storage_set_by}
    	}).dump());
	});


    // GET /system (static UI) - visible to user + admin (cookie required)
    srv.Get("/system", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, role;
        if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &actor_fp, &role)) return;

        std::string body;
        if (!read_file_to_string(STATIC_SYSTEM_HTML, body) || body.empty()) {
            res.status = 500;
            res.set_header("Content-Type", "text/plain");
            res.body = "Missing static file: " + STATIC_SYSTEM_HTML;
            return;
        }

        res.status = 200;
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.body = body;
    });

    // POST /api/v4/admin/users/upsert
    // Body: {"fingerprint":"...","name":"...","role":"user|admin","notes":"..."}
    srv.Post("/api/v4/admin/users/upsert", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        json j;
        try { j = json::parse(req.body); }
        catch (...) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
            return;
        }

        const std::string fp    = j.value("fingerprint", "");
        const std::string name  = j.value("name", "");
        const std::string role  = j.value("role", "user");
        const std::string notes = j.value("notes", "");

        if (fp.empty()) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
            return;
        }

        const std::string now_iso = now_iso_utc();

        // Preserve added_at/last_seen/status if user exists; otherwise create disabled by default.
        pqnas::UserRec u{};
        bool existed = false;

        if (auto cur = users.get(fp); cur.has_value()) {
            existed = true;
            u = *cur;
        } else {
            u.fingerprint = fp;
            u.added_at = now_iso;
            u.last_seen = "";
            u.status = "disabled"; // default fail-closed for manual add, admin can Enable
            u.role = "user";
            u.name = "";
            u.notes = "";
        }

        // Apply fields from request
        u.name  = name;
        u.notes = notes;
        u.role  = role;  // normalized inside upsert()

        const bool ok_upsert = users.upsert(u);
        const bool ok_save   = ok_upsert ? users.save(users_path) : false;

        {
            pqnas::AuditEvent ev;
            ev.event = "admin.user_upsert";
            ev.outcome = (ok_upsert && ok_save) ? "ok" : "fail";
            ev.f["fingerprint"] = fp;
            ev.f["existed"] = existed ? "true" : "false";
            ev.f["role"] = role;
            if (!name.empty()) ev.f["name"] = pqnas::shorten(name, 80);
            if (!notes.empty()) ev.f["notes"] = pqnas::shorten(notes, 120);
            ev.f["ts"] = now_iso;
            ev.f["actor_fp"] = actor_fp;
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }

        if (!ok_upsert) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","upsert failed"}}).dump());
            return;
        }
        if (!ok_save) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
            return;
        }

        reply_json(res, 200, json({{"ok",true}}).dump());
    });

    // POST /api/v4/admin/users/enable   {"fingerprint":"...","role":"user|admin"?,"name":"..."?,"notes":"..."?}
    srv.Post("/api/v4/admin/users/enable", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        json j;
        try { j = json::parse(req.body); }
        catch (...) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
            return;
        }

        const std::string fp    = j.value("fingerprint", "");
        const std::string role  = j.value("role", "user");
        const std::string name  = j.value("name", "");
        const std::string notes = j.value("notes", "");

        if (fp.empty()) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
            return;
        }
        if (!users.exists(fp)) {
            reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","user not found"}}).dump());
            return;
        }

        if (!users.set_status(fp, "enabled")) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","set_status failed"}}).dump());
            return;
        }

        // optional updates
        users.set_role(fp, role);
        if (!name.empty() || !notes.empty()) users.set_name_notes(fp, name, notes);

        const bool saved = users.save(users_path);

        {
            pqnas::AuditEvent ev;
            ev.event = "admin.user_enabled";
            ev.outcome = saved ? "ok" : "fail";
            ev.f["fingerprint"] = fp;
            ev.f["role"] = role;
            ev.f["ts"] = now_iso_utc();
            ev.f["actor_fp"] = actor_fp;

            if (!name.empty()) ev.f["name"] = pqnas::shorten(name, 80);
            if (!notes.empty()) ev.f["notes"] = pqnas::shorten(notes, 120);
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }

        if (!saved) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
            return;
        }

        reply_json(res, 200, json({{"ok",true}}).dump());
    });

    // POST /api/v4/admin/users/disable  {"fingerprint":"..."}
    srv.Post("/api/v4/admin/users/disable", [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

        json j;
        try { j = json::parse(req.body); }
        catch (...) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
            return;
        }

        const std::string fp = j.value("fingerprint", "");
        if (fp.empty()) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
            return;
        }
        if (!users.exists(fp)) {
            reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","user not found"}}).dump());
            return;
        }

        if (!users.set_status(fp, "disabled")) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","set_status failed"}}).dump());
            return;
        }

        const bool saved = users.save(users_path);

        {
            pqnas::AuditEvent ev;
            ev.event = "admin.user_disabled";
            ev.outcome = saved ? "ok" : "fail";
            ev.f["fingerprint"] = fp;
            ev.f["ts"] = now_iso_utc();
            ev.f["actor_fp"] = actor_fp;
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }

        if (!saved) {
            reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
            return;
        }

        reply_json(res, 200, json({{"ok",true}}).dump());
    });

    srv.Get("/api/v4/debug/approvals", [&](const httplib::Request&, httplib::Response& res) {
        json out;
        out["ok"] = true;
        out["count"] = 0;
        out["items"] = json::array();

        long now = pqnas::now_epoch();

        {
            std::lock_guard<std::mutex> lk(g_approvals_mu);
            out["count"] = (int)g_approvals.size();
            for (const auto& kv : g_approvals) {
                const auto& sid = kv.first;
                const auto& e = kv.second;
                out["items"].push_back({
                    {"sid", sid},
                    {"sid_len", (int)sid.size()},
                    {"expires_at", e.expires_at},
                    {"now", now},
                    {"ttl_left", (e.expires_at > now) ? (e.expires_at - now) : 0},
                    {"fingerprint", e.fingerprint}
                });
            }
        }

        reply_json(res, 200, out.dump());
    });

    // POST /api/v4/admin/users/delete
    // Body: {"fingerprint":"..."}
	srv.Post("/api/v4/admin/users/delete", [&](const httplib::Request& req, httplib::Response& res) {
    	std::string actor_fp;
	    if (!require_admin_cookie_users_actor(req, res, COOKIE_KEY, users_path, &users, &actor_fp)) return;

    	json j;
    	try { j = json::parse(req.body); }
    	catch (...) {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"}}).dump());
        	return;
    	}

    	const std::string fp = j.value("fingerprint", "");
	    if (fp.empty()) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing fingerprint"}}).dump());
    	    return;
	    }

    	// Prevent admin self-lockout: do not allow deleting your own identity entry.
    	if (fp == actor_fp) {
	        {
        	    pqnas::AuditEvent ev;
    	        ev.event = "admin.self_lockout_blocked";
	            ev.outcome = "fail";
            	ev.f["action"] = "delete";
        	    ev.f["fingerprint"] = fp;
    	        ev.f["ts"] = now_iso_utc();
	            ev.f["actor_fp"] = actor_fp;
            	ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	    maybe_auto_rotate_before_append();
    	        audit_append(ev);
	        }

        	reply_json(res, 400, json({
    	        {"ok",false},
	            {"error","bad_request"},
            	{"message","refusing to delete your own admin entry (prevents lockout)"}
        	}).dump());
    	    return;
	    }

	    if (!users.exists(fp)) {
        	reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","user not found"}}).dump());
    	    return;
	    }

    	// Safety: refuse deleting an enabled admin identity (keeps system recoverable)
	    if (users.is_admin_enabled(fp)) {
        	reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","refusing to delete an enabled admin"}}).dump());
    	    return;
	    }

    	const bool ok_del  = users.erase(fp);
    	const bool ok_save = ok_del ? users.save(users_path) : false;

    	{
	        pqnas::AuditEvent ev;
        	ev.event = "admin.user_deleted";
    	    ev.outcome = (ok_del && ok_save) ? "ok" : "fail";
	        ev.f["fingerprint"] = fp;
        	ev.f["ts"] = now_iso_utc();
    	    ev.f["actor_fp"] = actor_fp;
	        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	maybe_auto_rotate_before_append();
    	    audit_append(ev);
	    }

    	if (!ok_del) {
	        reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","delete failed"}}).dump());
        	return;
    	}
	    if (!ok_save) {
        	reply_json(res, 500, json({{"ok",false},{"error","server_error"},{"message","users save failed"}}).dump());
    	    return;
	    }

    	reply_json(res, 200, json({{"ok",true}}).dump());
	});

    std::cerr << "PQ-NAS server listening on 0.0.0.0:" << LISTEN_PORT << std::endl;
    srv.listen("0.0.0.0", LISTEN_PORT);
    return 0;
}
