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
#include <chrono>
#include <cstdio>
#include <sys/wait.h>

#include "pqnas_util.h"
#include "authz.h"
#include "session_cookie.h"
#include "policy.h"

// header-only HTTP server
#include "httplib.h"
#include "allowlist.h"
#include "v4_verify_shared.h"
#include "users_registry.h"
#include "storage_info.h"
#include "user_quota.h"

//sharing
#include "share_links.h"

//apps
#include "static_serve.h"

#include "system_metrics.h"
// JSON (header-only)
#include <nlohmann/json.hpp>

#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>


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
const std::string STATIC_ADMIN_APPS_HTML =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_apps.html").string();

const std::string STATIC_ADMIN_APPS_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/admin_apps.js").string();
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

const std::string APPS_DIR =
    (std::filesystem::path(REPO_ROOT) / "apps").string();

const std::string APPS_BUNDLED_DIR =
    (std::filesystem::path(REPO_ROOT) / "apps/bundled").string();

const std::string APPS_INSTALLED_DIR =
    (std::filesystem::path(REPO_ROOT) / "apps/installed").string();

const std::string APPS_USERS_DIR =
    (std::filesystem::path(REPO_ROOT) / "apps/users").string();

const std::string STATIC_THEME_CSS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/theme.css").string();
const std::string STATIC_THEME_JS =
    (std::filesystem::path(REPO_ROOT) / "server/src/static/theme.js").string();




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

// ===================== User storage filesystem (Phase 1A) =====================

// Root where PQ-NAS stores user data on disk (real filesystem).
// Default: <exe_dir()>/data  (self-contained next to binary).
static std::string data_root_dir() {
    std::string root = exe_dir() + "/data";
    if (const char* p = std::getenv("PQNAS_DATA_ROOT")) {
        if (*p) root = p;
    }
    return root;
}

static bool is_hex_lower_or_upper(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

#include <filesystem>

// Reject absolute paths and ".." traversal. Also reject empty.
static bool is_safe_rel_path(const std::string& rel) {
    if (rel.empty()) return false;
    std::filesystem::path p(rel);
    if (p.is_absolute()) return false;

    for (const auto& part : p) {
        const std::string s = part.string();
        if (s == "..") return false;
    }
    return true;
}

// Best-effort recursive size; skips symlinks; ignores errors.
static unsigned long long dir_size_bytes_best_effort(const std::filesystem::path& root) {
    std::error_code ec;

    if (!std::filesystem::exists(root, ec) || ec) return 0;
    if (!std::filesystem::is_directory(root, ec) || ec) return 0;

    unsigned long long total = 0;

    auto it = std::filesystem::recursive_directory_iterator(
        root,
        std::filesystem::directory_options::skip_permission_denied,
        ec
    );

    for (auto end = std::filesystem::recursive_directory_iterator(); it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }

        std::error_code ec2;
        const auto st = it->symlink_status(ec2);
        if (ec2) continue;

        // skip symlinks entirely
        if (std::filesystem::is_symlink(st)) continue;

        if (std::filesystem::is_regular_file(st)) {
            std::error_code ec3;
            const auto sz = std::filesystem::file_size(it->path(), ec3);
            if (!ec3) total += (unsigned long long)sz;
        }
    }

    return total;
}


// Conservative validation: fingerprint must be hex, reasonable length.
static bool is_valid_fingerprint_hex(const std::string& fp) {
    if (fp.size() < 16) return false;
    if (fp.size() > 256) return false;
    for (char c : fp) {
        if (!is_hex_lower_or_upper(c)) return false;
    }
    return true;
}

// Ensure a directory exists (mkdir -p behavior). Returns true if exists/created.
static bool ensure_dir_exists(const std::filesystem::path& p, std::string* err = nullptr) {
    try {
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            if (ec) {
                if (err) *err = "exists() error: " + ec.message();
                return false;
            }
            if (!std::filesystem::is_directory(p, ec) || ec) {
                if (err) *err = "path exists but is not directory";
                return false;
            }
            return true;
        }

        if (!std::filesystem::create_directories(p, ec) || ec) {
            if (err) *err = "create_directories failed: " + ec.message();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        if (err) *err = std::string("exception: ") + e.what();
        return false;
    } catch (...) {
        if (err) *err = "unknown exception";
        return false;
    }
}

// Computes absolute user directory path for a fingerprint.
static std::filesystem::path user_dir_for_fp(const std::string& fp_hex) {
    // Canonical-ish layout: <data_root>/users/<fingerprint_hex>
    return std::filesystem::path(data_root_dir()) / "users" / fp_hex;
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

static std::string rel_to_repo(const std::string& abs) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path p = fs::weakly_canonical(fs::path(abs), ec);
    fs::path r = fs::weakly_canonical(fs::path(REPO_ROOT), ec);
    if (ec) return abs;

    auto ps = p.string();
    auto rs = r.string();
    if (ps.size() >= rs.size() && ps.compare(0, rs.size(), rs) == 0) {
        if (ps.size() == rs.size()) return ".";
        if (ps[rs.size()] == '/') return ps.substr(rs.size() + 1);
    }
    return abs; // fallback
}


static bool serve_file_under_root(const std::string& root_dir,
                                  const std::string& rel,
                                  const std::string& content_type,
                                  httplib::Response& res,
                                  bool no_store = true) {
    namespace fs = std::filesystem;

    // Build full path then canonicalize.
    std::error_code ec;
    fs::path root = fs::weakly_canonical(fs::path(root_dir), ec);
    if (ec) {
        res.status = 500;
        res.set_content("static root unavailable", "text/plain; charset=utf-8");
        return false;
    }

    fs::path full = fs::weakly_canonical(root / rel, ec);
    if (ec) {
        res.status = 404;
        res.set_content("not found", "text/plain; charset=utf-8");
        return false;
    }

    // Enforce: full must be under root
    auto root_s = root.string();
    auto full_s = full.string();
    if (full_s.size() < root_s.size() ||
        full_s.compare(0, root_s.size(), root_s) != 0 ||
        (full_s.size() > root_s.size() && full_s[root_s.size()] != '/')) {
        res.status = 403;
        res.set_content("forbidden", "text/plain; charset=utf-8");
        return false;
        }

    // Only serve regular files
    if (!fs::is_regular_file(full, ec) || ec) {
        res.status = 404;
        res.set_content("not found", "text/plain; charset=utf-8");
        return false;
    }

    const std::string body = slurp_file(full_s);
    if (body.empty()) {
        res.status = 404;
        res.set_content("not found", "text/plain; charset=utf-8");
        return false;
    }

    res.set_header("X-Content-Type-Options", "nosniff");
    if (no_store) res.set_header("Cache-Control", "no-store");
    res.set_content(body, content_type);
    return true;
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


// Small helper: bytes -> hex
static std::string hex_encode_lower(const unsigned char* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[i * 2 + 0] = kHex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[(data[i] >> 0) & 0xF];
    }
    return out;
}

#include <cstdint>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>

// ----------------------------- ZIP streaming (store, no compression) ----------
// We create a ZIP with local headers + data descriptors + central directory.
// No external libs required. CRC32 is computed per-file while streaming.
//
// Limitations:
// - Uses ZIP32 fields (no Zip64). Good for typical sizes; if you need >4GiB single file
//   or very large archives, we can extend to Zip64 later.
// ------------------------------------------------------------------------------

namespace {

static inline void zip_u16(std::string& out, std::uint16_t v) {
    out.push_back((char)(v & 0xff));
    out.push_back((char)((v >> 8) & 0xff));
}
static inline void zip_u32(std::string& out, std::uint32_t v) {
    out.push_back((char)(v & 0xff));
    out.push_back((char)((v >> 8) & 0xff));
    out.push_back((char)((v >> 16) & 0xff));
    out.push_back((char)((v >> 24) & 0xff));
}

static std::uint32_t crc32_update(std::uint32_t crc, const unsigned char* data, size_t len) {
    static std::uint32_t table[256];
    static bool inited = false;
    if (!inited) {
        for (std::uint32_t i = 0; i < 256; i++) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        inited = true;
    }
    crc = crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

static inline std::string zip_sanitize_relpath(std::string p) {
    // ZIP paths use forward slashes and must not be absolute.
    for (auto& ch : p) if (ch == '\\') ch = '/';
    while (!p.empty() && p.front() == '/') p.erase(p.begin());
    // Remove any empty segments.
    while (p.find("//") != std::string::npos) p = std::string(p).replace(p.find("//"), 2, "/");
    return p;
}

static inline std::string zip_basename(const std::filesystem::path& p) {
    auto s = p.filename().string();
    if (s.empty()) s = "folder";
    return s;
}

static inline void zip_dos_time_date(std::filesystem::file_time_type ft, std::uint16_t& dos_time, std::uint16_t& dos_date) {
    // Best-effort conversion.
    // DOS date starts at 1980-01-01.
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(ft - std::filesystem::file_time_type::clock::now()
                                                       + system_clock::now());
    std::time_t tt = system_clock::to_time_t(sctp);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    int year = tm.tm_year + 1900;
    if (year < 1980) year = 1980;
    int mon = tm.tm_mon + 1;
    int day = tm.tm_mday;
    int hour = tm.tm_hour;
    int min = tm.tm_min;
    int sec = tm.tm_sec;

    dos_time = (std::uint16_t)(((hour & 31) << 11) | ((min & 63) << 5) | ((sec / 2) & 31));
    dos_date = (std::uint16_t)((((year - 1980) & 127) << 9) | ((mon & 15) << 5) | (day & 31));
}

struct ZipFileItem {
    std::filesystem::path abs_path; // full path on disk
    std::string zip_name;           // relative name inside zip (forward slashes)
    std::uint64_t size_u64 = 0;     // file size
    std::uint16_t dos_time = 0;
    std::uint16_t dos_date = 0;

    // Filled during streaming:
    std::uint32_t crc32 = 0;
    std::uint32_t size32 = 0;
    std::uint32_t local_header_off = 0;
};

struct ZipTotals {
    std::uint64_t total_bytes = 0;
    std::uint64_t central_dir_bytes = 0;
    std::uint64_t central_dir_off = 0;
};

// Compute exact archive size for "store + data descriptor".
static ZipTotals zip_compute_totals(const std::vector<ZipFileItem>& items) {
    ZipTotals t{};
    std::uint64_t off = 0;

    // Local file header layout:
    // 30 bytes fixed + filename + extra
    // file data
    // data descriptor 16 bytes (signature + crc + csize + usize)
    for (const auto& it : items) {
        off += 30;
        off += it.zip_name.size();
        off += 0; // extra
        off += it.size_u64;
        off += 16; // data descriptor (we include signature)
    }

    t.central_dir_off = off;

    // Central dir file header:
    // 46 bytes fixed + filename + extra + comment
    std::uint64_t cd = 0;
    for (const auto& it : items) {
        cd += 46;
        cd += it.zip_name.size();
        cd += 0; // extra
        cd += 0; // comment
    }

    // End of central dir: 22 bytes + comment(0)
    cd += 22;

    t.central_dir_bytes = cd;
    t.total_bytes = off + cd;
    return t;
}

// Streaming state machine that emits the full ZIP in-order.
class ZipStreamer {
public:
    ZipStreamer(std::vector<ZipFileItem> items, ZipTotals totals)
        : items_(std::move(items)), totals_(totals) {}

    std::uint64_t total_size() const { return totals_.total_bytes; }

    // Called by httplib content provider; must emit sequential bytes.
    bool emit(size_t offset, size_t max_len, httplib::DataSink& sink) {
        if (finished_) return false;
        if (offset != (size_t)cur_off_) {
            // httplib usually calls sequentially. If not, fail safe.
            return false;
        }

        size_t remaining = max_len;
        while (remaining > 0 && !finished_) {
            // Drain pending buffer first
            if (buf_pos_ < buf_.size()) {
                size_t n = std::min(remaining, buf_.size() - buf_pos_);
                sink.write(buf_.data() + buf_pos_, n);
                buf_pos_ += n;
                cur_off_ += n;
                remaining -= n;
                continue;
            }

            // Buffer empty; produce next chunk based on stage
            buf_.clear();
            buf_pos_ = 0;

            if (stage_ == Stage::LocalHeader) {
                if (idx_ >= items_.size()) {
                    stage_ = Stage::CentralDir;
                    continue;
                }
                auto& it = items_[idx_];
                it.local_header_off = (std::uint32_t)cur_off_; // zip32 offset
                make_local_header(it);
                stage_ = Stage::FileData;
                open_file(it);
                continue;
            }

            if (stage_ == Stage::FileData) {
                auto& it = items_[idx_];
                if (!fp_.is_open()) {
                    // nothing to read -> write descriptor
                    make_data_descriptor(it);
                    stage_ = Stage::NextFile;
                    continue;
                }

                // Read a chunk from file directly into sink (avoids extra copies)
                const size_t chunk = std::min<size_t>(remaining, 64 * 1024);
                tmp_.resize(chunk);

                fp_.read(tmp_.data(), (std::streamsize)chunk);
                std::streamsize got = fp_.gcount();
                if (got > 0) {
                    // update CRC
                    it.crc32 = crc32_update(it.crc32, (const unsigned char*)tmp_.data(), (size_t)got);
                    sink.write(tmp_.data(), (size_t)got);
                    cur_off_ += (size_t)got;
                    remaining -= (size_t)got;
                    continue;
                }

                // EOF
                fp_.close();
                // finalize sizes for central dir
                it.size32 = (std::uint32_t)std::min<std::uint64_t>(it.size_u64, 0xFFFFFFFFu);
                make_data_descriptor(it);
                stage_ = Stage::NextFile;
                continue;
            }

            if (stage_ == Stage::NextFile) {
                idx_++;
                stage_ = Stage::LocalHeader;
                continue;
            }

            if (stage_ == Stage::CentralDir) {
                if (!central_built_) {
                    build_central_directory();
                    central_built_ = true;
                }
                if (central_pos_ < central_.size()) {
                    // serve central dir bytes in chunks via buf_
                    const size_t n = std::min(remaining, central_.size() - central_pos_);
                    sink.write(central_.data() + central_pos_, n);
                    central_pos_ += n;
                    cur_off_ += n;
                    remaining -= n;
                    continue;
                }
                finished_ = true;
                break;
            }
        }

        return !finished_;
    }

    const std::vector<ZipFileItem>& items() const { return items_; }

private:
    enum class Stage { LocalHeader, FileData, NextFile, CentralDir };

    void make_local_header(const ZipFileItem& it) {
        // Local file header signature 0x04034b50
        zip_u32(buf_, 0x04034b50u);
        zip_u16(buf_, 20);             // version needed
        zip_u16(buf_, 0x0008u);        // general purpose bit flag: bit3 => data descriptor
        zip_u16(buf_, 0);              // compression method 0=store
        zip_u16(buf_, it.dos_time);
        zip_u16(buf_, it.dos_date);
        zip_u32(buf_, 0);              // crc32 (0 for now, in descriptor)
        zip_u32(buf_, 0);              // compressed size (0 for now)
        zip_u32(buf_, 0);              // uncompressed size (0 for now)
        zip_u16(buf_, (std::uint16_t)it.zip_name.size());
        zip_u16(buf_, 0);              // extra length
        buf_ += it.zip_name;           // filename bytes
    }

    void make_data_descriptor(const ZipFileItem& it) {
        // Data descriptor signature 0x08074b50 + crc + csize + usize
        zip_u32(buf_, 0x08074b50u);
        zip_u32(buf_, it.crc32);
        // store => compressed size == uncompressed size
        std::uint32_t sz = (std::uint32_t)std::min<std::uint64_t>(it.size_u64, 0xFFFFFFFFu);
        zip_u32(buf_, sz);
        zip_u32(buf_, sz);
    }

    void build_central_directory() {
        central_.clear();
        central_.reserve((size_t)totals_.central_dir_bytes);

        const std::uint32_t cd_start = (std::uint32_t)totals_.central_dir_off;
        std::uint32_t cd_size = 0;

        for (const auto& it : items_) {
            // Central directory header signature 0x02014b50
            zip_u32(central_, 0x02014b50u);
            zip_u16(central_, 0x031Eu);   // version made by (arbitrary)
            zip_u16(central_, 20);        // version needed
            zip_u16(central_, 0x0008u);   // flags: data descriptor used
            zip_u16(central_, 0);         // method: store
            zip_u16(central_, it.dos_time);
            zip_u16(central_, it.dos_date);
            zip_u32(central_, it.crc32);
            std::uint32_t sz = (std::uint32_t)std::min<std::uint64_t>(it.size_u64, 0xFFFFFFFFu);
            zip_u32(central_, sz);        // compressed
            zip_u32(central_, sz);        // uncompressed
            zip_u16(central_, (std::uint16_t)it.zip_name.size());
            zip_u16(central_, 0);         // extra len
            zip_u16(central_, 0);         // comment len
            zip_u16(central_, 0);         // disk number
            zip_u16(central_, 0);         // internal attrs
            zip_u32(central_, 0);         // external attrs
            zip_u32(central_, it.local_header_off);
            central_ += it.zip_name;

            cd_size += (std::uint32_t)(46 + it.zip_name.size());
        }

        // End of central directory record signature 0x06054b50
        zip_u32(central_, 0x06054b50u);
        zip_u16(central_, 0); // disk
        zip_u16(central_, 0); // disk start
        zip_u16(central_, (std::uint16_t)items_.size());
        zip_u16(central_, (std::uint16_t)items_.size());
        zip_u32(central_, cd_size);
        zip_u32(central_, cd_start);
        zip_u16(central_, 0); // comment len
    }

    void open_file(const ZipFileItem& it) {
        fp_.open(it.abs_path, std::ios::binary);
        // If open fails, we still proceed; read will yield 0 and descriptor will be written.
    }

private:
    std::vector<ZipFileItem> items_;
    ZipTotals totals_;

    Stage stage_ = Stage::LocalHeader;
    size_t idx_ = 0;

    std::ifstream fp_;
    std::string buf_;
    size_t buf_pos_ = 0;

    std::string central_;
    size_t central_pos_ = 0;
    bool central_built_ = false;

    std::vector<char> tmp_;

    std::uint64_t cur_off_ = 0;
    bool finished_ = false;
};

} // namespace

// Stream SHA-256 for a file. Returns false + err on failure.
static bool sha256_file(const std::filesystem::path& p, std::string* out_hex, std::string* err) {
    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    // ensure free on all exits
    struct CtxGuard {
        EVP_MD_CTX* c;
        ~CtxGuard() { if (c) EVP_MD_CTX_free(c); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return false;
    }

    std::array<char, 64 * 1024> buf{};
    while (f.good()) {
        f.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize n = f.gcount();
        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), (size_t)n) != 1) {
                if (err) *err = "EVP_DigestUpdate failed";
                return false;
            }
        }
    }
    if (!f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return false;
    }

    if (out_hex) *out_hex = hex_encode_lower(md, (size_t)md_len);
    return true;
}

static bool run_cmd_capture(const std::string& cmd, std::string* out, int* exit_code) {
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return false;
    std::string s;
    char buf[4096];
    while (true) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0) break;
        s.append(buf, n);
    }
    int rc = pclose(fp);
    if (out) *out = s;
    if (exit_code) *exit_code = WEXITSTATUS(rc);
    return true;
}

static std::string rand_hex_16() {
    static const char* k = "0123456789abcdef";
    std::array<unsigned char, 8> b{};
    randombytes_buf(b.data(), b.size());
    std::string s;
    s.reserve(16);
    for (unsigned char c : b) { s.push_back(k[c >> 4]); s.push_back(k[c & 0x0f]); }
    return s;
}

static bool safe_app_id(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (char c : s) {
        if (!(std::isalnum((unsigned char)c) || c=='_' || c=='-' || c=='.')) return false;
    }
    return true;
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
                audit.append(ev);
            } catch (...) {}

            return true;
        } catch (...) {
            return false;
        }
    };


// the actual policy check: call this before audit.append(ev)
// Uses admin_settings.json schema from /api/v4/admin/settings:
//   audit_rotation: { mode: manual|daily|size_mb|daily_or_size_mb, max_active_mb: int, rotate_utc_day: string }
auto maybe_auto_rotate_before_append = [&]() {
    json settings = load_admin_settings_cached(admin_settings_path);

    json rot = json::object();
    if (settings.contains("audit_rotation") && settings["audit_rotation"].is_object()) {
        rot = settings["audit_rotation"];
    }

    const std::string mode = rot.value("mode", "manual");
    const int max_mb = rot.value("max_active_mb", 256);

    // manual => never auto-rotate
    if (mode == "manual") return;

    static std::string last_rotated_day = utc_day_yyyymmdd_local();

    // daily trigger (UTC day change)
    if (mode == "daily" || mode == "daily_or_size_mb") {
        const std::string today = utc_day_yyyymmdd_local();
        if (today != last_rotated_day) {
            if (rotate_audit_now_internal("daily")) {
                last_rotated_day = today;
                return;
            }
        }
    }

    // size trigger
    if (mode == "size_mb" || mode == "daily_or_size_mb") {
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

	//Load shared files
    pqnas::ShareRegistry shares((std::filesystem::path(REPO_ROOT) / "config" / "shares.json").string());
    { std::string err; if (!shares.load(&err)) std::cerr << "[shares] WARNING: " << err << "\n"; }

    httplib::Server srv;

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

    const std::filesystem::path base = std::filesystem::path(REPO_ROOT) / "server/src/static";
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

    // Serve installed apps (system scope) at: /apps/<appId>/<version>/...
    // Example: /apps/filemgr/1.0.0/www/index.html
    srv.Get(R"(/apps/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(.*))",
            [&](const httplib::Request& req, httplib::Response& res) {
        const std::string appId = req.matches[1];
        const std::string ver   = req.matches[2];
        const std::string tail  = req.matches[3];

        // Root dir for this app version
        const std::string root =
            (std::filesystem::path(APPS_INSTALLED_DIR) / appId / ver).string();

        // Basic content-type mapping (extend later)
        auto guess_ct = [&](const std::string& p) -> std::string {
            if (p.size() >= 5 && p.substr(p.size()-5) == ".html") return "text/html; charset=utf-8";
            if (p.size() >= 3 && p.substr(p.size()-3) == ".js")   return "application/javascript; charset=utf-8";
            if (p.size() >= 4 && p.substr(p.size()-4) == ".css")  return "text/css; charset=utf-8";
            if (p.size() >= 4 && p.substr(p.size()-4) == ".png")  return "image/png";
            if (p.size() >= 4 && p.substr(p.size()-4) == ".svg")  return "image/svg+xml";
            if (p.size() >= 4 && p.substr(p.size()-4) == ".jpg")  return "image/jpeg";
            if (p.size() >= 5 && p.substr(p.size()-5) == ".jpeg") return "image/jpeg";
            if (p.size() >= 4 && p.substr(p.size()-4) == ".webp") return "image/webp";
            return "application/octet-stream";
        };

        serve_file_under_root(root, tail, guess_ct(tail), res, /*no_store=*/true);
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

    srv.Get("/api/v4/apps", [&](const httplib::Request& req, httplib::Response& res) {
    namespace fs = std::filesystem;
    json out;
    out["ok"] = true;
    out["bundled"] = json::array();
    out["installed"] = json::array();
    const bool isAdmin = is_admin_cookie(req, COOKIE_KEY, &allowlist);

    // Bundled: apps/bundled/<id>/*.zip
        // Bundled: apps/bundled/<id>/*.zip (admin-only visibility)
        if (isAdmin) {
            std::error_code ec;
            fs::path bundled(APPS_BUNDLED_DIR);
            if (fs::exists(bundled, ec) && fs::is_directory(bundled, ec)) {
                for (auto& de : fs::directory_iterator(bundled, ec)) {
                    if (ec) break;
                    if (!de.is_directory(ec) || ec) continue;

                    const std::string appId = de.path().filename().string();
                    for (auto& f : fs::directory_iterator(de.path(), ec)) {
                        if (ec) break;
                        if (!f.is_regular_file(ec) || ec) continue;
                        if (f.path().extension() != ".zip") continue;

                        json item;
                        item["id"] = appId;
                        item["zip"] = rel_to_repo(f.path().string());
                        out["bundled"].push_back(item);
                    }
                }
            }
        }


    // Installed: apps/installed/<id>/<ver>/manifest.json (or at least www/index.html)
    {
        std::error_code ec;
        fs::path installed(APPS_INSTALLED_DIR);
        if (fs::exists(installed, ec) && fs::is_directory(installed, ec)) {
            for (auto& deApp : fs::directory_iterator(installed, ec)) {
                if (ec) break;
                if (!deApp.is_directory(ec) || ec) continue;

                const std::string appId = deApp.path().filename().string();

                for (auto& deVer : fs::directory_iterator(deApp.path(), ec)) {
                    if (ec) break;
                    if (!deVer.is_directory(ec) || ec) continue;

                    const std::string ver = deVer.path().filename().string();
                    fs::path root = deVer.path();

                    // detect entry (prefer manifest, else default)
                    fs::path manifest = root / "manifest.json";
                    fs::path defaultEntry = root / "www" / "index.html";

                    if (!fs::exists(manifest, ec) && !fs::exists(defaultEntry, ec)) {
                        continue; // not a valid install dir
                    }

                    json item;
                    item["id"] = appId;
                    item["version"] = ver;
                    item["root"] = rel_to_repo(root.string());
                    item["has_manifest"] = fs::exists(manifest, ec);
                    out["installed"].push_back(item);
                }
            }
        }
    }

    res.set_header("Cache-Control", "no-store");
    res.set_content(out.dump(2), "application/json; charset=utf-8");
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
/*
    srv.Get("/app", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_APP_HTML);
        if (body.empty()) {
            res.status = 404;
            res.set_content("missing app.html", "text/plain");
            return;
        }
        res.set_content(body, "text/html; charset=utf-8");
    });
*/
    srv.Get("/app", [&](const httplib::Request&, httplib::Response& res) {
        const std::string body = slurp_file(STATIC_APP_HTML);
        if (body.empty()) { res.status = 404; res.set_content("missing app.html","text/plain"); return; }
        res.set_header("Cache-Control", "no-store");
        res.set_header("X-Content-Type-Options", "nosniff");
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

		// SAFE accessor for audit_min_level (never throws)
		auto get_level_safe = [&](const json& j, const std::string& fallback) -> std::string {
    		auto it2 = j.find("audit_min_level");
    		if (it2 != j.end() && it2->is_string()) return it2->get<std::string>();
    		return fallback;
		};

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

		// default theme
		std::string ui_theme = "dark";
		if (persisted.contains("ui_theme") && persisted["ui_theme"].is_string()) {
    		ui_theme = persisted["ui_theme"].get<std::string>();
		}
		if (!(ui_theme == "dark" || ui_theme == "bright" || ui_theme == "cpunk_orange" || ui_theme == "win_classic"))
		    ui_theme = "dark";




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

    		{"audit_min_level", get_level_safe(persisted, audit.min_level_str())},
    		{"audit_min_level_runtime", audit.min_level_str()},
    		{"allowed", json::array({"SECURITY","ADMIN","INFO","DEBUG"})},

    		{"audit_retention", retention},
    		{"audit_rotation", rotation},

    		{"audit_active_path", audit_jsonl_path},
    		{"audit_active_bytes", active_bytes},

    		{"ui_theme", ui_theme}
		}.dump());


    });

 // Admin settings API
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

    auto is_allowed_rotation_mode = [&](const std::string& m) -> bool {
        return (m == "manual" || m == "daily" || m == "size_mb" || m == "daily_or_size_mb");
    };

	auto is_allowed_theme = [&](const std::string& t) -> bool {
    return (t == "dark" || t == "bright" || t == "cpunk_orange" || t == "win_classic");
	};

    // SAFE accessor for audit_min_level (never throws)
    auto get_level_safe = [&](const json& j, const std::string& fallback) -> std::string {
        auto it2 = j.find("audit_min_level");
        if (it2 != j.end() && it2->is_string()) return it2->get<std::string>();
        return fallback;
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

        std::string before_theme = "dark";
        if (persisted.contains("ui_theme") && persisted["ui_theme"].is_string()) {
            before_theme = persisted["ui_theme"].get<std::string>();
        }
        if (!is_allowed_theme(before_theme)) before_theme = "dark";

        bool changed_level    = false;
        bool changed_ret      = false;
        bool changed_rotation = false;
        bool changed_theme    = false;

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

		// ---- ui_theme (optional) ----
		if (in.contains("ui_theme")) {
    		if (!in["ui_theme"].is_string()) {
        		reply_json(res, 400, json{
            		{"ok", false},
            		{"error", "bad_request"},
            		{"message", "ui_theme must be string"}
        		}.dump());
        		return;
    		}

    		std::string t = in["ui_theme"].get<std::string>();

    		if (!is_allowed_theme(t)) {
        		reply_json(res, 400, json{
            		{"ok", false},
            		{"error", "bad_request"},
            		{"message", "invalid ui_theme (allowed: dark, bright, cpunk_orange, win_classic)"}
        		}.dump());
        		return;
    		}

    		patch["ui_theme"] = t;
    		persisted["ui_theme"] = t;
    		changed_theme = true;

    		// Audit (best-effort)
    		try {
        		pqnas::AuditEvent ev;
        		ev.event = "admin.settings_changed";
        		ev.outcome = "ok";
        		ev.f["ui_theme_after"] = t;
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

        if (!changed_level && !changed_ret && !changed_rotation && !changed_theme) {
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "nothing to update (provide audit_min_level and/or audit_retention and/or audit_rotation and/or ui_theme)"}
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

        // ---- ui_theme in response ----
        std::string ui_theme_value = "dark";
        if (persisted.contains("ui_theme") && persisted["ui_theme"].is_string()) {
            ui_theme_value = persisted["ui_theme"].get<std::string>();
        }
        if (!is_allowed_theme(ui_theme_value)) ui_theme_value = "dark";

        const long long active_bytes = file_size_bytes_safe(audit_jsonl_path);

        reply_json(res, 200, json{
            {"ok", true},

            {"audit_min_level", get_level_safe(persisted, audit.min_level_str())},
            {"audit_min_level_runtime", audit.min_level_str()},
            {"allowed", json::array({"SECURITY","ADMIN","INFO","DEBUG"})},

            {"audit_retention", retention},
            {"audit_rotation", rotation},

            {"audit_active_path", audit_jsonl_path},
            {"audit_active_bytes", active_bytes},

            {"ui_theme", ui_theme_value}
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

    srv.Get("/admin/apps", [&](const httplib::Request& req, httplib::Response& res) {
    if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

    std::string body;
    if (!read_file_to_string(STATIC_ADMIN_APPS_HTML, body)) {
        res.status = 404;
        res.body = "Missing static file: " + STATIC_ADMIN_APPS_HTML;
        return;
    }

    res.set_header("Cache-Control", "no-store");
    res.set_content(body, "text/html; charset=utf-8");
    });

    srv.Get("/static/admin_apps.js", [&](const httplib::Request&, httplib::Response& res) {
        std::string body;
        if (!read_file_to_string(STATIC_ADMIN_APPS_JS, body)) {
            res.status = 404;
            res.body = "Missing static file: " + STATIC_ADMIN_APPS_JS;
            return;
        }

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

	srv.Get("/static/theme.css", [&](const httplib::Request&, httplib::Response& res) {
    std::string body;
    if (!read_file_to_string(STATIC_THEME_CSS, body)) {
        res.status = 404;
        res.body = "Missing static file: " + STATIC_THEME_CSS;
        return;
    }
    res.set_header("Cache-Control", "no-store");
    res.set_content(body, "text/css; charset=utf-8");
	});

	srv.Get("/static/theme.js", [&](const httplib::Request&, httplib::Response& res) {
    std::string body;
    if (!read_file_to_string(STATIC_THEME_JS, body)) {
        res.status = 404;
        res.body = "Missing static file: " + STATIC_THEME_JS;
        return;
    }
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

   			// storage usage (best-effort)
   			unsigned long long used_bytes = 0;
		    if (u.storage_state == "allocated" && !u.root_rel.empty() && is_safe_rel_path(u.root_rel)) {
		        std::filesystem::path abs = std::filesystem::path(data_root_dir()) / std::filesystem::path(u.root_rel);
       			used_bytes = dir_size_bytes_best_effort(abs);
   			}

		    out["users"].push_back({
		        {"fingerprint", u.fingerprint},
		        {"name", u.name},
		        {"role", u.role},
		        {"status", u.status},
		        {"added_at", u.added_at},
		        {"last_seen", u.last_seen},
        		{"notes", u.notes},

		        // profile
		        {"group", u.group},
		        {"email", u.email},
		        {"address", u.address},

		        // storage metadata
		        {"storage_state", u.storage_state},
		        {"quota_bytes", u.quota_bytes},
		        {"root_rel", u.root_rel},
		        {"storage_set_at", u.storage_set_at},
		        {"storage_set_by", u.storage_set_by},

		        // NEW: storage usage
        		{"storage_used_bytes", used_bytes}
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

    	// NEW: sanity check fingerprint format (hex-ish + reasonable length)
    	if (!is_valid_fingerprint_hex(fp)) {
	        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid fingerprint format"}}).dump());
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

    	// NEW: create/verify real filesystem directory BEFORE marking allocated
	    const std::filesystem::path udir = user_dir_for_fp(fp);

    	// Ensure <data_root>/users exists
	    {
        	std::string fs_err;
    	    const std::filesystem::path parent = udir.parent_path();
	        if (!ensure_dir_exists(parent, &fs_err)) {
        	    // Audit (best-effort)
    	        try {
	                pqnas::AuditEvent ev;
                	ev.event = "admin.user_storage_mkdir_failed";
            	    ev.outcome = "fail";
        	        ev.f["fingerprint"] = fp;
    	            ev.f["path"] = parent.string();
	                ev.f["detail"] = pqnas::shorten(fs_err, 180);
                	ev.f["ts"] = now_iso;
            	    ev.f["actor_fp"] = actor_fp;
        	        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
    	            maybe_auto_rotate_before_append();
	                audit_append(ev);
            	} catch (...) {}

            	reply_json(res, 500, json({
        	        {"ok", false},
    	            {"error", "server_error"},
	                {"message", "failed to create storage root"},
                	{"detail", fs_err}
            	}).dump());
        	    return;
    	    }
	    }

    	// Ensure <data_root>/users/<fp> exists
    	{
    	    std::string fs_err;
	        if (!ensure_dir_exists(udir, &fs_err)) {
            	// Audit (best-effort)
        	    try {
    	            pqnas::AuditEvent ev;
	                ev.event = "admin.user_storage_mkdir_failed";
                	ev.outcome = "fail";
            	    ev.f["fingerprint"] = fp;
        	        ev.f["path"] = udir.string();
    	            ev.f["detail"] = pqnas::shorten(fs_err, 180);
	                ev.f["ts"] = now_iso;
                	ev.f["actor_fp"] = actor_fp;
            	    ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	        maybe_auto_rotate_before_append();
	                audit_append(ev);
    	        } catch (...) {}

	            reply_json(res, 500, json({
                	{"ok", false},
            	    {"error", "server_error"},
        	        {"message", "failed to create user directory"},
    	            {"detail", fs_err}
	            }).dump());
            	return;
        	}
    	}

    	// Audit mkdir success (best-effort)
    	try {
    	    pqnas::AuditEvent ev;
	        ev.event = already_allocated ? "admin.user_storage_dir_verified" : "admin.user_storage_dir_created";
        	ev.outcome = "ok";
    	    ev.f["fingerprint"] = fp;
	        ev.f["path"] = udir.string();
        	ev.f["ts"] = now_iso;
    	    ev.f["actor_fp"] = actor_fp;
	        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        	maybe_auto_rotate_before_append();
    	    audit_append(ev);
	    } catch (...) {}

    	u.storage_state = "allocated";
    	u.quota_bytes = quota_bytes;
	    u.root_rel = std::string("users/") + fp; // Option A: full fingerprint
    	// NOTE: root_rel is relative to PQNAS_DATA_ROOT. Do not accept from client.
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

    	    // New: what directory was ensured
	        ev.f["user_dir"] = pqnas::shorten(udir.string(), 200);

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
	        {"storage_set_by", u.storage_set_by},

    	    // New: resolved absolute path for convenience (admin UI can show it)
	        {"user_dir", udir.string()},
        	{"data_root", data_root_dir()}
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

// GET /api/v4/system/storage  (used by /system page)
srv.Get("/api/v4/system/storage", [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &actor_fp, &role)) return;

    const std::string data_root = data_root_dir();

    pqnas::StorageInfo si;
    std::string err;
    pqnas::get_storage_info(data_root, &si, &err);

    json out;
    out["ok"] = true;

    out["data_root"] = si.root;
    out["fstype"] = si.fstype;
    out["mountpoint"] = si.mountpoint;
    out["source"] = si.source;
    out["options"] = si.options;
    out["prjquota_enabled"] = si.prjquota_enabled;

    out["note"] = si.prjquota_enabled
        ? "Project quotas appear enabled (prjquota/pquota)."
        : "Project quotas not detected in mount options.";

    if (!err.empty())
        out["warning"] = err;

    reply_json(res, 200, out.dump());
});

    // ---- Files API (user storage) ----
// POST /api/v4/files/move?from=old/path&to=new/path
srv.Post("/api/v4/files/move", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& from_rel = "", const std::string& to_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_move_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!from_rel.empty()) ev.f["from"] = pqnas::shorten(from_rel, 200);
        if (!to_rel.empty())   ev.f["to"]   = pqnas::shorten(to_rel, 200);
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


    auto audit_ok = [&](const std::string& from_rel,
                        const std::string& to_rel,
                        const std::string& type,
                        std::uint64_t bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_move_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["from"] = pqnas::shorten(from_rel, 200);
        ev.f["to"]   = pqnas::shorten(to_rel, 200);
        ev.f["type"] = type;
        if (type == "file") ev.f["bytes"] = std::to_string((unsigned long long)bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string from_rel, to_rel;
    if (req.has_param("from")) from_rel = req.get_param_value("from");
    if (req.has_param("to"))   to_rel   = req.get_param_value("to");

    if (from_rel.empty() || to_rel.empty()) {
        audit_fail("missing_from_or_to", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing from or to"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path from_abs, to_abs;
    std::string err1, err2;
    if (!pqnas::resolve_user_path_strict(user_dir, from_rel, &from_abs, &err1)) {
        audit_fail("invalid_from_path", 400, err1, from_rel, to_rel);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid from path"}}.dump());
        return;
    }
    if (!pqnas::resolve_user_path_strict(user_dir, to_rel, &to_abs, &err2)) {
        audit_fail("invalid_to_path", 400, err2, from_rel, to_rel);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid to path"}}.dump());
        return;
    }

    // refuse no-op (helps avoid weird audits)
    if (from_abs == to_abs) {
        audit_fail("same_path", 400, "", from_rel, to_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "from and to are the same"}
        }.dump());
        return;
    }

    // source must exist
    std::error_code ec;
    auto st = std::filesystem::status(from_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", from_rel, to_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "source not found"}
        }.dump());
        return;
    }

    const bool is_dir  = std::filesystem::is_directory(st);
    const bool is_file = std::filesystem::is_regular_file(st);

    // ensure destination parent exists
    ec.clear();
    std::filesystem::create_directories(to_abs.parent_path(), ec);
    if (ec) {
        audit_fail("mkdir_failed", 500, ec.message());
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to create destination directories"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }
    const std::string type = is_dir ? "dir" : (is_file ? "file" : "other");
    std::uint64_t bytes = 0;
    if (is_file) bytes = pqnas::file_size_u64_safe(from_abs);

    // rename/move
    ec.clear();
    std::filesystem::rename(from_abs, to_abs, ec);
    if (ec) {
        audit_fail("rename_failed", 500, ec.message());
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "move failed"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    audit_ok(from_rel, to_rel, type, bytes);

    reply_json(res, 200, json{
        {"ok", true},
        {"from", from_rel},
        {"to", to_rel},
        {"type", type},
        {"bytes", bytes}
    }.dump());

});

// ---- Files API (user storage) ----
// POST /api/v4/files/mkdir?path=relative/dir
srv.Post("/api/v4/files/mkdir", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_mkdir_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_ok = [&](const std::string& rel_path) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_mkdir_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // ---- path param ----
    std::string rel_path;
    if (req.has_param("path"))
        rel_path = req.get_param_value("path");

    if (rel_path.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    // reuse strict resolver
    std::filesystem::path abs;
    std::string path_err;
    if (!pqnas::resolve_user_path_strict(user_dir, rel_path, &abs, &path_err)) {
        audit_fail("invalid_path", 400, path_err);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(abs, ec);
    if (ec) {
        audit_fail("mkdir_failed", 500, ec.message());
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to create directory"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    audit_ok(rel_path);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", rel_path}
    }.dump());
});

    // POST /api/v4/files/hash?path=rel/path&algo=sha256
srv.Post("/api/v4/files/hash", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "", const std::string& algo = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_hash_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!algo.empty())     ev.f["algo"] = pqnas::shorten(algo, 40);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        const std::string& algo,
                        std::uint64_t bytes,
                        const std::string& digest_hex) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_hash_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["algo"] = pqnas::shorten(algo, 40);
        ev.f["bytes"] = std::to_string((unsigned long long)bytes);
        // Don’t store full digest if you want shorter logs; but full is often fine.
        ev.f["digest"] = pqnas::shorten(digest_hex, 80);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    std::string algo = "sha256";
    if (req.has_param("algo")) algo = req.get_param_value("algo");

    // v1: only sha256 supported
    if (algo != "sha256") {
        audit_fail("unsupported_algo", 400, "", path_rel, algo);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "unsupported algo (use sha256)"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel, algo);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // must exist + must be file
    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel, algo);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "file not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_regular_file(st)) {
        audit_fail("not_file", 400, "", path_rel, algo);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "path is not a file"}
        }.dump());
        return;
    }

    const std::uint64_t bytes = pqnas::file_size_u64_safe(path_abs);

    std::string digest_hex, herr;
    if (!sha256_file(path_abs, &digest_hex, &herr)) {
        audit_fail("hash_failed", 500, herr, path_rel, algo);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "hash failed"},
            {"detail", pqnas::shorten(herr, 180)}
        }.dump());
        return;
    }

    audit_ok(path_rel, algo, bytes, digest_hex);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"algo", algo},
        {"bytes", bytes},
        {"digest_hex", digest_hex}
    }.dump());
});

    // POST /api/v4/files/rmdir?path=rel/dir
srv.Post("/api/v4/files/rmdir", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_rmdir_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_rmdir_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "directory not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_directory(st)) {
        audit_fail("not_dir", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "path is not a directory"}
        }.dump());
        return;
    }

    // empty-only v1
    ec.clear();
    bool empty = std::filesystem::is_empty(path_abs, ec);
    if (ec) {
        audit_fail("is_empty_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to check if directory is empty"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }
    if (!empty) {
        audit_fail("not_empty", 409, "", path_rel);
        reply_json(res, 409, json{
            {"ok", false},
            {"error", "not_empty"},
            {"message", "directory is not empty"}
        }.dump());
        return;
    }

    ec.clear();
    std::filesystem::remove(path_abs, ec);
    if (ec) {
        audit_fail("remove_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to remove directory"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    audit_ok(path_rel);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel}
    }.dump());
});


    // POST /api/v4/files/tree?path=rel/path&max=500
srv.Post("/api/v4/files/tree", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "", int max_entries = -1) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_tree_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (max_entries >= 0)  ev.f["max"]  = std::to_string(max_entries);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel, int max_entries,
                        std::uint64_t entries, std::uint64_t files, std::uint64_t dirs, bool truncated) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_tree_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["max"] = std::to_string(max_entries);
        ev.f["entries"] = std::to_string((unsigned long long)entries);
        ev.f["files"] = std::to_string((unsigned long long)files);
        ev.f["dirs"]  = std::to_string((unsigned long long)dirs);
        ev.f["truncated"] = truncated ? "1" : "0";

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) path_rel = "."; // convenience: root of user storage

    int max_entries = 500;
    if (req.has_param("max")) {
        try { max_entries = std::stoi(req.get_param_value("max")); } catch (...) {}
    }
    max_entries = std::max(1, std::min(5000, max_entries));

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel, max_entries);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel, max_entries);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }

    // Helpers for building relative paths under user_dir (for UI)
    auto to_rel_from_user_dir = [&](const std::filesystem::path& abs) -> std::string {
        std::error_code ec3;
        auto rel = std::filesystem::relative(abs, user_dir, ec3);
        if (ec3) return path_rel; // fallback
        return rel.generic_string();
    };

    std::uint64_t entries = 0, files = 0, dirs = 0;
    bool truncated = false;

    // Return shape:
    // node = { name, path, type, bytes?, children? }
    std::function<json(const std::filesystem::path&, const std::filesystem::path&)> build_node;

    build_node = [&](const std::filesystem::path& abs, const std::filesystem::path& name_for_display) -> json {
        json node;
        node["name"] = name_for_display.empty() ? std::string("") : name_for_display.generic_string();
        node["path"] = to_rel_from_user_dir(abs);

        std::error_code ec2;
        auto st2 = std::filesystem::symlink_status(abs, ec2);
        if (ec2) {
            node["type"] = "other";
            return node;
        }

        // Do not follow symlinks: report and stop.
        if (std::filesystem::is_symlink(st2)) {
            node["type"] = "symlink";
            return node;
        }

        if (std::filesystem::is_regular_file(st2)) {
            node["type"] = "file";
            node["bytes"] = pqnas::file_size_u64_safe(abs);
            return node;
        }

        if (std::filesystem::is_directory(st2)) {
            node["type"] = "dir";
            node["children"] = json::array();

            // Stop adding children if we hit max
            if ((int)entries >= max_entries) {
                truncated = true;
                return node;
            }

            // Stable order: name sort
            std::vector<std::filesystem::directory_entry> kids;
            for (auto it = std::filesystem::directory_iterator(abs, std::filesystem::directory_options::skip_permission_denied, ec2);
                 it != std::filesystem::directory_iterator();
                 it.increment(ec2)) {
                if (ec2) break;
                kids.push_back(*it);
            }
            std::sort(kids.begin(), kids.end(), [](const auto& a, const auto& b) {
                return a.path().filename().string() < b.path().filename().string();
            });

            for (auto& de : kids) {
                if ((int)entries >= max_entries) { truncated = true; break; }

                // Count entry (dir or file) when we *include* it
                std::error_code ec4;
                auto stc = de.symlink_status(ec4);
                if (ec4) continue;

                // Skip symlinks entirely (or keep as leaf). Here: keep as leaf.
                // That still doesn't follow them.
                entries++;

                if (std::filesystem::is_symlink(stc)) {
                    node["children"].push_back(json{
                        {"name", de.path().filename().string()},
                        {"path", to_rel_from_user_dir(de.path())},
                        {"type", "symlink"}
                    });
                    continue;
                }

                if (std::filesystem::is_directory(stc)) {
                    dirs++;
                    node["children"].push_back(build_node(de.path(), de.path().filename()));
                    continue;
                }

                if (std::filesystem::is_regular_file(stc)) {
                    files++;
                    node["children"].push_back(json{
                        {"name", de.path().filename().string()},
                        {"path", to_rel_from_user_dir(de.path())},
                        {"type", "file"},
                        {"bytes", pqnas::file_size_u64_safe(de.path())}
                    });
                    continue;
                }

                node["children"].push_back(json{
                    {"name", de.path().filename().string()},
                    {"path", to_rel_from_user_dir(de.path())},
                    {"type", "other"}
                });
            }

            return node;
        }

        node["type"] = "other";
        return node;
    };

    json root;

    // Root node counts
    entries = 1; // root itself
    if (std::filesystem::is_directory(st)) dirs = 1;
    else if (std::filesystem::is_regular_file(st)) files = 1;

    // For root node name: show last component unless "." (use "")
    std::filesystem::path root_name = path_abs.filename();
    if (path_rel == "." || path_rel == "/" || path_rel.empty()) root_name = "";

    root = build_node(path_abs, root_name);

    audit_ok(path_rel, max_entries, entries, files, dirs, truncated);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"max", max_entries},
        {"truncated", truncated},
        {"entries", entries},
        {"files", files},
        {"dirs", dirs},
        {"tree", root}
    }.dump());
});

// POST /api/v4/files/touch?path=rel/file
srv.Post("/api/v4/files/touch", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_touch_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_touch_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["action"] = "created";

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");

    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // Ensure parent exists
    std::error_code ec;
    std::filesystem::create_directories(path_abs.parent_path(), ec);
    if (ec) {
        audit_fail("mkdir_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to create parent directories"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    // Create-only: if exists -> 409
    ec.clear();
    auto st = std::filesystem::status(path_abs, ec);
    if (!ec && std::filesystem::exists(st)) {
        audit_fail("already_exists", 409, "", path_rel);
        reply_json(res, 409, json{
            {"ok", false},
            {"error", "already_exists"},
            {"message", "file already exists"}
        }.dump());
        return;
    }

    // Create empty file
    {
        std::ofstream f(path_abs, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!f.good()) {
            audit_fail("create_failed", 500, "cannot create file", path_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create file"}
            }.dump());
            return;
        }
    }

    audit_ok(path_rel);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"action", "created"}
    }.dump());
});

    // POST /api/v4/files/cat?path=rel/file&max_bytes=65536
srv.Post("/api/v4/files/cat", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "", int max_bytes = -1) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_cat_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (max_bytes >= 0)    ev.f["max_bytes"] = std::to_string(max_bytes);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        int max_bytes,
                        std::uint64_t bytes_total,
                        std::uint64_t bytes_returned,
                        bool truncated) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_cat_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["max_bytes"] = std::to_string(max_bytes);
        ev.f["bytes_total"] = std::to_string((unsigned long long)bytes_total);
        ev.f["bytes_returned"] = std::to_string((unsigned long long)bytes_returned);
        ev.f["truncated"] = truncated ? "1" : "0";

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    int max_bytes = 64 * 1024;
    if (req.has_param("max_bytes")) {
        try { max_bytes = std::stoi(req.get_param_value("max_bytes")); } catch (...) {}
    }
    max_bytes = std::max(1, std::min(1024 * 1024, max_bytes)); // 1..1MiB

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel, max_bytes);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // must exist + must be file
    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel, max_bytes);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "file not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_regular_file(st)) {
        audit_fail("not_file", 400, "", path_rel, max_bytes);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "path is not a file"}
        }.dump());
        return;
    }

    const std::uint64_t bytes_total = pqnas::file_size_u64_safe(path_abs);

    std::ifstream f(path_abs, std::ios::binary);
    if (!f.good()) {
        audit_fail("open_failed", 500, "cannot open file", path_rel, max_bytes);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to open file"}
        }.dump());
        return;
    }

    std::string buf;
    buf.resize((size_t)max_bytes);
    f.read(&buf[0], (std::streamsize)buf.size());
    std::streamsize n = f.gcount();
    if (n < 0) n = 0;
    buf.resize((size_t)n);

    bool truncated = (bytes_total > (std::uint64_t)buf.size());

    // Detect binary-ish content: reject if NUL found in returned bytes
    if (std::find(buf.begin(), buf.end(), '\0') != buf.end()) {
        audit_fail("binary_detected", 415, "", path_rel, max_bytes);
        reply_json(res, 415, json{
            {"ok", false},
            {"error", "unsupported_media_type"},
            {"message", "binary file cannot be previewed as text"}
        }.dump());
        return;
    }

    audit_ok(path_rel, max_bytes, bytes_total, (std::uint64_t)buf.size(), truncated);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"bytes_total", bytes_total},
        {"bytes_returned", (std::uint64_t)buf.size()},
        {"truncated", truncated},
        {"text", buf}
    }.dump());
});

    // POST /api/v4/files/save_text?path=rel/file   (body = UTF-8 text)
srv.Post("/api/v4/files/save_text", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_save_text_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_quota = [&](int http,
                           const std::string& detail,
                           const std::string& path_rel,
                           std::uint64_t new_bytes,
                           std::uint64_t old_bytes,
                           std::uint64_t delta_bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_save_text_quota_exceeded";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = "quota_exceeded";
        ev.f["http"] = std::to_string(http);
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["new_bytes"] = std::to_string((unsigned long long)new_bytes);
        ev.f["old_bytes"] = std::to_string((unsigned long long)old_bytes);
        ev.f["delta_bytes"] = std::to_string((unsigned long long)delta_bytes);
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        std::uint64_t new_bytes,
                        std::uint64_t old_bytes,
                        std::uint64_t delta_bytes,
                        bool overwrote) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_save_text_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["type"] = "file";
        ev.f["new_bytes"] = std::to_string((unsigned long long)new_bytes);
        ev.f["old_bytes"] = std::to_string((unsigned long long)old_bytes);
        ev.f["delta_bytes"] = std::to_string((unsigned long long)delta_bytes);
        ev.f["overwrote"] = overwrote ? "1" : "0";

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // Body is the text content (can be empty)
    const std::string& body = req.body;

    // Reject binary-ish: any NUL in body
    if (std::find(body.begin(), body.end(), '\0') != body.end()) {
        audit_fail("binary_detected", 415, "", path_rel);
        reply_json(res, 415, json{
            {"ok", false},
            {"error", "unsupported_media_type"},
            {"message", "binary content not allowed for save_text"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // If destination exists: must be a file (not dir)
    bool overwrote = false;
    std::uint64_t old_bytes = 0;

    std::error_code ec;
    auto st_dst = std::filesystem::status(path_abs, ec);
    if (!ec && std::filesystem::exists(st_dst)) {
        overwrote = true;
        if (!std::filesystem::is_regular_file(st_dst)) {
            audit_fail("dst_not_file", 400, "", path_rel);
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "destination exists and is not a file"}
            }.dump());
            return;
        }
        old_bytes = pqnas::file_size_u64_safe(path_abs);
    }

    // Ensure parent dirs exist
    ec.clear();
    std::filesystem::create_directories(path_abs.parent_path(), ec);
    if (ec) {
        audit_fail("mkdir_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to create parent directories"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    const std::uint64_t new_bytes = (std::uint64_t)body.size();

    // Quota delta: only additional bytes count
    std::uint64_t delta_bytes = 0;
    if (new_bytes > old_bytes) delta_bytes = (new_bytes - old_bytes);

    if (delta_bytes > 0) {
        pqnas::QuotaCheckResult qc = pqnas::quota_check_for_upload_v1(
            users, fp_hex, user_dir, path_rel, delta_bytes
        );

        // Adjust field name if needed (you used qc.ok earlier)
        if (!qc.ok) {
            int http = 403;
            std::string detail;

            audit_quota(http, detail, path_rel, new_bytes, old_bytes, delta_bytes);

            reply_json(res, http, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "Quota exceeded"},
                {"detail", pqnas::shorten(detail, 180)}
            }.dump());
            return;
        }
    }

    // Atomic write: temp file in same directory + rename
    const std::filesystem::path tmp =
        path_abs.parent_path() /
        (path_abs.filename().string() + ".tmp.save_text." + random_b64url(12));

    // Write temp
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!out.good()) {
            audit_fail("tmp_create_failed", 500, "cannot create temp file", path_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create temp file"}
            }.dump());
            return;
        }
        out.write(body.data(), (std::streamsize)body.size());
        if (!out.good()) {
            std::error_code ec2;
            std::filesystem::remove(tmp, ec2);

            audit_fail("tmp_write_failed", 500, "write failed", path_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "write failed"}
            }.dump());
            return;
        }
    }

    // Overwrite handling: remove existing destination first
    if (overwrote) {
        ec.clear();
        std::filesystem::remove(path_abs, ec);
        if (ec) {
            std::error_code ec2;
            std::filesystem::remove(tmp, ec2);

            audit_fail("overwrite_remove_failed", 500, ec.message(), path_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to overwrite destination"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }
    }

    // Rename into place
    ec.clear();
    std::filesystem::rename(tmp, path_abs, ec);
    if (ec) {
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);

        audit_fail("rename_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "save failed"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    audit_ok(path_rel, new_bytes, old_bytes, delta_bytes, overwrote);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"new_bytes", new_bytes},
        {"old_bytes", old_bytes},
        {"delta_bytes", delta_bytes},
        {"overwrote", overwrote}
    }.dump());
});

    // POST /api/v4/files/zip?path=rel/path&max_bytes=52428800
srv.Post("/api/v4/files/zip", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "", std::uint64_t max_bytes = 0) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (max_bytes) ev.f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        const std::string& type,
                        std::uint64_t max_bytes,
                        std::uint64_t input_bytes,
                        std::uint64_t zip_bytes,
                        std::uint64_t files,
                        std::uint64_t dirs) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["type"] = type;
        ev.f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
        ev.f["input_bytes"] = std::to_string((unsigned long long)input_bytes);
        ev.f["zip_bytes"] = std::to_string((unsigned long long)zip_bytes);
        ev.f["files"] = std::to_string((unsigned long long)files);
        ev.f["dirs"]  = std::to_string((unsigned long long)dirs);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // Safety: reject a leading '-' so it can't be treated as a zip option
    if (!path_rel.empty() && path_rel[0] == '-') {
        audit_fail("invalid_path", 400, "leading '-' refused", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // max_bytes cap (controls RAM usage too)
    std::uint64_t max_bytes = 50ull * 1024 * 1024; // 50 MiB default
    if (req.has_param("max_bytes")) {
        try {
            long long v = std::stoll(req.get_param_value("max_bytes"));
            if (v > 0) max_bytes = (std::uint64_t)v;
        } catch (...) {}
    }
    const std::uint64_t MINB = 1ull * 1024 * 1024;       // 1 MiB
    const std::uint64_t MAXB = 250ull * 1024 * 1024;     // 250 MiB hard clamp
    if (max_bytes < MINB) max_bytes = MINB;
    if (max_bytes > MAXB) max_bytes = MAXB;

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel, max_bytes);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // must exist
    std::error_code ec;
    auto st = std::filesystem::symlink_status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel, max_bytes);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }

    // No symlinks in v1 (avoid surprises with zip behavior)
    if (std::filesystem::is_symlink(st)) {
        audit_fail("symlink_not_supported", 400, "", path_rel, max_bytes);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "symlinks not supported for zip download"}
        }.dump());
        return;
    }

    const bool is_file = std::filesystem::is_regular_file(st);
    const bool is_dir  = std::filesystem::is_directory(st);
    const std::string type = is_dir ? "dir" : (is_file ? "file" : "other");

    // Pre-walk to compute total bytes and ensure no symlinks inside
    std::uint64_t files = 0, dirs = 0, input_bytes = 0;

    if (is_file) {
        files = 1;
        input_bytes = pqnas::file_size_u64_safe(path_abs);
    } else if (is_dir) {
        dirs = 1; // include root dir

        std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;
        ec.clear();
        for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                audit_fail("walk_failed", 500, ec.message(), path_rel, max_bytes);
                reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "directory walk failed"},
                    {"detail", pqnas::shorten(ec.message(), 180)}
                }.dump());
                return;
            }

            std::error_code ec2;
            auto st2 = it->symlink_status(ec2);
            if (ec2) continue;

            if (std::filesystem::is_symlink(st2)) {
                audit_fail("symlink_not_supported", 400, "symlink inside tree", path_rel, max_bytes);
                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "symlinks inside directory are not supported for zip download"}
                }.dump());
                return;
            }

            if (std::filesystem::is_directory(st2)) {
                dirs += 1;
                continue;
            }

            if (std::filesystem::is_regular_file(st2)) {
                files += 1;
                input_bytes += pqnas::file_size_u64_safe(it->path());
                if (input_bytes > max_bytes) break;
                continue;
            }

            // other file types count as “file-like” but 0 bytes
            files += 1;
        }
    } else {
        audit_fail("unsupported_type", 400, "", path_rel, max_bytes);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "unsupported path type for zip download"}
        }.dump());
        return;
    }

    if (input_bytes > max_bytes) {
        audit_fail("too_large", 413, "input exceeds max_bytes", path_rel, max_bytes);
        reply_json(res, 413, json{
            {"ok", false},
            {"error", "too_large"},
            {"message", "selected content exceeds max_bytes"}
        }.dump());
        return;
    }

    // Build zip using /usr/bin/zip and capture to memory (bounded).
    // We run: zip -r -q - <relpath>  (stdout is the zip)
    // in cwd=user_dir, so relpath stays inside user storage.
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        audit_fail("pipe_failed", 500, "pipe()", path_rel, max_bytes);
        reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
        return;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]); ::close(pipefd[1]);
        audit_fail("fork_failed", 500, "fork()", path_rel, max_bytes);
        reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
        return;
    }

    if (pid == 0) {
        // child
        ::dup2(pipefd[1], STDOUT_FILENO);
        // keep STDERR separate

        ::close(pipefd[0]);
        ::close(pipefd[1]);

        if (::chdir(user_dir.c_str()) != 0) _exit(127);



        // args: zip -r -q - <path_rel>
        // Using "--" is supported by many zip builds, but to be safe we already reject leading '-'.
        const char* argv[] = {
            "zip",
            "-r",
            "-q",
            "-",
            path_rel.c_str(),
            nullptr
        };
        ::execvp("zip", (char* const*)argv);
        _exit(127);
    }

    // parent
    ::close(pipefd[1]);

    std::string zip_data;
    zip_data.reserve((size_t)std::min<std::uint64_t>(max_bytes, 4ull * 1024 * 1024));

    const std::uint64_t zip_limit = max_bytes + 8ull * 1024 * 1024; // allow some zip overhead
    std::array<char, 64 * 1024> buf{};
    while (true) {
        ssize_t n = ::read(pipefd[0], buf.data(), (ssize_t)buf.size());
        if (n == 0) break;
        if (n < 0) {
            ::close(pipefd[0]);
            ::kill(pid, SIGKILL);
            audit_fail("read_failed", 500, "read()", path_rel, max_bytes);
            reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
            return;
        }

        if (zip_data.size() + (size_t)n > (size_t)zip_limit) {
            ::close(pipefd[0]);
            ::kill(pid, SIGKILL);
            audit_fail("zip_too_large", 413, "zip output exceeds limit", path_rel, max_bytes);
            reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "zip output too large"}
            }.dump());
            return;
        }

        zip_data.append(buf.data(), (size_t)n);
    }
    ::close(pipefd[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        audit_fail("zip_failed", 500, "zip exit nonzero", path_rel, max_bytes);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "zip failed"}
        }.dump());
        return;
    }

    // filename suggestion
    std::string base = std::filesystem::path(path_rel).filename().string();
    if (base.empty()) base = "download";
    std::string fname = base + ".zip";

    audit_ok(path_rel, type, max_bytes, input_bytes, (std::uint64_t)zip_data.size(), files, dirs);

    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Type", "application/zip");
    res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
    res.body = std::move(zip_data);
});

// POST /api/v4/files/zip_sel
// Body JSON: { "paths": ["rel/a.txt", "rel/dir", ...], "max_bytes": 52428800, "base": "rel/dir" }
// Response: application/zip (in-memory, bounded)
//
// Semantics:
// - paths[] are user-root-relative (same as other v4 file endpoints).
// - If "base" is provided, we chdir() into user_dir/base and feed zip with paths
//   stripped to be relative to base. This avoids the annoying "selection/<cwd>/..."
//   nesting when user selects files from inside a folder.
srv.Post("/api/v4/files/zip_sel", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          std::uint64_t max_bytes = 0, std::uint64_t paths_n = 0) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_sel_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (max_bytes) ev.f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
        if (paths_n)  ev.f["paths_n"]  = std::to_string((unsigned long long)paths_n);
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](std::uint64_t max_bytes,
                        std::uint64_t input_bytes,
                        std::uint64_t zip_bytes,
                        std::uint64_t files,
                        std::uint64_t dirs,
                        std::uint64_t paths_n,
                        const std::string& base_rel) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_sel_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
        ev.f["input_bytes"] = std::to_string((unsigned long long)input_bytes);
        ev.f["zip_bytes"] = std::to_string((unsigned long long)zip_bytes);
        ev.f["files"] = std::to_string((unsigned long long)files);
        ev.f["dirs"]  = std::to_string((unsigned long long)dirs);
        ev.f["paths_n"] = std::to_string((unsigned long long)paths_n);
        if (!base_rel.empty()) ev.f["base"] = pqnas::shorten(base_rel, 200);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    // Parse JSON body
    json body;
    try {
        body = json::parse(req.body.empty() ? "{}" : req.body);
    } catch (const std::exception& e) {
        audit_fail("json_parse", 400, e.what());
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    if (!body.is_object()) {
        audit_fail("json_schema", 400, "body must be object");
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid json schema"}}.dump());
        return;
    }

    if (!body.contains("paths") || !body["paths"].is_array()) {
        audit_fail("missing_paths", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing paths[]"}
        }.dump());
        return;
    }

    // Optional base folder: when provided, zip entries are stored relative to base.
    // Example: base="test" and paths=["test/note.txt"] -> zip entry "note.txt".
    std::string base_rel;
    if (body.contains("base") && body["base"].is_string()) {
        base_rel = body["base"].get<std::string>();

        // normalize slashes + trim leading slashes
        for (char& c : base_rel) if (c == '\\') c = '/';
        while (!base_rel.empty() && base_rel[0] == '/') base_rel.erase(base_rel.begin());

        // strip duplicate slashes
        {
            std::string tmp;
            tmp.reserve(base_rel.size());
            bool prev_slash = false;
            for (char c : base_rel) {
                if (c == '/') {
                    if (prev_slash) continue;
                    prev_slash = true;
                    tmp.push_back(c);
                } else {
                    prev_slash = false;
                    tmp.push_back(c);
                }
            }
            base_rel.swap(tmp);
        }

        // remove trailing slash
        while (!base_rel.empty() && base_rel.back() == '/') base_rel.pop_back();

        // reject unsafe base
        bool bad = false;
        if (!base_rel.empty() && base_rel[0] == '-') bad = true;
        if (base_rel.find('\n') != std::string::npos || base_rel.find('\r') != std::string::npos) bad = true;

        // reject traversal segments
        if (!bad && !base_rel.empty()) {
            size_t start = 0;
            while (start < base_rel.size()) {
                size_t end = base_rel.find('/', start);
                if (end == std::string::npos) end = base_rel.size();
                std::string seg = base_rel.substr(start, end - start);
                if (seg == "." || seg == ".." || seg.empty()) { bad = true; break; }
                start = end + 1;
            }
        }

        if (bad) base_rel.clear();
    }

    // max_bytes cap (controls RAM usage too)
    std::uint64_t max_bytes = 50ull * 1024 * 1024; // 50 MiB default
    if (body.contains("max_bytes")) {
        try {
            long long v = 0;
            if (body["max_bytes"].is_number_integer()) v = body["max_bytes"].get<long long>();
            else if (body["max_bytes"].is_string()) v = std::stoll(body["max_bytes"].get<std::string>());
            if (v > 0) max_bytes = (std::uint64_t)v;
        } catch (...) {}
    }
    const std::uint64_t MINB = 1ull * 1024 * 1024;       // 1 MiB
    const std::uint64_t MAXB = 250ull * 1024 * 1024;     // 250 MiB hard clamp
    if (max_bytes < MINB) max_bytes = MINB;
    if (max_bytes > MAXB) max_bytes = MAXB;

    // Collect + basic sanitize
    std::vector<std::string> paths_in;
    paths_in.reserve(body["paths"].size());

    for (const auto& it : body["paths"]) {
        if (!it.is_string()) continue;
        std::string p = it.get<std::string>();

        // normalize slashes + trim leading slashes
        for (char& c : p) if (c == '\\') c = '/';
        while (!p.empty() && p[0] == '/') p.erase(p.begin());

        // strip duplicate slashes
        {
            std::string tmp;
            tmp.reserve(p.size());
            bool prev_slash = false;
            for (char c : p) {
                if (c == '/') {
                    if (prev_slash) continue;
                    prev_slash = true;
                    tmp.push_back(c);
                } else {
                    prev_slash = false;
                    tmp.push_back(c);
                }
            }
            p.swap(tmp);
        }

        // remove trailing slash (we still treat dir fine)
        while (p.size() > 1 && p.back() == '/') p.pop_back();

        if (p.empty()) continue;

        // Safety: reject leading '-' so it can't be treated as an option by zip
        if (!p.empty() && p[0] == '-') continue;

        // Safety: reject traversal segments
        bool bad = false;
        {
            size_t start = 0;
            while (start < p.size()) {
                size_t end = p.find('/', start);
                if (end == std::string::npos) end = p.size();
                std::string seg = p.substr(start, end - start);
                if (seg == "." || seg == ".." || seg.empty()) { bad = true; break; }
                start = end + 1;
            }
        }
        if (bad) continue;

        // prevent CR/LF injection into -@ stdin list
        if (p.find('\n') != std::string::npos || p.find('\r') != std::string::npos) continue;

        paths_in.push_back(std::move(p));
    }

    // Hard cap selection count to avoid abuse
    const std::size_t MAX_PATHS = 500;
    if (paths_in.empty()) {
        audit_fail("no_valid_paths", 400, "", max_bytes, 0);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "no valid paths"}
        }.dump());
        return;
    }
    if (paths_in.size() > MAX_PATHS) {
        audit_fail("too_many_paths", 413, "paths[] too large", max_bytes, (std::uint64_t)paths_in.size());
        reply_json(res, 413, json{
            {"ok", false},
            {"error", "too_large"},
            {"message", "too many selected paths"}
        }.dump());
        return;
    }

    // Dedupe + drop children if parent dir is selected
    std::sort(paths_in.begin(), paths_in.end());
    paths_in.erase(std::unique(paths_in.begin(), paths_in.end()), paths_in.end());

    std::vector<std::string> paths_rel;
    paths_rel.reserve(paths_in.size());

    auto is_child_of = [&](const std::string& child, const std::string& parent) -> bool {
        if (child.size() <= parent.size()) return false;
        if (child.compare(0, parent.size(), parent) != 0) return false;
        return child[parent.size()] == '/';
    };

    for (const auto& p : paths_in) {
        if (paths_rel.empty()) {
            paths_rel.push_back(p);
            continue;
        }
        bool covered = false;
        for (const auto& sel : paths_rel) {
            if (is_child_of(p, sel)) { covered = true; break; }
        }
        if (!covered) paths_rel.push_back(p);
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    // If base is provided, ensure it's a real directory under user_dir (fail-closed).
    std::filesystem::path base_abs;
    if (!base_rel.empty()) {
        std::string berr;
        if (!pqnas::resolve_user_path_strict(user_dir, base_rel, &base_abs, &berr)) {
            audit_fail("invalid_base", 400, berr, max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid base"}}.dump());
            return;
        }
        std::error_code bec;
        auto bst = std::filesystem::symlink_status(base_abs, bec);
        if (bec || !std::filesystem::exists(bst) || !std::filesystem::is_directory(bst) || std::filesystem::is_symlink(bst)) {
            audit_fail("invalid_base", 400, "base must be an existing directory", max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid base"}}.dump());
            return;
        }
    }

    // If base is set, require all selected paths to be within base.
    // This prevents weird results when we chdir into base but zip tries to access paths outside it.
    if (!base_rel.empty()) {
        for (const auto& p : paths_rel) {
            if (p == base_rel) continue;
            if (!is_child_of(p, base_rel)) {
                audit_fail("path_outside_base", 400, pqnas::shorten(p, 180), max_bytes, (std::uint64_t)paths_rel.size());
                reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "selected path outside base"}
                }.dump());
                return;
            }
        }
    }

    // Resolve + pre-walk all selections (size + symlink checks)
    std::uint64_t files = 0, dirs = 0, input_bytes = 0;

    for (const auto& path_rel : paths_rel) {
        std::filesystem::path path_abs;
        std::string err;
        if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
            audit_fail("invalid_path", 400, err, max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid path"}}.dump());
            return;
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            audit_fail("not_found", 404, path_rel, max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 404, json{{"ok",false},{"error","not_found"},{"message","path not found"}}.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail("symlink_not_supported", 400, "symlink selected", max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","symlinks not supported for zip download"}}.dump());
            return;
        }

        const bool is_file = std::filesystem::is_regular_file(st);
        const bool is_dir  = std::filesystem::is_directory(st);

        if (is_file) {
            files += 1;
            input_bytes += pqnas::file_size_u64_safe(path_abs);
            if (input_bytes > max_bytes) break;
            continue;
        }

        if (is_dir) {
            dirs += 1; // include selected root dir

            std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;
            ec.clear();
            for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
                 it != std::filesystem::recursive_directory_iterator();
                 it.increment(ec)) {

                if (ec) {
                    audit_fail("walk_failed", 500, ec.message(), max_bytes, (std::uint64_t)paths_rel.size());
                    reply_json(res, 500, json{
                        {"ok", false},
                        {"error", "server_error"},
                        {"message", "directory walk failed"},
                        {"detail", pqnas::shorten(ec.message(), 180)}
                    }.dump());
                    return;
                }

                std::error_code ec2;
                auto st2 = it->symlink_status(ec2);
                if (ec2) continue;

                if (std::filesystem::is_symlink(st2)) {
                    audit_fail("symlink_not_supported", 400, "symlink inside tree", max_bytes, (std::uint64_t)paths_rel.size());
                    reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "symlinks inside directory are not supported for zip download"}
                    }.dump());
                    return;
                }

                if (std::filesystem::is_directory(st2)) {
                    dirs += 1;
                    continue;
                }

                if (std::filesystem::is_regular_file(st2)) {
                    files += 1;
                    input_bytes += pqnas::file_size_u64_safe(it->path());
                    if (input_bytes > max_bytes) break;
                    continue;
                }

                files += 1; // other types, 0 bytes
            }
            if (input_bytes > max_bytes) break;
            continue;
        }

        audit_fail("unsupported_type", 400, path_rel, max_bytes, (std::uint64_t)paths_rel.size());
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","unsupported path type for zip download"}}.dump());
        return;
    }

    if (input_bytes > max_bytes) {
        audit_fail("too_large", 413, "input exceeds max_bytes", max_bytes, (std::uint64_t)paths_rel.size());
        reply_json(res, 413, json{{"ok",false},{"error","too_large"},{"message","selected content exceeds max_bytes"}}.dump());
        return;
    }

    // Run: zip -r -q - -@ (read file list from stdin, write zip to stdout)
    int out_pipe[2] = {-1, -1};
    int in_pipe[2]  = {-1, -1};
    if (::pipe(out_pipe) != 0 || ::pipe(in_pipe) != 0) {
        if (out_pipe[0] >= 0) { ::close(out_pipe[0]); ::close(out_pipe[1]); }
        if (in_pipe[0]  >= 0) { ::close(in_pipe[0]);  ::close(in_pipe[1]);  }
        audit_fail("pipe_failed", 500, "pipe()", max_bytes, (std::uint64_t)paths_rel.size());
        reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
        return;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(in_pipe[0]);  ::close(in_pipe[1]);
        audit_fail("fork_failed", 500, "fork()", max_bytes, (std::uint64_t)paths_rel.size());
        reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
        return;
    }

    if (pid == 0) {
        // child
        ::dup2(in_pipe[0], STDIN_FILENO);
        ::dup2(out_pipe[1], STDOUT_FILENO);

        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        ::close(in_pipe[0]);
        ::close(in_pipe[1]);

        if (!base_rel.empty()) {
            std::filesystem::path cd = user_dir / base_rel;
            if (::chdir(cd.c_str()) != 0) _exit(127);
        } else {
            if (::chdir(user_dir.c_str()) != 0) _exit(127);
        }

        const char* argv[] = {
            "zip",
            "-r",
            "-q",
            "-",
            "-@",
            nullptr
        };
        ::execvp("zip", (char* const*)argv);
        _exit(127);
    }

    // parent
    ::close(out_pipe[1]); // read zip from out_pipe[0]
    ::close(in_pipe[0]);  // write list to in_pipe[1]

    // feed paths list
    {
        auto starts_with_dir = [](const std::string& p, const std::string& base) -> bool {
            if (base.empty()) return false;
            if (p.size() <= base.size()) return false;
            if (p.compare(0, base.size(), base) != 0) return false;
            return p[base.size()] == '/';
        };

        bool write_ok = true;
        for (const auto& p0 : paths_rel) {
            std::string p = p0;

            // When chdir() into base, feed zip paths relative to base.
            if (!base_rel.empty()) {
                if (p0 == base_rel) {
                    p = "."; // zip the current directory (the base itself)
                } else if (starts_with_dir(p0, base_rel)) {
                    p = p0.substr(base_rel.size() + 1);
                } else {
                    // should be impossible due to earlier validation
                    write_ok = false;
                }
            }

            if (!write_ok) break;

            if (p.empty()) p = "."; // never send empty line

            std::string line = p;
            line.push_back('\n');

            const char* data = line.data();
            size_t left = line.size();
            while (left > 0) {
                ssize_t n = ::write(in_pipe[1], data, (ssize_t)left);
                if (n <= 0) { write_ok = false; break; }
                data += n;
                left -= (size_t)n;
            }
            if (!write_ok) break;
        }

        ::close(in_pipe[1]);

        if (!write_ok) {
            ::close(out_pipe[0]);
            ::kill(pid, SIGKILL);
            audit_fail("write_failed", 500, "write(stdin)", max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
            return;
        }
    }

    std::string zip_data;
    zip_data.reserve((size_t)std::min<std::uint64_t>(max_bytes, 4ull * 1024 * 1024));

    const std::uint64_t zip_limit = max_bytes + 8ull * 1024 * 1024; // allow some zip overhead
    std::array<char, 64 * 1024> buf{};
    while (true) {
        ssize_t n = ::read(out_pipe[0], buf.data(), (ssize_t)buf.size());
        if (n == 0) break;
        if (n < 0) {
            ::close(out_pipe[0]);
            ::kill(pid, SIGKILL);
            audit_fail("read_failed", 500, "read(zip)", max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
            return;
        }

        if (zip_data.size() + (size_t)n > (size_t)zip_limit) {
            ::close(out_pipe[0]);
            ::kill(pid, SIGKILL);
            audit_fail("zip_too_large", 413, "zip output exceeds limit", max_bytes, (std::uint64_t)paths_rel.size());
            reply_json(res, 413, json{{"ok",false},{"error","too_large"},{"message","zip output too large"}}.dump());
            return;
        }

        zip_data.append(buf.data(), (size_t)n);
    }
    ::close(out_pipe[0]);

    int st = 0;
    ::waitpid(pid, &st, 0);
    if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
        audit_fail("zip_failed", 500, "zip exit nonzero", max_bytes, (std::uint64_t)paths_rel.size());
        reply_json(res, 500, json{{"ok",false},{"error","server_error"},{"message","zip failed"}}.dump());
        return;
    }

    // filename suggestion
    const std::string fname = "selection.zip";

    audit_ok(max_bytes, input_bytes, (std::uint64_t)zip_data.size(), files, dirs, (std::uint64_t)paths_rel.size(), base_rel);

    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Type", "application/zip");
    res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
    res.body = std::move(zip_data);
});

    // POST /api/v4/files/rmrf?path=rel/path
srv.Post("/api/v4/files/rmrf", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_rmrf_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        const std::string& type,
                        std::uint64_t removed_files,
                        std::uint64_t removed_dirs,
                        std::uint64_t removed_bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_rmrf_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["type"] = type;
        ev.f["removed_files"] = std::to_string((unsigned long long)removed_files);
        ev.f["removed_dirs"]  = std::to_string((unsigned long long)removed_dirs);
        ev.f["removed_bytes"] = std::to_string((unsigned long long)removed_bytes);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");

    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // extra safety: refuse root-ish deletes
    auto norm = path_rel;
    while (!norm.empty() && (norm.back() == ' ' || norm.back() == '\t' || norm.back() == '\n' || norm.back() == '\r'))
        norm.pop_back();
    while (!norm.empty() && (norm.front() == ' ' || norm.front() == '\t' || norm.front() == '\n' || norm.front() == '\r'))
        norm.erase(norm.begin());

    if (norm.empty() || norm == "." || norm == "/" || norm == "./") {
        audit_fail("refuse_root", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "refusing to delete root"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // refuse deleting the user_dir itself
    std::error_code ec;
    auto abs_weak = std::filesystem::weakly_canonical(path_abs, ec);
    auto user_weak = std::filesystem::weakly_canonical(user_dir, ec);
    if (!ec && abs_weak == user_weak) {
        audit_fail("refuse_user_root", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "refusing to delete user storage root"}
        }.dump());
        return;
    }

    // must exist
    ec.clear();
    auto st = std::filesystem::symlink_status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }

    // v1 safety: refuse deleting a symlink target directly (prevents confusion)
    if (std::filesystem::is_symlink(st)) {
        audit_fail("target_is_symlink", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "refusing to rmrf a symlink path"}
        }.dump());
        return;
    }

    const bool is_file = std::filesystem::is_regular_file(st);
    const bool is_dir  = std::filesystem::is_directory(st);

    std::string type = is_dir ? "dir" : (is_file ? "file" : "other");

    // Pre-count bytes/files/dirs without following symlinks
    std::uint64_t removed_files = 0;
    std::uint64_t removed_dirs  = 0;
    std::uint64_t removed_bytes = 0;

    if (is_file) {
        removed_files = 1;
        removed_bytes = pqnas::file_size_u64_safe(path_abs);
    } else if (is_dir) {
        removed_dirs = 1; // root dir
        std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;

        ec.clear();
        for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                audit_fail("walk_failed", 500, ec.message(), path_rel);
                reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "directory walk failed"},
                    {"detail", pqnas::shorten(ec.message(), 180)}
                }.dump());
                return;
            }

            std::error_code ec2;
            auto st2 = it->symlink_status(ec2);
            if (ec2) continue;

            if (std::filesystem::is_symlink(st2)) {
                // do not follow; count as "file-like" removed entry of 0 bytes
                removed_files += 1;
                if (it->is_directory(ec2)) it.disable_recursion_pending();
                continue;
            }

            if (std::filesystem::is_directory(st2)) {
                removed_dirs += 1;
                continue;
            }

            if (std::filesystem::is_regular_file(st2)) {
                removed_files += 1;
                removed_bytes += pqnas::file_size_u64_safe(it->path());
                continue;
            }

            // other types counted as file-like entries with 0 bytes
            removed_files += 1;
        }
    } else {
        // other types: treat like single entry delete attempt
        removed_files = 1;
        removed_bytes = 0;
    }

    // Remove (remove_all handles file or dir)
    ec.clear();
    std::uintmax_t removed = std::filesystem::remove_all(path_abs, ec);
    if (ec) {
        audit_fail("remove_all_failed", 500, ec.message(), path_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "recursive delete failed"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    // removed is best-effort count from FS; we report our own counts (more meaningful)
    (void)removed;

    audit_ok(path_rel, type, removed_files, removed_dirs, removed_bytes);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"type", type},
        {"removed_files", removed_files},
        {"removed_dirs", removed_dirs},
        {"removed_bytes", removed_bytes}
    }.dump());
});

    // POST /api/v4/files/search?path=rel/dir&q=needle&max=200
srv.Post("/api/v4/files/search", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    const std::uint64_t SCAN_HARD_CAP = 200000; // hard cap for file search

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "", const std::string& q = "", int max = 0) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_search_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!q.empty())        ev.f["q"] = pqnas::shorten(q, 120);
        if (max > 0)           ev.f["max"] = std::to_string(max);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel, const std::string& q, int max,
                        std::uint64_t scanned, std::uint64_t matched,
                        std::uint64_t returned, bool truncated,
                        bool scan_capped) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_search_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel.empty() ? "." : path_rel, 200);
        ev.f["q"] = pqnas::shorten(q, 120);
        ev.f["max"] = std::to_string(max);
        ev.f["scanned"] = std::to_string((unsigned long long)scanned);
        ev.f["matched"] = std::to_string((unsigned long long)matched);
        ev.f["returned"] = std::to_string((unsigned long long)returned);
        ev.f["truncated"] = truncated ? "1" : "0";

        if (scan_capped) {
            ev.f["scan_capped"] = "1";
            ev.f["scan_cap"] = std::to_string((unsigned long long)SCAN_HARD_CAP);
        }

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel, q;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (req.has_param("q"))    q = req.get_param_value("q");

    // allow "." as user root for convenience
    if (path_rel == "." || path_rel == "./") path_rel.clear();

    if (q.empty()) {
        audit_fail("missing_q", 400, "", path_rel, q);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing q"}
        }.dump());
        return;
    }

    // v1: avoid pathological queries
    if (q.size() > 128) {
        audit_fail("q_too_long", 400, "", path_rel, q);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "q too long"}
        }.dump());
        return;
    }

    int max = 200;
    if (req.has_param("max")) {
        try { max = std::stoi(req.get_param_value("max")); } catch (...) {}
    }
    max = std::max(1, std::min(2000, max));

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path base_abs;
    std::string err;

    // IMPORTANT: do NOT call strict resolver for empty/"." path; treat as user root.
    if (path_rel.empty()) {
        base_abs = user_dir;
    } else {
        if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &base_abs, &err)) {
            audit_fail("invalid_path", 400, err, path_rel, q, max);
            reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid path"}}.dump());
            return;
        }
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(base_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel, q, max);
        reply_json(res, 404, json{{"ok",false},{"error","not_found"},{"message","path not found"}}.dump());
        return;
    }
    if (std::filesystem::is_symlink(st)) {
        audit_fail("symlink_not_supported", 400, "", path_rel, q, max);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","symlinks not supported for search base"}}.dump());
        return;
    }
    if (!std::filesystem::is_directory(st)) {
        audit_fail("not_a_directory", 400, "", path_rel, q, max);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","path must be a directory"}}.dump());
        return;
    }

    auto lower_ascii = [](std::string s) {
        for (char& c : s) c = (char)std::tolower((unsigned char)c);
        return s;
    };

    const std::string ql = lower_ascii(q);

    std::uint64_t scanned = 0;
    std::uint64_t matched = 0;
    bool truncated = false;
    bool scan_capped = false;

    json results = json::array();

    std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;

    ec.clear();
    for (auto it = std::filesystem::recursive_directory_iterator(base_abs, opts, ec);
         it != std::filesystem::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            audit_fail("walk_failed", 500, ec.message(), path_rel, q, max);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "directory walk failed"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }

        scanned++;

        if (scanned >= SCAN_HARD_CAP) {
            scan_capped = true;
            truncated = true;
            break;
        }

        // Do not follow symlinks; also do not recurse into symlink dirs
        std::error_code ec2;
        auto st2 = it->symlink_status(ec2);
        if (!ec2 && std::filesystem::is_symlink(st2)) {
            if (it->is_directory(ec2)) it.disable_recursion_pending();
            continue;
        }

        const std::filesystem::path p = it->path();
        const std::string name = p.filename().string();
        const std::string namel = lower_ascii(name);

        if (namel.find(ql) == std::string::npos) {
            continue;
        }

        matched++;

        std::string type = "other";
        std::uint64_t bytes = 0;

        if (!ec2 && std::filesystem::is_directory(st2)) {
            type = "dir";
        } else if (!ec2 && std::filesystem::is_regular_file(st2)) {
            type = "file";
            bytes = pqnas::file_size_u64_safe(p);
        }

        // Convert to user-relative path
        std::filesystem::path rel = std::filesystem::relative(p, user_dir, ec2);
        std::string rel_s = ec2 ? "" : rel.generic_string();

        json item;
        item["path"] = rel_s.empty() ? pqnas::shorten(p.string(), 220) : rel_s;
        item["name"] = pqnas::shorten(name, 200);
        item["type"] = type;
        if (type == "file") item["bytes"] = bytes;

        results.push_back(item);

        if ((int)results.size() >= max) {
            truncated = true;
            break;
        }
    }

    audit_ok(path_rel, q, max, scanned, matched,
         (std::uint64_t)results.size(), truncated, scan_capped);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel.empty() ? "." : path_rel},
        {"q", q},
        {"max", max},
        {"scanned", scanned},
        {"matched", matched},
        {"truncated", truncated},
        {"scan_capped", scan_capped},
        {"results", results}
    }.dump());
});

// /api/v4/files/stat?path=rel/path or "." (dir -> children + recursive bytes by default)
// GET/POST /api/v4/files/stat?path=rel/path or "." ...
auto files_stat_handler = [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    // Caps for recursive directory aggregation (UI-safe)
    const std::uint64_t RECURSIVE_HARD_CAP = 100000; // max entries scanned
    const int RECURSIVE_TIME_CAP_MS = 300;           // soft wall clock cap

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http,
                          const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_stat_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");

    // allow "." as user root for convenience
    if (path_rel == "." || path_rel == "./" || path_rel == "/") path_rel.clear();

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;

    // IMPORTANT: do NOT call strict resolver for empty/"." path; treat as user root.
    if (path_rel.empty()) {
        path_abs = user_dir;
    } else {
        if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
            audit_fail("invalid_path", 400, err, path_rel);
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }
    }

    // Detect symlink without following (matches /search base behavior)
    std::error_code ec;
    auto st = std::filesystem::symlink_status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }
    if (std::filesystem::is_symlink(st)) {
        audit_fail("symlink_not_supported", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "symlinks not supported"}
        }.dump());
        return;
    }

    // Helper: absolute-like normalized path for UI (/foo/bar). Root => "/"
    auto make_path_norm = [&](const std::filesystem::path& p) -> std::string {
        std::error_code ec2;
        auto rel = std::filesystem::relative(p, user_dir, ec2);
        if (ec2) return "/";
        std::string s = rel.generic_string();
        if (s.empty() || s == ".") return "/";
        if (!s.empty() && s[0] != '/') s = "/" + s;
        return s;
    };

    auto mode_octal_from_perms = [&](std::filesystem::perms pr) -> std::string {
        auto has = [&](std::filesystem::perms bit) { return (pr & bit) != std::filesystem::perms::none; };

        int m = 0;
        if (has(std::filesystem::perms::owner_read))  m |= 0400;
        if (has(std::filesystem::perms::owner_write)) m |= 0200;
        if (has(std::filesystem::perms::owner_exec))  m |= 0100;

        if (has(std::filesystem::perms::group_read))  m |= 0040;
        if (has(std::filesystem::perms::group_write)) m |= 0020;
        if (has(std::filesystem::perms::group_exec))  m |= 0010;

        if (has(std::filesystem::perms::others_read))  m |= 0004;
        if (has(std::filesystem::perms::others_write)) m |= 0002;
        if (has(std::filesystem::perms::others_exec))  m |= 0001;

        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04o", m);
        return std::string(buf);
    };

    auto guess_mime = [&](const std::string& name) -> std::string {
        auto lower = [](std::string s) {
            for (char& c : s) c = (char)std::tolower((unsigned char)c);
            return s;
        };
        std::string n = lower(name);
        auto dot = n.rfind('.');
        std::string ext = (dot == std::string::npos) ? "" : n.substr(dot + 1);

        if (ext == "txt" || ext == "log" || ext == "md") return "text/plain";
        if (ext == "json") return "application/json";
        if (ext == "html" || ext == "htm") return "text/html";
        if (ext == "css") return "text/css";
        if (ext == "js") return "application/javascript";
        if (ext == "xml") return "application/xml";
        if (ext == "csv") return "text/csv";

        if (ext == "png") return "image/png";
        if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
        if (ext == "gif") return "image/gif";
        if (ext == "webp") return "image/webp";
        if (ext == "svg") return "image/svg+xml";

        if (ext == "pdf") return "application/pdf";
        if (ext == "zip") return "application/zip";

        return "application/octet-stream";
    };

    auto looks_like_text = [&](const std::filesystem::path& p) -> bool {
        // lightweight "binary reject": treat NUL as binary
        std::ifstream f(p, std::ios::binary);
        if (!f.good()) return false;

        char buf[4096];
        f.read(buf, sizeof(buf));
        std::streamsize n = f.gcount();
        for (std::streamsize i = 0; i < n; i++) {
            if (buf[i] == '\0') return false;
        }
        return true;
    };

    const bool is_dir = std::filesystem::is_directory(st);
    const bool is_file = std::filesystem::is_regular_file(st);

    std::string type = "other";
    if (is_dir) type = "dir";
    else if (is_file) type = "file";

    const std::string path_norm = make_path_norm(path_abs);
    const std::string name = (path_abs == user_dir) ? "" : path_abs.filename().string();

    // mtime (portable via last_write_time)
    std::uint64_t mtime_epoch = 0;
    {
        std::error_code ec3;
        auto ftime = std::filesystem::last_write_time(path_abs, ec3);
        if (!ec3) {
            using namespace std::chrono;
            auto sctp = time_point_cast<system_clock::duration>(
                ftime - std::filesystem::file_time_type::clock::now() + system_clock::now()
            );
            auto sec = duration_cast<seconds>(sctp.time_since_epoch()).count();
            if (sec > 0) mtime_epoch = (std::uint64_t)sec;
        }
    }

    // mode (best-effort)
    std::string mode_octal = "0000";
    {
        std::error_code ec4;
        auto stp = std::filesystem::status(path_abs, ec4);
        if (!ec4) mode_octal = mode_octal_from_perms(stp.permissions());
    }

    json out;
    out["ok"] = true;
    out["path"] = path_rel.empty() ? "." : path_rel;
    out["path_norm"] = path_norm;
    out["name"] = pqnas::shorten(name, 200);
    out["type"] = type;
    out["exists"] = true;
    if (mtime_epoch > 0) out["mtime_epoch"] = mtime_epoch;
    out["mode_octal"] = mode_octal;

    if (type == "file") {
        out["bytes"] = pqnas::file_size_u64_safe(path_abs);
        out["mime"] = guess_mime(name);
        out["is_text"] = looks_like_text(path_abs);
        reply_json(res, 200, out.dump());
        return;
    }

    if (type == "dir") {
        // immediate children counts
        std::uint64_t c_files = 0, c_dirs = 0, c_other = 0;

        std::error_code ec5;
        for (auto it = std::filesystem::directory_iterator(path_abs, std::filesystem::directory_options::skip_permission_denied, ec5);
             !ec5 && it != std::filesystem::directory_iterator();
             it.increment(ec5)) {

            std::error_code ec6;
            auto stc = it->symlink_status(ec6);
            if (ec6) { c_other++; continue; }

            if (std::filesystem::is_symlink(stc)) { c_other++; continue; }
            if (std::filesystem::is_directory(stc)) c_dirs++;
            else if (std::filesystem::is_regular_file(stc)) c_files++;
            else c_other++;
        }

        out["children"] = json{
            {"files", c_files},
            {"dirs", c_dirs},
            {"other", c_other}
        };

        // recursive bytes: sum regular files only, skip symlinks (matches /du)
        std::uint64_t bytes_recursive = 0;
        std::uint64_t scanned = 0;
        bool complete = true;

        auto t0 = std::chrono::steady_clock::now();
        std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;

        ec5.clear();
        for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec5);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec5)) {

            if (ec5) {
                audit_fail("walk_failed", 500, ec5.message(), path_rel);
                reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "directory walk failed"},
                    {"detail", pqnas::shorten(ec5.message(), 180)}
                }.dump());
                return;
            }

            scanned++;

            if (scanned >= RECURSIVE_HARD_CAP) { complete = false; break; }

            auto now = std::chrono::steady_clock::now();
            auto ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
            if (ms >= RECURSIVE_TIME_CAP_MS) { complete = false; break; }

            std::error_code ec6;
            auto st2 = it->symlink_status(ec6);
            if (ec6) continue;

            // Do not follow symlinks; do not descend into symlink dirs
            if (std::filesystem::is_symlink(st2)) {
                if (it->is_directory(ec6)) it.disable_recursion_pending();
                continue;
            }

            if (std::filesystem::is_regular_file(st2)) {
                bytes_recursive += pqnas::file_size_u64_safe(it->path());
            }
        }

        out["bytes_recursive"] = bytes_recursive;
        out["recursive_scanned_entries"] = scanned;
        out["recursive_complete"] = complete;
        out["scan_cap"] = RECURSIVE_HARD_CAP;
        out["time_cap_ms"] = RECURSIVE_TIME_CAP_MS;

        reply_json(res, 200, out.dump());
        return;
    }

    // other types: just return metadata
    reply_json(res, 200, out.dump());
};

srv.Post("/api/v4/files/stat", files_stat_handler);
srv.Get ("/api/v4/files/stat", files_stat_handler);

// POST /api/v4/files/stat_sel
// Body: { "paths": ["rel/path", ".", ...] }
// Returns aggregated selection stats (total bytes etc) + per-item minimal stats.
srv.Post("/api/v4/files/stat_sel", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    // caps (match /stat)
    const std::uint64_t RECURSIVE_HARD_CAP = 100000;
    const int RECURSIVE_TIME_CAP_MS = 300;

    // selection cap (protect server)
    const int MAX_ITEMS = 200;

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    if (!body.is_object() || !body.contains("paths") || !body["paths"].is_array()) {
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "body must be { paths: [...] }"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    // Helpers (copied from /stat for consistency)
    auto mode_octal_from_perms = [&](std::filesystem::perms pr) -> std::string {
        auto has = [&](std::filesystem::perms bit) { return (pr & bit) != std::filesystem::perms::none; };
        int m = 0;
        if (has(std::filesystem::perms::owner_read))  m |= 0400;
        if (has(std::filesystem::perms::owner_write)) m |= 0200;
        if (has(std::filesystem::perms::owner_exec))  m |= 0100;
        if (has(std::filesystem::perms::group_read))  m |= 0040;
        if (has(std::filesystem::perms::group_write)) m |= 0020;
        if (has(std::filesystem::perms::group_exec))  m |= 0010;
        if (has(std::filesystem::perms::others_read))  m |= 0004;
        if (has(std::filesystem::perms::others_write)) m |= 0002;
        if (has(std::filesystem::perms::others_exec))  m |= 0001;
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04o", m);
        return std::string(buf);
    };

    auto make_path_norm = [&](const std::filesystem::path& p) -> std::string {
        std::error_code ec2;
        auto rel = std::filesystem::relative(p, user_dir, ec2);
        if (ec2) return "/";
        std::string s = rel.generic_string();
        if (s.empty() || s == ".") return "/";
        if (!s.empty() && s[0] != '/') s = "/" + s;
        return s;
    };

    auto dir_bytes_recursive = [&](const std::filesystem::path& base_abs,
                                   std::uint64_t* out_scanned,
                                   bool* out_complete) -> std::uint64_t {
        std::uint64_t bytes_recursive = 0;
        std::uint64_t scanned = 0;
        bool complete = true;

        auto t0 = std::chrono::steady_clock::now();
        std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;

        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(base_abs, opts, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                // Treat walk failure as incomplete; caller will record error.
                complete = false;
                break;
            }

            scanned++;
            if (scanned >= RECURSIVE_HARD_CAP) { complete = false; break; }

            auto now = std::chrono::steady_clock::now();
            auto ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
            if (ms >= RECURSIVE_TIME_CAP_MS) { complete = false; break; }

            std::error_code ec6;
            auto st2 = it->symlink_status(ec6);
            if (ec6) continue;

            if (std::filesystem::is_symlink(st2)) {
                if (it->is_directory(ec6)) it.disable_recursion_pending();
                continue;
            }

            if (std::filesystem::is_regular_file(st2)) {
                bytes_recursive += pqnas::file_size_u64_safe(it->path());
            }
        }

        if (out_scanned) *out_scanned = scanned;
        if (out_complete) *out_complete = complete;
        return bytes_recursive;
    };

    // Aggregate
    std::uint64_t total_bytes = 0;
    int n_files = 0, n_dirs = 0, n_other = 0;
    bool partial = false;

    json items = json::array();
    json errors = json::array();

    int idx = 0;
    for (const auto& v : body["paths"]) {
        if (idx >= MAX_ITEMS) { partial = true; break; }
        idx++;

        if (!v.is_string()) {
            partial = true;
            errors.push_back(json{{"path",""}, {"error","bad_request"}, {"message","path must be string"}});
            continue;
        }

        std::string path_rel = v.get<std::string>();

        // allow "." as user root
        if (path_rel == "." || path_rel == "./" || path_rel == "/") path_rel.clear();

        std::filesystem::path path_abs;
        std::string err;

        if (path_rel.empty()) {
            path_abs = user_dir;
        } else {
            if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
                partial = true;
                errors.push_back(json{{"path", path_rel}, {"error","invalid_path"}, {"message", pqnas::shorten(err, 180)}});
                continue;
            }
        }

        // Detect symlink without following
        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            partial = true;
            errors.push_back(json{{"path", path_rel.empty() ? "." : path_rel}, {"error","not_found"}});
            continue;
        }
        if (std::filesystem::is_symlink(st)) {
            partial = true;
            errors.push_back(json{{"path", path_rel.empty() ? "." : path_rel}, {"error","symlink_not_supported"}});
            continue;
        }

        const bool is_dir = std::filesystem::is_directory(st);
        const bool is_file = std::filesystem::is_regular_file(st);

        std::string type = "other";
        if (is_dir) type = "dir";
        else if (is_file) type = "file";

        json itj;
        itj["path"] = path_rel.empty() ? "." : path_rel;
        itj["path_norm"] = make_path_norm(path_abs);
        itj["type"] = type;

        // mode (best-effort, same as /stat)
        {
            std::error_code ec4;
            auto stp = std::filesystem::status(path_abs, ec4);
            if (!ec4) itj["mode_octal"] = mode_octal_from_perms(stp.permissions());
        }

        if (type == "file") {
            std::uint64_t b = pqnas::file_size_u64_safe(path_abs);
            itj["bytes"] = b;
            total_bytes += b;
            n_files++;
            items.push_back(itj);
            continue;
        }

        if (type == "dir") {
            std::uint64_t scanned = 0;
            bool complete = true;

            // recursive bytes: sum regular files only, skip symlinks (same as /stat)
            std::uint64_t b = dir_bytes_recursive(path_abs, &scanned, &complete);

            itj["bytes_recursive"] = b;
            itj["recursive_scanned_entries"] = scanned;
            itj["recursive_complete"] = complete;

            total_bytes += b;
            n_dirs++;

            if (!complete) partial = true;

            items.push_back(itj);
            continue;
        }

        // other
        n_other++;
        items.push_back(itj);
        partial = true; // “other” is uncommon; treat aggregate as partial/unknown
    }

    json out;
    out["ok"] = true;
    out["count"] = (int)items.size();
    out["files"] = n_files;
    out["dirs"] = n_dirs;
    out["other"] = n_other;
    out["bytes_total"] = total_bytes;
    out["partial"] = partial;

    out["limits"] = json{
        {"max_items", MAX_ITEMS},
        {"scan_cap", RECURSIVE_HARD_CAP},
        {"time_cap_ms", RECURSIVE_TIME_CAP_MS}
    };

    out["items"] = items;
    out["errors"] = errors;

    reply_json(res, 200, out.dump());
});



    // POST /api/v4/files/du?path=rel/path
srv.Post("/api/v4/files/du", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_du_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        const std::string& type,
                        std::uint64_t bytes_total,
                        std::uint64_t files,
                        std::uint64_t dirs) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_du_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["type"] = type;
        ev.f["bytes_total"] = std::to_string((unsigned long long)bytes_total);
        ev.f["files"] = std::to_string((unsigned long long)files);
        ev.f["dirs"]  = std::to_string((unsigned long long)dirs);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");
    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }

    // If file: trivial
    if (std::filesystem::is_regular_file(st)) {
        std::uint64_t bytes = pqnas::file_size_u64_safe(path_abs);
        audit_ok(path_rel, "file", bytes, /*files=*/1, /*dirs=*/0);
        reply_json(res, 200, json{
            {"ok", true},
            {"path", path_rel},
            {"type", "file"},
            {"bytes_total", bytes},
            {"files", 1},
            {"dirs", 0}
        }.dump());
        return;
    }

    // If not a directory: reject (keeps semantics clean)
    if (!std::filesystem::is_directory(st)) {
        audit_fail("not_file_or_dir", 400, "", path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "path is not a file or directory"}
        }.dump());
        return;
    }

    // Directory recursive: sum regular files only, do not follow symlinks
    std::uint64_t bytes_total = 0;
    std::uint64_t files = 0;
    std::uint64_t dirs = 1; // count root dir

    std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;

    ec.clear();
    for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
         it != std::filesystem::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            // Fail closed: if traversal hits an error, stop and report
            audit_fail("walk_failed", 500, ec.message(), path_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "directory walk failed"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }

        std::error_code ec2;
        auto st2 = it->symlink_status(ec2);
        if (ec2) continue;

        // Do not follow symlinks: if entry is symlink, skip it (and don’t descend)
        if (std::filesystem::is_symlink(st2)) {
            if (it->is_directory(ec2)) it.disable_recursion_pending();
            continue;
        }

        if (std::filesystem::is_directory(st2)) {
            dirs++;
            continue;
        }

        if (std::filesystem::is_regular_file(st2)) {
            files++;
            std::uint64_t sz = pqnas::file_size_u64_safe(it->path());
            bytes_total += sz;
            continue;
        }

        // other types ignored
    }

    audit_ok(path_rel, "dir", bytes_total, files, dirs);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"type", "dir"},
        {"bytes_total", bytes_total},
        {"files", files},
        {"dirs", dirs}
    }.dump());
});


// DELETE /api/v4/files/delete?path=relative/path
// Deletes a file or directory (recursive). Refuses empty path (won't delete user root).
srv.Delete("/api/v4/files/delete", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role)) return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_delete_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_ok = [&](const std::string& rel_path, const std::string& type,
                        std::uint64_t freed_bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_delete_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);
        ev.f["type"] = type;
        ev.f["freed_bytes"] = std::to_string((unsigned long long)freed_bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // Storage allocated check (fail-closed)
    {
        auto uopt = users.get(fp_hex);
        if (!uopt.has_value()) {
            audit_fail("user_missing", 403);
            reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "policy denied"}}.dump());
            return;
        }
        const auto& u = *uopt;
        if (u.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403);
            reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Storage not allocated"},
                {"fingerprint_hex", fp_hex},
                {"quota_bytes", u.quota_bytes}
            }.dump());
            return;
        }
    }

    // path param (required)
    std::string rel_path;
    if (req.has_param("path")) rel_path = req.get_param_value("path");
    if (rel_path.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path abs_path;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(user_dir, rel_path, &abs_path, &perr)) {
        audit_fail("invalid_path", 400, perr);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // Extra safety: refuse deleting the user root directly
    // (only possible if rel_path somehow resolves to user_dir, but keep it explicit)
    if (abs_path == user_dir) {
        audit_fail("refuse_root_delete", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "refusing to delete root"}
        }.dump());
        return;
    }

    // Must exist
    std::error_code ec;
    auto st = std::filesystem::status(abs_path, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "path not found"}
        }.dump());
        return;
    }

    // Compute freed bytes (best-effort)
    auto compute_freed_bytes = [&](const std::filesystem::path& p) -> std::uint64_t {
        std::uint64_t total = 0;
        std::error_code ecx;

        auto st2 = std::filesystem::status(p, ecx);
        if (ecx) return 0;

        if (std::filesystem::is_regular_file(st2)) {
            auto sz = std::filesystem::file_size(p, ecx);
            if (!ecx) total += (std::uint64_t)sz;
            return total;
        }

        if (std::filesystem::is_directory(st2)) {
            for (std::filesystem::recursive_directory_iterator it(p, ecx), end;
                 it != end && !ecx;
                 it.increment(ecx)) {
                std::error_code ec2;
                if (it->is_regular_file(ec2) && !ec2) {
                    std::error_code ec3;
                    auto sz = it->file_size(ec3);
                    if (!ec3) total += (std::uint64_t)sz;
                }
            }
        }

        return total;
    };

    const bool is_dir = std::filesystem::is_directory(st);
    const std::string type = is_dir ? "dir" : (std::filesystem::is_regular_file(st) ? "file" : "other");

    std::uint64_t freed_bytes = compute_freed_bytes(abs_path);

    // Delete
    if (is_dir) {
        std::uintmax_t removed = std::filesystem::remove_all(abs_path, ec);
        if (ec || removed == 0) {
            audit_fail("remove_all_failed", 500, ec.message());
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "delete failed"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }
    } else {
        bool removed = std::filesystem::remove(abs_path, ec);
        if (ec || !removed) {
            audit_fail("remove_failed", 500, ec.message());
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "delete failed"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }
    }

    audit_ok(rel_path, type, freed_bytes);

    reply_json(res, 200, json{
        {"ok", true},
        {"fingerprint_hex", fp_hex},
        {"path", rel_path},
        {"type", type},
        {"freed_bytes", freed_bytes}
    }.dump());
});

// GET /api/v4/files/list?path=relative/dir   (path optional; empty => user root)
// Response: JSON listing of immediate children (no recursion)
srv.Get("/api/v4/files/list", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role)) return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_list_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_ok = [&](const std::string& rel_dir, std::size_t count) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_list_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_dir, 200);
        ev.f["count"] = std::to_string((unsigned long long)count);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // Storage allocated check (fail-closed)
    {
        auto uopt = users.get(fp_hex);
        if (!uopt.has_value()) {
            audit_fail("user_missing", 403);
            reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "policy denied"}}.dump());
            return;
        }
        const auto& u = *uopt;
        if (u.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403);
            reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Storage not allocated"},
                {"fingerprint_hex", fp_hex},
                {"quota_bytes", u.quota_bytes}
            }.dump());
            return;
        }
    }

    // path param (optional). Empty => root listing.
    std::string rel_dir;
    if (req.has_param("path")) rel_dir = req.get_param_value("path");
    // allow empty here
    // but still reject NUL and backslashes / drive letters etc if provided
    // We'll validate via resolve_user_path_strict only when non-empty.

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);
    std::filesystem::path abs_dir = user_dir;

    if (!rel_dir.empty()) {
        std::string perr;
        if (!pqnas::resolve_user_path_strict(user_dir, rel_dir, &abs_dir, &perr)) {
            audit_fail("invalid_path", 400, perr);
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }
    }

    // Must exist and be directory
    std::error_code ec;
    auto st = std::filesystem::status(abs_dir, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "directory not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_directory(st)) {
        audit_fail("not_a_directory", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "not a directory"}
        }.dump());
        return;
    }

    json out;
    out["ok"] = true;
    out["fingerprint_hex"] = fp_hex;
    out["path"] = rel_dir;
    out["items"] = json::array();

    // List immediate children
    std::size_t count = 0;
    for (std::filesystem::directory_iterator it(abs_dir, ec), end; it != end && !ec; it.increment(ec)) {
        std::error_code ec2;

        const auto name = it->path().filename().string();
        if (name == "." || name == ".." || name.empty()) continue;

        std::string type = "other";
        if (it->is_directory(ec2) && !ec2) type = "dir";
        ec2.clear();
        if (it->is_regular_file(ec2) && !ec2) type = "file";

        std::uint64_t size_bytes = 0;
        if (type == "file") {
            ec2.clear();
            auto sz = it->file_size(ec2);
            if (!ec2) size_bytes = (std::uint64_t)sz;
        }

        long long mtime_unix = 0;
        // best-effort mtime (portable-ish)
        ec2.clear();
        auto ft = it->last_write_time(ec2);
        if (!ec2) {
            using namespace std::chrono;
            auto sctp = time_point_cast<system_clock::duration>(
                ft - decltype(ft)::clock::now() + system_clock::now()
            );
            mtime_unix = (long long)duration_cast<seconds>(sctp.time_since_epoch()).count();
        }

        out["items"].push_back(json{
            {"name", name},
            {"type", type},
            {"size_bytes", size_bytes},
            {"mtime_unix", mtime_unix}
        });
        count++;
        if (count >= 5000) break; // v1 safety cap
    }

    audit_ok(rel_dir, count);
    reply_json(res, 200, out.dump());
});

    // POST /api/v4/files/exists?path=rel/path
srv.Post("/api/v4/files/exists", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_exists_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& path_rel,
                        const std::string& type,
                        bool exists,
                        std::uint64_t bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_exists_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(path_rel, 200);
        ev.f["exists"] = exists ? "1" : "0";
        ev.f["type"] = type;
        if (exists && type == "file") ev.f["bytes"] = std::to_string((unsigned long long)bytes);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string path_rel;
    if (req.has_param("path")) path_rel = req.get_param_value("path");

    if (path_rel.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path path_abs;
    std::string err;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &path_abs, &err)) {
        audit_fail("invalid_path", 400, err, path_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::status(path_abs, ec);

    bool exists = (!ec && std::filesystem::exists(st));
    std::string type = "missing";
    std::uint64_t bytes = 0;

    if (exists) {
        if (std::filesystem::is_regular_file(st)) {
            type = "file";
            bytes = pqnas::file_size_u64_safe(path_abs);
        } else if (std::filesystem::is_directory(st)) {
            type = "dir";
        } else if (std::filesystem::is_symlink(st)) {
            // resolve_user_path_strict should already prevent escaping,
            // but we still report accurately.
            type = "symlink";
        } else {
            type = "other";
        }
    }

    audit_ok(path_rel, type, exists, bytes);

    reply_json(res, 200, json{
        {"ok", true},
        {"path", path_rel},
        {"exists", exists},
        {"type", type},
        {"bytes", bytes}
    }.dump());
});


    // POST /api/v4/files/copy?from=old/path&to=new/path
srv.Post("/api/v4/files/copy", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& from_rel = "", const std::string& to_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_copy_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!from_rel.empty()) ev.f["from"] = pqnas::shorten(from_rel, 200);
        if (!to_rel.empty())   ev.f["to"]   = pqnas::shorten(to_rel, 200);
        if (!detail.empty())   ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_quota = [&](int http,
                           const std::string& detail,
                           const std::string& from_rel,
                           const std::string& to_rel,
                           std::uint64_t src_bytes,
                           std::uint64_t dst_old_bytes,
                           std::uint64_t delta_bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_copy_quota_exceeded";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = "quota_exceeded";
        ev.f["http"] = std::to_string(http);
        ev.f["from"] = pqnas::shorten(from_rel, 200);
        ev.f["to"]   = pqnas::shorten(to_rel, 200);
        ev.f["src_bytes"] = std::to_string((unsigned long long)src_bytes);
        ev.f["dst_old_bytes"] = std::to_string((unsigned long long)dst_old_bytes);
        ev.f["delta_bytes"] = std::to_string((unsigned long long)delta_bytes);
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&](const std::string& from_rel,
                        const std::string& to_rel,
                        std::uint64_t src_bytes,
                        std::uint64_t dst_old_bytes,
                        std::uint64_t delta_bytes,
                        bool overwrote) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_copy_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["from"] = pqnas::shorten(from_rel, 200);
        ev.f["to"]   = pqnas::shorten(to_rel, 200);
        ev.f["type"] = "file";
        ev.f["src_bytes"] = std::to_string((unsigned long long)src_bytes);
        ev.f["dst_old_bytes"] = std::to_string((unsigned long long)dst_old_bytes);
        ev.f["delta_bytes"] = std::to_string((unsigned long long)delta_bytes);
        ev.f["overwrote"] = overwrote ? "1" : "0";

        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // must have allocated storage
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "storage_unallocated"},
            {"message", "Storage not allocated"}
        }.dump());
        return;
    }

    std::string from_rel, to_rel;
    if (req.has_param("from")) from_rel = req.get_param_value("from");
    if (req.has_param("to"))   to_rel   = req.get_param_value("to");

    if (from_rel.empty() || to_rel.empty()) {
        audit_fail("missing_from_or_to", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing from or to"}
        }.dump());
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    std::filesystem::path from_abs, to_abs;
    std::string err1, err2;
    if (!pqnas::resolve_user_path_strict(user_dir, from_rel, &from_abs, &err1)) {
        audit_fail("invalid_from_path", 400, err1, from_rel, to_rel);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid from path"}}.dump());
        return;
    }
    if (!pqnas::resolve_user_path_strict(user_dir, to_rel, &to_abs, &err2)) {
        audit_fail("invalid_to_path", 400, err2, from_rel, to_rel);
        reply_json(res, 400, json{{"ok",false},{"error","bad_request"},{"message","invalid to path"}}.dump());
        return;
    }

    // refuse no-op
    if (from_abs == to_abs) {
        audit_fail("same_path", 400, "", from_rel, to_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "from and to are the same"}
        }.dump());
        return;
    }

    // source must exist + must be regular file (v1: file-only)
    std::error_code ec;
    auto st_src = std::filesystem::status(from_abs, ec);
    if (ec || !std::filesystem::exists(st_src)) {
        audit_fail("not_found", 404, "", from_rel, to_rel);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "source not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_regular_file(st_src)) {
        audit_fail("src_not_file", 400, "", from_rel, to_rel);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "source must be a file (directories not supported yet)"}
        }.dump());
        return;
    }

    const std::uint64_t src_bytes = pqnas::file_size_u64_safe(from_abs);

    // destination: if exists, must be regular file (overwrite) or missing
    bool dst_exists = false;
    bool dst_is_file = false;
    std::uint64_t dst_old_bytes = 0;

    ec.clear();
    auto st_dst = std::filesystem::status(to_abs, ec);
    if (!ec && std::filesystem::exists(st_dst)) {
        dst_exists = true;
        dst_is_file = std::filesystem::is_regular_file(st_dst);
        if (!dst_is_file) {
            audit_fail("dst_not_file", 400, "", from_rel, to_rel);
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "destination exists and is not a file"}
            }.dump());
            return;
        }
        dst_old_bytes = pqnas::file_size_u64_safe(to_abs);
    }

    // ensure destination parent exists
    ec.clear();
    std::filesystem::create_directories(to_abs.parent_path(), ec);
    if (ec) {
        audit_fail("mkdir_failed", 500, ec.message(), from_rel, to_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to create destination directories"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    // quota-aware: delta = src_bytes - dst_old_bytes (only if positive)
    std::uint64_t delta_bytes = 0;
    if (src_bytes > dst_old_bytes) delta_bytes = (src_bytes - dst_old_bytes);

    if (delta_bytes > 0) {
        // IMPORTANT: use destination rel path for quota attribution
        pqnas::QuotaCheckResult qc = pqnas::quota_check_for_upload_v1(
            users, fp_hex, user_dir, to_rel, delta_bytes
        );

        // ---- Adjust these field names if your QuotaCheckResult differs ----
        // Expected: qc.ok (bool). If you have qc.allowed, rename accordingly.
        if (!qc.ok) {
            // Choose http + detail if your struct carries them, otherwise fall back.
            int http = 403;
            std::string detail;

            // If your struct has these, uncomment/adjust:
            // if (qc.http > 0) http = qc.http;
            // detail = qc.detail.empty() ? qc.message : qc.detail;

            audit_quota(http, detail, from_rel, to_rel, src_bytes, dst_old_bytes, delta_bytes);

            reply_json(res, http, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "Quota exceeded"},
                {"detail", pqnas::shorten(detail, 180)}
            }.dump());
            return;
        }
    }

    // copy using temp file + rename (atomic within same directory)
    const std::filesystem::path tmp =
    to_abs.parent_path() /
    (to_abs.filename().string() + ".tmp.copy." + random_b64url(12));

    // Best effort: remove stale tmp
    ec.clear();
    std::filesystem::remove(tmp, ec);

    ec.clear();
    std::filesystem::copy_file(from_abs, tmp, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        audit_fail("copy_failed", 500, ec.message(), from_rel, to_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "copy failed"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    // If overwriting, remove destination right before rename
    if (dst_exists) {
        ec.clear();
        std::filesystem::remove(to_abs, ec);
        if (ec) {
            // cleanup tmp
            std::error_code ec2;
            std::filesystem::remove(tmp, ec2);

            audit_fail("overwrite_remove_failed", 500, ec.message(), from_rel, to_rel);
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to overwrite destination"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }
    }

    ec.clear();
    std::filesystem::rename(tmp, to_abs, ec);
    if (ec) {
        // cleanup tmp
        std::error_code ec2;
        std::filesystem::remove(tmp, ec2);

        audit_fail("rename_failed", 500, ec.message(), from_rel, to_rel);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "copy failed"},
            {"detail", pqnas::shorten(ec.message(), 180)}
        }.dump());
        return;
    }

    audit_ok(from_rel, to_rel, src_bytes, dst_old_bytes, delta_bytes, dst_exists);

    reply_json(res, 200, json{
        {"ok", true},
        {"from", from_rel},
        {"to", to_rel},
        {"type", "file"},
        {"src_bytes", src_bytes},
        {"dst_old_bytes", dst_old_bytes},
        {"delta_bytes", delta_bytes},
        {"overwrote", dst_exists}
    }.dump());
});

// GET /api/v4/files/zip?path=relative/dir
// Response: application/zip (streams a zip of the directory)
srv.Get("/api/v4/files/zip", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role)) return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_ok = [&](const std::string& rel_path, std::uint64_t bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_zip_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);
        ev.f["bytes"] = std::to_string((unsigned long long)bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // path param (directory)
    std::string rel_path;
    if (req.has_param("path")) rel_path = req.get_param_value("path");
    if (rel_path.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // Must be allocated (fail-closed)
    {
        auto uopt = users.get(fp_hex);
        if (!uopt.has_value()) {
            audit_fail("user_missing", 403);
            reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "policy denied"}}.dump());
            return;
        }
        const auto& u = *uopt;
        if (u.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403);
            reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Storage not allocated"},
                {"fingerprint_hex", fp_hex},
                {"quota_bytes", u.quota_bytes}
            }.dump());
            return;
        }
    }

    // Resolve directory path strictly under user dir
    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);
    std::filesystem::path abs_dir;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(user_dir, rel_path, &abs_dir, &perr)) {
        audit_fail("invalid_path", 400, perr);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // Validate exists + directory
    std::error_code ec;
    auto st = std::filesystem::status(abs_dir, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "directory not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_directory(st)) {
        audit_fail("not_directory", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "not a directory"}
        }.dump());
        return;
    }

    // Collect files (pass 1)
    std::vector<ZipFileItem> items;
    std::uint64_t total_payload = 0;

    // ZIP will contain entries relative to rel_path root.
    // Example: rel_path="photos" => inside zip, paths like "photos/a.jpg" etc.
    // This makes it intuitive when extracted.
    const std::string zip_root = zip_sanitize_relpath(rel_path);
    const std::filesystem::path base = abs_dir;

    for (auto it = std::filesystem::recursive_directory_iterator(base, ec);
         !ec && it != std::filesystem::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) break;
        const auto& de = *it;
        if (!de.is_regular_file(ec)) continue;
        if (ec) { ec.clear(); continue; }

        const std::filesystem::path abs = de.path();
        std::uint64_t sz = pqnas::file_size_u64_safe(abs);

        // build relative name within the selected directory
        std::filesystem::path rel_inside = std::filesystem::relative(abs, base, ec);
        if (ec) { ec.clear(); continue; }

        std::string name = zip_root.empty()
            ? rel_inside.string()
            : (zip_root + "/" + rel_inside.string());

        name = zip_sanitize_relpath(name);
        if (name.empty()) continue;

        ZipFileItem z;
        z.abs_path = abs;
        z.zip_name = name;
        z.size_u64 = sz;

        std::uint16_t dt=0, dd=0;
        zip_dos_time_date(de.last_write_time(ec), dt, dd);
        if (ec) ec.clear();
        z.dos_time = dt;
        z.dos_date = dd;

        items.push_back(std::move(z));
        total_payload += sz;
    }

    if (ec) {
        audit_fail("iter_failed", 500, ec.message());
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to enumerate directory"}
        }.dump());
        return;
    }

    if (items.empty()) {
        // Allow empty zips (valid), but still produce something useful.
        // We'll return a small zip with no entries.
    }

    // Sort stable by name for deterministic output
    std::sort(items.begin(), items.end(), [](const ZipFileItem& a, const ZipFileItem& b){
        return a.zip_name < b.zip_name;
    });

    // Compute total zip size (exact, ZIP32)
    ZipTotals totals = zip_compute_totals(items);
    const std::uint64_t zip_bytes = totals.total_bytes;

    if (zip_bytes > 0xFFFFFFFFull) {
        audit_fail("zip_too_large_zip32", 413);
        reply_json(res, 413, json{
            {"ok", false},
            {"error", "too_large"},
            {"message", "directory too large for zip (zip32 limit)"}
        }.dump());
        return;
    }

    // Build filename
    std::string out_name = zip_basename(abs_dir) + ".zip";

    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Type", "application/zip");
    res.set_header("Content-Length", std::to_string((unsigned long long)zip_bytes));
    res.set_header("Content-Disposition", std::string("attachment; filename=\"") + out_name + "\"");

    auto streamer = std::make_shared<ZipStreamer>(std::move(items), totals);

    res.set_content_provider(
        (size_t)zip_bytes,
        "application/zip",
        [streamer](size_t offset, size_t length, httplib::DataSink& sink) mutable {
            return streamer->emit(offset, length, sink);
        },
        [streamer](bool /*success*/) mutable {
            // nothing to close; files are opened/closed per entry inside streamer
        }
    );

    audit_ok(rel_path, zip_bytes);
});


// GET /api/v4/files/get?path=relative/path.bin
// Response: raw bytes (streams file)
srv.Get("/api/v4/files/get", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role)) return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_get_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_ok = [&](const std::string& rel_path, std::uint64_t bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_get_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);
        ev.f["bytes"] = std::to_string((unsigned long long)bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    // path param
    std::string rel_path;
    if (req.has_param("path")) rel_path = req.get_param_value("path");
    if (rel_path.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // Must be allocated (fail-closed)
    {
        auto uopt = users.get(fp_hex);
        if (!uopt.has_value()) {
            audit_fail("user_missing", 403);
            reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "policy denied"}}.dump());
            return;
        }
        const auto& u = *uopt;
        if (u.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403);
            reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Storage not allocated"},
                {"fingerprint_hex", fp_hex},
                {"quota_bytes", u.quota_bytes}
            }.dump());
            return;
        }
    }

    // Resolve file path strictly under user dir
    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);
    std::filesystem::path abs;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(user_dir, rel_path, &abs, &perr)) {
        audit_fail("invalid_path", 400, perr);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid path"}
        }.dump());
        return;
    }

    // Validate exists + regular + size
    std::error_code ec;
    auto st = std::filesystem::status(abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404);
        reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "file not found"}
        }.dump());
        return;
    }
    if (!std::filesystem::is_regular_file(st)) {
        audit_fail("not_regular_file", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "not a regular file"}
        }.dump());
        return;
    }

    const std::uint64_t sz = pqnas::file_size_u64_safe(abs);

    // Stream it
    auto fp = std::make_shared<std::ifstream>(abs, std::ios::binary);
    if (!fp->good()) {
        audit_fail("open_failed", 500);
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to open file"}
        }.dump());
        return;
    }

    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Type", "application/octet-stream");
    res.set_header("Content-Length", std::to_string((unsigned long long)sz));

    // Optional: browser-friendly filename (safe-ish: just basename)
    res.set_header("Content-Disposition",
                   std::string("attachment; filename=\"") + abs.filename().string() + "\"");

    // httplib content provider: called repeatedly until it returns false
    res.set_content_provider(
        (size_t)sz,
        "application/octet-stream",
        [fp](size_t /*offset*/, size_t length, httplib::DataSink& sink) mutable {
            std::string buf;
            buf.resize(length);

            fp->read(buf.data(), (std::streamsize)length);
            std::streamsize n = fp->gcount();
            if (n > 0) sink.write(buf.data(), (size_t)n);

            return n > 0; // false ends the stream
        },
        [fp](bool /*success*/) mutable {
            if (fp && fp->is_open()) fp->close();
        }
    );


    audit_ok(rel_path, sz);
});

// ---- Files API (user storage) ----
// PUT /api/v4/files/put?path=relative/path.bin
// Body: raw bytes (entire file)
srv.Put("/api/v4/files/put", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role)) return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };

    auto header_u64 = [&](const char* name, std::uint64_t* out) -> bool {
        if (!out) return false;
        auto it = req.headers.find(name);
        if (it == req.headers.end()) return false;
        const std::string& s = it->second;
        try {
            size_t idx = 0;
            unsigned long long v = std::stoull(s, &idx, 10);
            if (idx != s.size()) return false;
            *out = (std::uint64_t)v;
            return true;
        } catch (...) {
            return false;
        }
    };

    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_put_fail";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
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

    auto audit_quota_deny = [&](const std::string& rel_path, const pqnas::QuotaCheckResult& qc) {
        pqnas::AuditEvent ev;
        ev.event = "user_storage_quota_exceeded";
        ev.outcome = "deny";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);

        ev.f["used_bytes"] = std::to_string((unsigned long long)qc.used_bytes);
        ev.f["quota_bytes"] = std::to_string((unsigned long long)qc.quota_bytes);
        ev.f["incoming_bytes"] = std::to_string((unsigned long long)qc.incoming_bytes);
        ev.f["existing_bytes"] = std::to_string((unsigned long long)qc.existing_bytes);
        ev.f["would_used_bytes"] = std::to_string((unsigned long long)qc.would_used_bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };


    auto audit_ok = [&](const std::string& rel_path, std::uint64_t bytes) {
        pqnas::AuditEvent ev;
        ev.event = "v4.files_put_ok";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["path"] = pqnas::shorten(rel_path, 200);
        ev.f["bytes"] = std::to_string((unsigned long long)bytes);

        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

        ev.f["ua"] = audit_ua();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };


    // path param
    std::string rel_path;
    if (req.has_param("path")) rel_path = req.get_param_value("path");
    if (rel_path.empty()) {
        audit_fail("missing_path", 400);
        reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing path"}
        }.dump());
        return;
    }

    // incoming bytes: prefer Content-Length if present, but sanity-check vs req.body.size()
    std::uint64_t incoming_bytes = (std::uint64_t)req.body.size();
    std::uint64_t cl = 0;
    if (header_u64("Content-Length", &cl)) {
        // Fail-closed if mismatch (proxy/client bug)
        if (cl != (std::uint64_t)req.body.size()) {
            audit_fail("content_length_mismatch", 400,
                       "Content-Length=" + std::to_string((unsigned long long)cl) +
                       " body=" + std::to_string((unsigned long long)req.body.size()));
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "Content-Length mismatch"},
                {"content_length", cl},
                {"body_bytes", (std::uint64_t)req.body.size()}
            }.dump());
            return;
        }
        incoming_bytes = cl;
    }

    // quota + path resolve
    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);
    pqnas::QuotaCheckResult qc = pqnas::quota_check_for_upload_v1(
        users, fp_hex, user_dir, rel_path, incoming_bytes
    );

    if (!qc.ok) {
        if (qc.error == "storage_unallocated") {
            reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Storage not allocated"},
                {"fingerprint_hex", fp_hex},
                {"quota_bytes", qc.quota_bytes},
                {"incoming_bytes", qc.incoming_bytes}
            }.dump());
            return;
        }
        if (qc.error == "invalid_path") {
            audit_fail("invalid_path", 400);
            reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }
        if (qc.error == "quota_exceeded") {
            audit_quota_deny(rel_path, qc);
            reply_json(res, 413, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "User quota exceeded"},
                {"fingerprint_hex", fp_hex},
                {"used_bytes", qc.used_bytes},
                {"quota_bytes", qc.quota_bytes},
                {"incoming_bytes", qc.incoming_bytes},
                {"existing_bytes", qc.existing_bytes},
                {"would_used_bytes", qc.would_used_bytes}
            }.dump());
            return;
        }
        audit_fail("quota_check_failed", 403, qc.error);
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "policy denied"}
        }.dump());
        return;
    }

    const std::filesystem::path out_abs = qc.abs_path;

    // Ensure parent directory exists
    {
        std::error_code ec;
        std::filesystem::create_directories(out_abs.parent_path(), ec);
        if (ec) {
            audit_fail("mkdir_failed", 500, ec.message());
            reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create directories"},
                {"detail", pqnas::shorten(ec.message(), 180)}
            }.dump());
            return;
        }
    }

    // Temp write + rename
    const std::filesystem::path tmp =
        out_abs.parent_path() /
        (out_abs.filename().string() + ".upload." + random_b64url(8) + ".tmp");

    try {
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f.good()) throw std::runtime_error("open tmp failed");
            if (!req.body.empty())
                f.write(req.body.data(), (std::streamsize)req.body.size());
            f.flush();
            if (!f.good()) throw std::runtime_error("write tmp failed");
        }

        std::error_code ec;
        std::filesystem::rename(tmp, out_abs, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            throw std::runtime_error(std::string("rename failed: ") + ec.message());
        }

        audit_ok(rel_path, incoming_bytes);

        reply_json(res, 200, json{
            {"ok", true},
            {"fingerprint_hex", fp_hex},
            {"path", rel_path},
            {"bytes", incoming_bytes}
        }.dump());
        return;

    } catch (const std::exception& e) {
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        audit_fail("write_failed", 500, e.what());
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "upload failed"},
            {"detail", pqnas::shorten(e.what(), 180)}
        }.dump());
        return;
    }
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

    srv.Post("/api/v4/apps/upload_install", [&](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

        auto reply = [&](int status, const json& j) {
            res.status = status;
            res.set_header("Cache-Control", "no-store");
            res.set_content(j.dump(2), "application/json; charset=utf-8");
        };

        const std::string ct = req.get_header_value("Content-Type");
        const std::string origName = req.get_header_value("X-PQNAS-Filename");

        auto audit_fail = [&](const std::string& why) {
            pqnas::AuditEvent ev;
            ev.event = "admin.apps_upload_install";
            ev.outcome = "fail";
            if (!origName.empty()) ev.f["src"] = pqnas::shorten(origName, 160);
            ev.f["why"] = pqnas::shorten(why, 180);
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            ev.f["ts"] = now_iso_utc();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        };

        if (ct.find("application/zip") == std::string::npos &&
            ct.find("application/octet-stream") == std::string::npos) {
            audit_fail("expected application/zip");
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "expected Content-Type: application/zip"}});
            return;
        }

    std::error_code ec;

    // Write uploaded zip to temp file
    const std::filesystem::path tmpZip =
        std::filesystem::path(APPS_INSTALLED_DIR) / (".tmp_upload_" + rand_hex_16() + ".zip");

    {
        std::filesystem::create_directories(tmpZip.parent_path(), ec);
        if (ec) {
            reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to create temp dir"}});
            return;
        }

        std::ofstream f(tmpZip, std::ios::binary);
        if (!f.good()) {
            audit_fail("failed to open temp zip for write");
            reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to open temp zip for write"}});
            return;
        }
        f.write(req.body.data(), (std::streamsize)req.body.size());
        f.close();
        if (!f.good()) {
            std::filesystem::remove(tmpZip, ec);
            audit_fail("failed to write temp zip");
            reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to write temp zip"}});
            return;
        }
    }

    auto cleanupZip = [&]() {
        std::filesystem::remove(tmpZip, ec);
    };

    // Zip-slip defense: list entries and validate names
    {
        std::string listing;
        int rc = -1;
        const std::string cmd = "unzip -Z1 \"" + tmpZip.string() + "\" 2>/dev/null";
        if (!run_cmd_capture(cmd, &listing, &rc) || rc != 0 || listing.empty()) {
            audit_fail("zip unreadable or empty");
            cleanupZip();
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip unreadable or empty"}});
            return;
        }


        std::istringstream iss(listing);
        std::string line;
        int count = 0;
        while (std::getline(iss, line)) {
            if (line.empty()) continue;
            count++;
            if (count > 2000) { // sanity limit
                audit_fail("zip has too many entries");
                cleanupZip();
                reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip has too many entries"}});
                return;
            }

            // Reject absolute paths or Windows-style
            if (!line.empty() && (line[0] == '/' || line[0] == '\\')) {
                audit_fail("zip contains unsafe paths");
                cleanupZip();
                reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip contains unsafe paths"}});
                return;
            }
            if (line.find('\\') != std::string::npos) {
                audit_fail("zip contains unsafe paths");
                cleanupZip();
                reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip contains unsafe paths"}});
                return;
            }

            // Reject .. segments
            // (handles "../x", "a/../b", etc.)
            if (line == ".." || line.rfind("../", 0) == 0 || line.find("/../") != std::string::npos ||
                (line.size() >= 3 && line.compare(line.size()-3, 3, "/..") == 0)) {
                audit_fail("zip contains path traversal");
                cleanupZip();
                reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip contains path traversal"}});
                return;
            }
        }
    }

    // Read manifest.json from zip
    std::string manifest_txt;
    {
        std::string out;
        int rc = -1;
        const std::string cmd = "unzip -p \"" + tmpZip.string() + "\" manifest.json 2>/dev/null";
        if (!run_cmd_capture(cmd, &out, &rc) || rc != 0 || out.empty()) {
            cleanupZip();
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest.json missing or unreadable in zip"}});
            return;
        }
        manifest_txt = out;
    }

    json mani;
    try { mani = json::parse(manifest_txt); }
    catch (...) {
        cleanupZip();
        audit_fail("manifest.json is not valid json");
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest.json is not valid json"}});
        return;
    }

    const std::string id  = mani.value("id", "");
    const std::string ver = mani.value("version", "");
    if (!safe_app_id(id) || ver.empty() || ver.size() > 64) {
        cleanupZip();
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest id/version invalid"}});
        return;
    }

    const std::filesystem::path dst = std::filesystem::path(APPS_INSTALLED_DIR) / id / ver;
    if (std::filesystem::exists(dst, ec) && !ec) {
        cleanupZip();
        audit_fail("version already installed");
        reply(409, {{"ok", false}, {"error", "conflict"}, {"message", "version already installed (remove first)"}});
        return;
    }

    // Extract to temp dir under apps/installed
    const std::filesystem::path tmp =
        std::filesystem::path(APPS_INSTALLED_DIR) / (".tmp_install_" + id + "_" + rand_hex_16());

    std::filesystem::create_directories(tmp, ec);
    if (ec) {
        audit_fail("failed to create temp dir");
        cleanupZip();
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to create temp dir"}});
        return;
    }

    // unzip into temp
    {
        std::string out;
        int rc = -1;
        const std::string cmd = "unzip -q \"" + tmpZip.string() + "\" -d \"" + tmp.string() + "\" 2>/dev/null";
        if (!run_cmd_capture(cmd, &out, &rc) || rc != 0) {
            std::filesystem::remove_all(tmp, ec);
            cleanupZip();
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "failed to extract zip"}});
            return;
        }
    }

    // Required structure
    if (!std::filesystem::exists(tmp / "manifest.json", ec) || ec ||
        !std::filesystem::exists(tmp / "www" / "index.html", ec) || ec) {
        std::filesystem::remove_all(tmp, ec);
        cleanupZip();
        audit_fail("zip missing required files");
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip missing required files (manifest.json, www/index.html)"}});
        return;
    }

    std::filesystem::create_directories(dst.parent_path(), ec);
    if (ec) {
        std::filesystem::remove_all(tmp, ec);
        cleanupZip();
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to create destination dir"}});
        return;
    }

    std::filesystem::rename(tmp, dst, ec);
    if (ec) {
        std::filesystem::remove_all(tmp, ec);
        cleanupZip();
        audit_fail("failed to finalize install");
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to finalize install"}});
        return;
    }

    cleanupZip();
        {
            pqnas::AuditEvent ev;
            ev.event = "admin.apps_upload_install";
            ev.outcome = "ok";
            ev.f["id"] = id;
            ev.f["version"] = ver;
            if (!origName.empty()) ev.f["src"] = pqnas::shorten(origName, 160);
            ev.f["bytes"] = std::to_string(req.body.size());
            ev.f["ip"] = client_ip(req);
            ev.f["ts"] = now_iso_utc();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }

    reply(200, {{"ok", true}, {"id", id}, {"version", ver}, {"root", rel_to_repo(dst.string())}, {"src", origName}});
});

srv.Post("/api/v4/apps/install_bundled", [&](const httplib::Request& req, httplib::Response& res) {
    auto reply = [&](int status, const json& j) {
        res.status = status;
        res.set_header("Cache-Control", "no-store");
        res.set_content(j.dump(2), "application/json; charset=utf-8");
    };
    //only admins can install apps
    if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

    auto audit_fail = [&](const std::string& why) {
        pqnas::AuditEvent ev;
        ev.event = "admin.apps_install_bundled";
        ev.outcome = "fail";
        ev.f["why"] = pqnas::shorten(why, 180);
        ev.f["ip"] = client_ip(req);
        ev.f["ts"] = now_iso_utc();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    json in;
    try { in = json::parse(req.body); }
    catch (...) {
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "invalid json"}});
        return;
    }

    const std::string id  = in.value("id", "");
    const std::string zip = in.value("zip", "");

    if (!safe_app_id(id) || zip.empty() ||
        zip.find('/') != std::string::npos || zip.find('\\') != std::string::npos) {
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "bad id or zip"}});
        return;
    }

    std::error_code ec;
    const std::filesystem::path zip_path = std::filesystem::path(APPS_BUNDLED_DIR) / id / zip;

    if (!std::filesystem::exists(zip_path, ec) || ec) {
        reply(404, {{"ok", false}, {"error", "not_found"}, {"message", "bundled zip not found"}});
        return;
    }

    // Read manifest.json from zip
    std::string manifest_txt;
    int code = -1;
    {
        const std::string cmd = "unzip -p \"" + zip_path.string() + "\" manifest.json 2>/dev/null";
        if (!run_cmd_capture(cmd, &manifest_txt, &code) || code != 0 || manifest_txt.empty()) {
            audit_fail("manifest.json missing or unreadable in zip");
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest.json missing or unreadable in zip"}});
            return;
        }
    }

    json mani;
    try { mani = json::parse(manifest_txt); }
    catch (...) {
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest.json is not valid json"}});
        return;
    }

    const std::string mid = mani.value("id", "");
    const std::string ver = mani.value("version", "");

    if (mid != id || !safe_app_id(mid) || ver.empty() || ver.size() > 64) {
        audit_fail("manifest id/version invalid");
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "manifest id/version invalid or mismatch"}});
        return;
    }

    const std::filesystem::path dst = std::filesystem::path(APPS_INSTALLED_DIR) / id / ver;
    if (std::filesystem::exists(dst, ec) && !ec) {
        reply(409, {{"ok", false}, {"error", "conflict"}, {"message", "version already installed (remove first)"}});
        return;
    }

    // Extract to temp dir under apps/installed
    const std::filesystem::path tmp =
        std::filesystem::path(APPS_INSTALLED_DIR) / (".tmp_install_" + id + "_" + rand_hex_16());

    std::filesystem::create_directories(tmp, ec);
    if (ec) {
        audit_fail("failed to create temp dir");
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to create temp dir"}});
        return;
    }

    // unzip into temp
    {
        const std::string cmd = "unzip -q \"" + zip_path.string() + "\" -d \"" + tmp.string() + "\" 2>/dev/null";
        std::string out;
        int rc = -1;
        if (!run_cmd_capture(cmd, &out, &rc) || rc != 0) {
            std::filesystem::remove_all(tmp, ec);
            audit_fail("failed to extract zip");
            reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "failed to extract zip"}});
            return;
        }
    }

    // Required structure
    if (!std::filesystem::exists(tmp / "manifest.json", ec) || ec ||
        !std::filesystem::exists(tmp / "www" / "index.html", ec) || ec) {
        std::filesystem::remove_all(tmp, ec);
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "zip missing required files (manifest.json, www/index.html)"}});
        return;
    }

    std::filesystem::create_directories(dst.parent_path(), ec);
    if (ec) {
        std::filesystem::remove_all(tmp, ec);
        audit_fail("failed to create destination dir");
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to create destination dir"}});
        return;
    }

    std::filesystem::rename(tmp, dst, ec);
    if (ec) {
        std::filesystem::remove_all(tmp, ec);
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to finalize install"}});
        return;
    }

    reply(200, {{"ok", true}, {"id", id}, {"version", ver}, {"root", rel_to_repo(dst.string())}});
});


srv.Post("/api/v4/apps/uninstall", [&](const httplib::Request& req, httplib::Response& res) {
    auto reply = [&](int status, const json& j) {
        res.status = status;
        res.set_header("Cache-Control", "no-store");
        res.set_content(j.dump(2), "application/json; charset=utf-8");
    };

    // only admins can uninstall apps
    if (!require_admin_cookie(req, res, COOKIE_KEY, allowlist_path, &allowlist)) return;

    json in;
    try { in = json::parse(req.body); }
    catch (...) {
        // audit (fail)
        {
            pqnas::AuditEvent ev;
            ev.event = "admin.apps_uninstall";
            ev.outcome = "fail";
            ev.f["why"] = "invalid json";
            ev.f["ip"] = client_ip(req);
            ev.f["ts"] = now_iso_utc();
            maybe_auto_rotate_before_append();
            audit_append(ev);
        }
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "invalid json"}});
        return;
    }

    const std::string id  = in.value("id", "");
    const std::string ver = in.value("version", "");

    auto audit_fail = [&](const std::string& why) {
        pqnas::AuditEvent ev;
        ev.event = "admin.apps_uninstall";
        ev.outcome = "fail";
        if (!id.empty())  ev.f["id"] = id;
        if (!ver.empty()) ev.f["version"] = ver;
        ev.f["why"] = pqnas::shorten(why, 180);
        ev.f["ip"] = client_ip(req);
        ev.f["ts"] = now_iso_utc();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    auto audit_ok = [&]() {
        pqnas::AuditEvent ev;
        ev.event = "admin.apps_uninstall";
        ev.outcome = "ok";
        ev.f["id"] = id;
        ev.f["version"] = ver;
        ev.f["ip"] = client_ip(req);
        ev.f["ts"] = now_iso_utc();
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    if (!safe_app_id(id) || ver.empty() || ver.size() > 64) {
        audit_fail("bad id or version");
        reply(400, {{"ok", false}, {"error", "bad_request"}, {"message", "bad id or version"}});
        return;
    }

    std::error_code ec;
    const std::filesystem::path dst = std::filesystem::path(APPS_INSTALLED_DIR) / id / ver;

    if (!std::filesystem::exists(dst, ec) || ec) {
        audit_fail("not installed");
        reply(404, {{"ok", false}, {"error", "not_found"}, {"message", "not installed"}});
        return;
    }

    std::filesystem::remove_all(dst, ec);
    if (ec) {
        audit_fail(std::string("failed to remove app: ") + ec.message());
        reply(500, {{"ok", false}, {"error", "server_error"}, {"message", "failed to remove app"}});
        return;
    }

    // Optional: remove empty appId dir
    const std::filesystem::path appDir = std::filesystem::path(APPS_INSTALLED_DIR) / id;
    if (std::filesystem::exists(appDir, ec) && std::filesystem::is_directory(appDir, ec)) {
        bool empty = (std::filesystem::directory_iterator(appDir, ec) == std::filesystem::directory_iterator());
        if (!ec && empty) std::filesystem::remove(appDir, ec);
    }

    audit_ok();
    reply(200, {{"ok", true}, {"id", id}, {"version", ver}});
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



    srv.Post("/api/v4/shares/create", [&](const httplib::Request& req, httplib::Response& res) {
    auto reply = [&](int status, const json& j) {
        res.status = status;
        res.set_header("Cache-Control", "no-store");
        res.set_content(j.dump(2), "application/json; charset=utf-8");
    };

    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };
    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);
        ev.f["ua"] = audit_ua();
    };
    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& path_rel = "") {
        pqnas::AuditEvent ev;
        ev.event = "share_create";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!path_rel.empty()) ev.f["path"] = pqnas::shorten(path_rel, 200);
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);
        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };
    auto audit_ok = [&](const pqnas::ShareLink& s) {
        pqnas::AuditEvent ev;
        ev.event = "share_create";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["token"] = pqnas::shorten(s.token, 32);
        ev.f["owner_fp"] = s.owner_fp;
        ev.f["path"] = pqnas::shorten(s.path, 200);
        ev.f["type"] = s.type;
        if (!s.expires_at.empty()) ev.f["expires_at"] = s.expires_at;
        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    if (role != "admin") {
        audit_fail("not_admin", 403);
        reply(403, json{{"ok", false}, {"error", "not_authorized"}, {"message", "Admin required"}});
        return;
    }

    // Parse body: { "path": "<rel>", "expires_sec": 86400 }
    json body;
    try { body = json::parse(req.body.empty() ? "{}" : req.body); }
    catch (const std::exception& e) {
        audit_fail("json_parse", 400, e.what());
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "invalid json"}});
        return;
    }
    if (!body.is_object() || !body.contains("path") || !body["path"].is_string()) {
        audit_fail("missing_path", 400);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing path"}});
        return;
    }

    std::string path_rel = body["path"].get<std::string>();
    for (char& c : path_rel) if (c == '\\') c = '/';
    while (!path_rel.empty() && path_rel[0] == '/') path_rel.erase(path_rel.begin());
    while (path_rel.size() > 1 && path_rel.back() == '/') path_rel.pop_back();

    // basic safety: reject '-' and CRLF
    if (path_rel.empty() || path_rel[0] == '-' ||
        path_rel.find('\n') != std::string::npos || path_rel.find('\r') != std::string::npos) {
        audit_fail("invalid_path", 400, "bad chars", path_rel);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "invalid path"}});
        return;
    }

    // Optional expires_sec
    long long expires_sec = 0;
    if (body.contains("expires_sec")) {
        try {
            if (body["expires_sec"].is_number_integer()) expires_sec = body["expires_sec"].get<long long>();
            else if (body["expires_sec"].is_string()) expires_sec = std::stoll(body["expires_sec"].get<std::string>());
        } catch (...) {}
    }
    if (expires_sec < 0) expires_sec = 0;

    // must have allocated storage (owner is the current user in v1)
    auto uopt = users.get(fp_hex);
    if (!uopt.has_value() || uopt->storage_state != "allocated") {
        audit_fail("storage_unallocated", 403, "", path_rel);
        reply(403, json{{"ok", false}, {"error", "storage_unallocated"}, {"message", "Storage not allocated"}});
        return;
    }

    const std::filesystem::path user_dir = user_dir_for_fp(fp_hex);

    // Resolve path strictly using your existing safe resolver
    std::filesystem::path abs;
    std::string rerr;
    if (!pqnas::resolve_user_path_strict(user_dir, path_rel, &abs, &rerr)) {
        audit_fail("invalid_path", 400, rerr, path_rel);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "invalid path"}});
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        audit_fail("not_found", 404, "", path_rel);
        reply(404, json{{"ok", false}, {"error", "not_found"}, {"message", "path not found"}});
        return;
    }
    if (std::filesystem::is_symlink(st)) {
        audit_fail("symlink_not_supported", 400, "", path_rel);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "symlinks not supported"}});
        return;
    }

    std::string type = std::filesystem::is_directory(st) ? "dir" : (std::filesystem::is_regular_file(st) ? "file" : "");
    if (type.empty()) {
        audit_fail("unsupported_type", 400, "", path_rel);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "unsupported path type"}});
        return;
    }

    pqnas::ShareLink out;
    std::string err;
    if (!shares.create(fp_hex, path_rel, type, expires_sec, &out, &err)) {
        audit_fail("create_failed", 500, err, path_rel);
        reply(500, json{{"ok", false}, {"error", "server_error"}, {"message", "share create failed"}});
        return;
    }

    audit_ok(out);

    reply(200, json{
        {"ok", true},
        {"token", out.token},
        {"url", std::string("/s/") + out.token},
        {"expires_at", out.expires_at.empty() ? json() : json(out.expires_at)},
        {"type", out.type},
        {"path", out.path}
    });
});


    srv.Post("/api/v4/shares/revoke", [&](const httplib::Request& req, httplib::Response& res) {
    auto reply = [&](int status, const json& j) {
        res.status = status;
        res.set_header("Cache-Control", "no-store");
        res.set_content(j.dump(2), "application/json; charset=utf-8");
    };

    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };
    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);
        ev.f["ua"] = audit_ua();
    };
    auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "",
                          const std::string& token_short = "") {
        pqnas::AuditEvent ev;
        ev.event = "share_revoke";
        ev.outcome = "fail";
        ev.f["fingerprint"] = fp_hex;
        ev.f["reason"] = reason;
        ev.f["http"] = std::to_string(http);
        if (!token_short.empty()) ev.f["token"] = token_short;
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);
        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };
    auto audit_ok = [&](const std::string& token_short) {
        pqnas::AuditEvent ev;
        ev.event = "share_revoke";
        ev.outcome = "ok";
        ev.f["fingerprint"] = fp_hex;
        ev.f["token"] = token_short;
        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    if (role != "admin") {
        audit_fail("not_admin", 403);
        reply(403, json{{"ok", false}, {"error", "not_authorized"}, {"message", "Admin required"}});
        return;
    }

    json body;
    try { body = json::parse(req.body.empty() ? "{}" : req.body); }
    catch (const std::exception& e) {
        audit_fail("json_parse", 400, e.what());
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "invalid json"}});
        return;
    }

    if (!body.is_object() || !body.contains("token") || !body["token"].is_string()) {
        audit_fail("missing_token", 400);
        reply(400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing token"}});
        return;
    }

    std::string token = body["token"].get<std::string>();
    std::string token_short = pqnas::shorten(token, 32);

    std::string err;
    bool removed = shares.revoke(token, &err);
    if (!removed) {
        // If err set => save failed; else token not found
        if (!err.empty()) {
            audit_fail("revoke_failed", 500, err, token_short);
            reply(500, json{{"ok", false}, {"error", "server_error"}, {"message", "share revoke failed"}});
        } else {
            audit_fail("not_found", 404, "", token_short);
            reply(404, json{{"ok", false}, {"error", "not_found"}, {"message", "token not found"}});
        }
        return;
    }

    audit_ok(token_short);
    reply(200, json{{"ok", true}});
});


    srv.Get("/api/v4/shares/list", [&](const httplib::Request& req, httplib::Response& res) {
    std::string fp_hex, role;
    if (!require_user_cookie_users_actor(req, res, COOKIE_KEY, &users, &fp_hex, &role))
        return;

    if (role != "admin") {
        res.status = 403;
        res.set_header("Cache-Control", "no-store");
        res.set_content(json{{"ok",false},{"error","not_authorized"},{"message","Admin required"}}.dump(2),
                        "application/json; charset=utf-8");
        return;
    }

    auto v = shares.list();

    json out;
    out["ok"] = true;
    out["shares"] = json::array();
    for (const auto& s : v) {
        json it;
        it["token"] = s.token;
        it["url"] = std::string("/s/") + s.token;
        it["owner_fp"] = s.owner_fp;
        it["path"] = s.path;
        it["type"] = s.type;
        it["created_at"] = s.created_at;
        if (!s.expires_at.empty()) it["expires_at"] = s.expires_at;
        it["downloads"] = s.downloads;
        out["shares"].push_back(std::move(it));
    }

    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_content(out.dump(2), "application/json; charset=utf-8");
});
    // Public share download: GET /s/<token>
srv.Get(R"(/s/([A-Za-z0-9_-]+))", [&](const httplib::Request& req, httplib::Response& res) {
    const std::string token = req.matches[1].str();

    auto audit_ua = [&]() -> std::string {
        auto it = req.headers.find("User-Agent");
        return pqnas::shorten(it == req.headers.end() ? "" : it->second);
    };
    auto add_ip_headers = [&](pqnas::AuditEvent& ev) {
        ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);
        ev.f["ua"] = audit_ua();
    };

    auto audit_event = [&](const std::string& name,
                           const std::string& outcome,
                           const pqnas::ShareLink* s,
                           const std::string& reason = "",
                           int http = 0,
                           const std::string& detail = "") {
        pqnas::AuditEvent ev;
        ev.event = name;
        ev.outcome = outcome;
        ev.f["token"] = pqnas::shorten(token, 32);
        if (http) ev.f["http"] = std::to_string(http);
        if (!reason.empty()) ev.f["reason"] = reason;
        if (!detail.empty()) ev.f["detail"] = pqnas::shorten(detail, 180);
        if (s) {
            ev.f["owner_fp"] = s->owner_fp;
            ev.f["path"] = pqnas::shorten(s->path, 200);
            ev.f["type"] = s->type;
            if (!s->expires_at.empty()) ev.f["expires_at"] = s->expires_at;
        }
        add_ip_headers(ev);
        maybe_auto_rotate_before_append();
        audit_append(ev);
    };

    pqnas::ShareLink s;
    std::string err;
    auto valid = shares.is_valid_now(token, &s, &err);

    if (!valid.has_value()) {
        audit_event("share_download", "fail", nullptr, "not_found", 404);
        res.status = 404;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Not found\n", "text/plain; charset=utf-8");
        return;
    }

    if (valid.value() == false) {
        // expired
        audit_event("share_expired", "ok", &s, "expired", 410);
        audit_event("share_download", "fail", &s, "expired", 410);

        res.status = 410;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Expired\n", "text/plain; charset=utf-8");
        return;
    }

    // Resolve to disk
    const std::filesystem::path user_dir = user_dir_for_fp(s.owner_fp);

    std::filesystem::path abs;
    std::string rerr;
    if (!pqnas::resolve_user_path_strict(user_dir, s.path, &abs, &rerr)) {
        audit_event("share_download", "fail", &s, "invalid_path", 400, rerr);
        res.status = 404; // safer: do not leak
        res.set_header("Cache-Control", "no-store");
        res.set_content("Not found\n", "text/plain; charset=utf-8");
        return;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs, ec);
    if (ec || !std::filesystem::exists(st) || std::filesystem::is_symlink(st)) {
        audit_event("share_download", "fail", &s, "not_found", 404);
        res.status = 404;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Not found\n", "text/plain; charset=utf-8");
        return;
    }

    // Optional: enforce stored type matches on-disk type
    if (s.type == "file" && !std::filesystem::is_regular_file(st)) {
        audit_event("share_download", "fail", &s, "type_mismatch", 404);
        res.status = 404;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Not found\n", "text/plain; charset=utf-8");
        return;
    }
    if (s.type == "dir" && !std::filesystem::is_directory(st)) {
        audit_event("share_download", "fail", &s, "type_mismatch", 404);
        res.status = 404;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Not found\n", "text/plain; charset=utf-8");
        return;
    }

    // Serve
    if (s.type == "file") {
        // Stream file (simple v1: read to memory; if you already have a streaming helper, use it)
        std::ifstream f(abs, std::ios::binary);
        if (!f.good()) {
            audit_event("share_download", "fail", &s, "open_failed", 500);
            res.status = 500;
            res.set_header("Cache-Control", "no-store");
            res.set_content("Server error\n", "text/plain; charset=utf-8");
            return;
        }
        std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        audit_event("share_download", "ok", &s, "", 200);
        (void)shares.increment_downloads(token, &err); // best effort

        std::string fname = std::filesystem::path(s.path).filename().string();
        if (fname.empty()) fname = "download";

        res.status = 200;
        res.set_header("Cache-Control", "no-store");
        res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
        res.set_content(std::move(data), "application/octet-stream");
        return;
    }

    // s.type == "dir" -> zip directory (reuse your existing in-memory zip style)
    // For v1, we zip the directory root as "<dirname>/..." like your /api/v4/files/zip does.
    // We also reject symlinks inside, same rule as your zip endpoints.

    // Pre-walk: check symlinks + count bytes (reuse your helper pqnas::file_size_u64_safe)
    std::uint64_t input_bytes = 0;
    std::uint64_t files = 0, dirs = 0;

    dirs = 1;
    {
        std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;
        ec.clear();
        for (auto it = std::filesystem::recursive_directory_iterator(abs, opts, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {

            if (ec) {
                audit_event("share_download", "fail", &s, "walk_failed", 500, ec.message());
                res.status = 500;
                res.set_header("Cache-Control", "no-store");
                res.set_content("Server error\n", "text/plain; charset=utf-8");
                return;
            }

            std::error_code ec2;
            auto st2 = it->symlink_status(ec2);
            if (ec2) continue;

            if (std::filesystem::is_symlink(st2)) {
                audit_event("share_download", "fail", &s, "symlink_not_supported", 400, "symlink inside tree");
                res.status = 400;
                res.set_header("Cache-Control", "no-store");
                res.set_content("Bad request\n", "text/plain; charset=utf-8");
                return;
            }

            if (std::filesystem::is_directory(st2)) { dirs += 1; continue; }
            if (std::filesystem::is_regular_file(st2)) {
                files += 1;
                input_bytes += pqnas::file_size_u64_safe(it->path());
                continue;
            }

            files += 1;
        }
    }

    // Run: zip -r -q - <dirname> in cwd=user_dir, referencing relpath (s.path)
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        audit_event("share_download", "fail", &s, "pipe_failed", 500, "pipe()");
        res.status = 500;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Server error\n", "text/plain; charset=utf-8");
        return;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]); ::close(pipefd[1]);
        audit_event("share_download", "fail", &s, "fork_failed", 500, "fork()");
        res.status = 500;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Server error\n", "text/plain; charset=utf-8");
        return;
    }

    if (pid == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);

        if (::chdir(user_dir.c_str()) != 0) _exit(127);

        const char* argv[] = {
            "zip",
            "-r",
            "-q",
            "-",
            s.path.c_str(),
            nullptr
        };
        ::execvp("zip", (char* const*)argv);
        _exit(127);
    }

    ::close(pipefd[1]);

    std::string zip_data;
    zip_data.reserve(4ull * 1024 * 1024);

    std::array<char, 64 * 1024> buf{};
    while (true) {
        ssize_t n = ::read(pipefd[0], buf.data(), (ssize_t)buf.size());
        if (n == 0) break;
        if (n < 0) {
            ::close(pipefd[0]);
            ::kill(pid, SIGKILL);
            audit_event("share_download", "fail", &s, "read_failed", 500, "read(zip)");
            res.status = 500;
            res.set_header("Cache-Control", "no-store");
            res.set_content("Server error\n", "text/plain; charset=utf-8");
            return;
        }
        zip_data.append(buf.data(), (size_t)n);
    }
    ::close(pipefd[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        audit_event("share_download", "fail", &s, "zip_failed", 500, "zip exit nonzero");
        res.status = 500;
        res.set_header("Cache-Control", "no-store");
        res.set_content("Server error\n", "text/plain; charset=utf-8");
        return;
    }

    audit_event("share_download", "ok", &s, "", 200);
    (void)shares.increment_downloads(token, &err); // best effort

    std::string base = std::filesystem::path(s.path).filename().string();
    if (base.empty()) base = "download";
    std::string fname = base + ".zip";

    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Type", "application/zip");
    res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
    res.body = std::move(zip_data);
});

    std::cerr << "PQ-NAS server listening on 0.0.0.0:" << LISTEN_PORT << std::endl;
    srv.listen("0.0.0.0", LISTEN_PORT);
    return 0;
}
