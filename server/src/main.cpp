// pqnas_server.cpp (v4 stateless QR auth) — cleaned, single-definition, buildable
// Notes:
// - Uses libsodium for Ed25519 + base64 (urlsafe + standard).
// - Uses OpenSSL SHA256 for st_hash (standard base64 with padding, to match Python).
// - Uses OpenSSL SHA3-512 for fingerprint (sha3_512(pubkey) hex lower), to match Python.
// - Loads native PQClean verifier from libdna_pq_verify.so (dna_verify_mldsa87).
// - Keeps canonical JSON rules consistent with the Python v4_tokens.py design.
//
// IMPORTANT BUILD NOTES:
// - Requires: libsodium, OpenSSL (EVP), httplib.h, policy.h, session_cookie.h, qrauth_v4.h
// - If you see EVP_* not found, ensure you include <openssl/evp.h> and link -lcrypto
//
// Debugging:
// - Everything prints to stderr with std::endl (flush) so you WILL see it in terminal.

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
#include <unordered_map>
#include <mutex>

#include "audit_log.h"
#include "audit_fields.h"
extern "C" {
#include "qrauth_v4.h"
}

#include "session_cookie.h"
#include "policy.h"

// header-only HTTP server
#include "httplib.h"

// JSON (header-only)
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// ---- config ----
static unsigned char SERVER_PK[32];
static unsigned char SERVER_SK[64];
static unsigned char COOKIE_KEY[32];



static std::string ORIGIN   = "https://nas.example.com";
static std::string ISS      = "pq-nas";
static std::string AUD      = "dna-messenger";
static std::string SCOPE    = "pqnas.login";
static std::string APP_NAME = "PQ-NAS";

// v4 app requires rp binding inside st payload
static std::string RP_ID    = "nas.example.com";  // relying party id (domain)

static int REQ_TTL  = 60;
static int SESS_TTL = 8 * 3600;
static int LISTEN_PORT = 8081; // use 8081 to avoid conflicts

static long now_epoch() { return (long)std::time(nullptr); }

struct ApprovalEntry {
    std::string cookie_val;   // pqnas_session cookie value (b64url.claims + "." + b64url.mac)
    std::string fingerprint;  // computed_fp (hex)
    long expires_at = 0;      // epoch seconds
};

static std::unordered_map<std::string, ApprovalEntry> g_approvals;
static std::mutex g_approvals_mu;

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

// -----------------------------------------------------------------------------
// Native PQ verifier loader (from libdna_lib.so)
// Symbol: qgp_dsa87_verify
// Signature (from qgp_dilithium.c):
//   int qgp_dsa87_verify(const uint8_t* sig, size_t siglen,
//                        const uint8_t* m,   size_t mlen,
//                        const uint8_t* pk);
// Returns 0 on success, non-zero on failure.
// -----------------------------------------------------------------------------

using qgp_dsa87_verify_fn = int (*)(const uint8_t* sig, size_t siglen,
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t* pk);

static qgp_dsa87_verify_fn load_qgp_dsa87_verify() {
    static void* h = nullptr;
    static qgp_dsa87_verify_fn fn = nullptr;
    if (fn) return fn;

    // Load the library that actually exports qgp_dsa87_verify
    // If you place libdna_lib.so next to the binary, use exe_dir()+"/libdna_lib.so"
    std::string libpath = exe_dir() + "/libdna_lib.so";
    h = dlopen(libpath.c_str(), RTLD_NOW);
    if (!h) throw std::runtime_error(std::string("dlopen failed: ") + libpath + " : " + dlerror());


    fn = (qgp_dsa87_verify_fn)dlsym(h, "qgp_dsa87_verify");
    if (!fn) throw std::runtime_error("dlsym failed: qgp_dsa87_verify");

    return fn;
}

static bool verify_mldsa87_signature_native(const std::vector<unsigned char>& pubkey,
                                           const std::vector<unsigned char>& msg,
                                           const std::vector<unsigned char>& sig) {
    auto fn = load_qgp_dsa87_verify();

    const int rc = fn(
        sig.data(), sig.size(),
        msg.data(), msg.size(),
        pubkey.data()
    );

    std::cerr << "[pq-verify] qgp_dsa87_verify rc=" << rc
              << " sig_len=" << sig.size()
              << " msg_len=" << msg.size()
              << " pk_len=" << pubkey.size()
              << "\n" << std::flush;

    // pqcrystals_*_verify returns 0 on success
    return (rc == 0);
}


// -----------------------------------------------------------------------------
// Base64 helpers (libsodium)
// -----------------------------------------------------------------------------
static std::vector<unsigned char> b64decode_loose(const std::string& in) {
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') s.push_back(c);
    }

    std::vector<unsigned char> out(s.size() + 8);
    size_t out_len = 0;

    auto try_variant = [&](int variant) -> bool {
        out_len = 0;
        return sodium_base642bin(out.data(), out.size(),
                                 s.c_str(), s.size(),
                                 nullptr, &out_len, nullptr,
                                 variant) == 0;
    };

    if (try_variant(sodium_base64_VARIANT_ORIGINAL) ||
        try_variant(sodium_base64_VARIANT_URLSAFE) ||
        try_variant(sodium_base64_VARIANT_URLSAFE_NO_PADDING)) {
        out.resize(out_len);
        return out;
        }

    throw std::runtime_error("invalid base64");
}

static bool read_file_to_string(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}


static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

static std::string b64_std(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

// sha256 -> standard base64 WITH padding (matches Python base64.b64encode)
static std::string sha256_b64_std_bytes(const unsigned char* data, size_t len) {
    unsigned char h[32];
    SHA256(data, len, h);
    return b64_std(h, 32);
}
static std::string sha256_b64_std_str(const std::string& s) {
    return sha256_b64_std_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
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

// -----------------------------------------------------------------------------
// Misc helpers
// -----------------------------------------------------------------------------
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
    // Encode as 8-bit to avoid surprises; EC level M is a good default.
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

    // Draw modules as black rectangles
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

static std::string get_header(const httplib::Request& req, const char* name) {
  auto it = req.headers.find(name);
  if (it == req.headers.end()) return "";
  return it->second;
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

static std::string trim_slashes(std::string s) {
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

static std::string lower_ascii(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// -----------------------------------------------------------------------------
// Fingerprint (sha3-512(pubkey) hex lower) — matches Python
// -----------------------------------------------------------------------------
static std::string hex_lower(const unsigned char* b, size_t n) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; i++) {
        out[2*i]     = hexd[(b[i] >> 4) & 0xF];
        out[2*i + 1] = hexd[b[i] & 0xF];
    }
    return out;
}

static std::string fingerprint_from_pubkey_sha3_512_hex(const std::vector<unsigned char>& pubkey) {
    unsigned char h[64]; // SHA3-512 digest size

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, pubkey.data(), pubkey.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, h, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP sha3-512 failed");
    }

    EVP_MD_CTX_free(ctx);
    return hex_lower(h, sizeof(h));
}

// -----------------------------------------------------------------------------
// v4 token helpers (Ed25519 over canonical JSON bytes)
// Wire format: v4.<payload_b64url_no_pad>.<sig_b64url_no_pad>
// -----------------------------------------------------------------------------
static json verify_token_v4_ed25519(const std::string& token, const unsigned char pk[32]) {
    auto dot1 = token.find('.');
    auto dot2 = (dot1 == std::string::npos) ? std::string::npos : token.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos) throw std::runtime_error("bad token format");

    std::string prefix      = token.substr(0, dot1);
    std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig_b64     = token.substr(dot2 + 1);

    if (prefix != "v4") throw std::runtime_error("bad token prefix");

    // libsodium decoder tries ORIGINAL then URLSAFE; token uses URLSAFE_NO_PADDING → this works.
    auto payload_bytes = b64decode_loose(payload_b64);
    auto sig_bytes     = b64decode_loose(sig_b64);

    if (sig_bytes.size() != crypto_sign_BYTES) throw std::runtime_error("bad signature size");

    if (crypto_sign_verify_detached(sig_bytes.data(),
                                    payload_bytes.data(),
                                    (unsigned long long)payload_bytes.size(),
                                    pk) != 0) {
        throw std::runtime_error("invalid signature");
    }

    return json::parse(payload_bytes.begin(), payload_bytes.end());
}

// Sign token from a JSON object using canonical JSON serialization:
// - sorted keys (nlohmann json object_t defaults to std::map → sorted)
// - no whitespace (dump with indent=-1)
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

// Canonical bytes for v4 phone signature verification (matches Python _canonical_v4_phone_auth)
static std::string canonical_v4_phone_auth(const json& sp) {
    json c;
    c["expires_at"] = sp.at("expires_at");
    c["issued_at"]  = sp.at("issued_at");
    c["nonce"]      = sp.at("nonce");
    c["origin"]     = sp.at("origin");
    c["rp_id_hash"] = sp.at("rp_id_hash");
    c["session_id"] = sp.at("session_id");
    c["sid"]        = sp.at("sid");
    c["st_hash"]    = sp.at("st_hash");
    return c.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
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
    // Python lowercases RP ID before hashing; do the same here.
    std::string rp = lower_ascii(RP_ID);
    std::string rp_id_hash = sha256_b64_std_str(rp);

    // IMPORTANT: keep stable/canonical order
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

// -----------------------------------------------------------------------------
// Optional: decode ST payload JSON (debug helper)
// -----------------------------------------------------------------------------
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

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main() {
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

    if (const char* p = std::getenv("PQNAS_POLICY_FILE")) {
        if (!policy_load_allowlist(p)) {
            std::cerr << "Failed policy load: " << p << std::endl;
            return 3;
        }
    }

    httplib::Server srv;



// ---- Audit log (hash-chained JSONL) ----
// Default paths (can later be made configurable):
//   server/audit/pqnas_audit.jsonl
//   server/audit/pqnas_audit.state
const std::string audit_dir = exe_dir() + "/audit";
try {
    std::filesystem::create_directories(audit_dir);
} catch (const std::exception& e) {
    std::cerr << "[audit] WARNING: create_directories failed: " << e.what() << std::endl;
}

pqnas::AuditLog audit(
    audit_dir + "/pqnas_audit.jsonl",
    audit_dir + "/pqnas_audit.state"
);


const std::string STATIC_LOGIN = "server/src/static/login.html";
const std::string STATIC_JS    = "server/src/static/pqnas_v4.js";

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
    res.body = body;
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

srv.Get("/success", [&](const httplib::Request&, httplib::Response& res) {
    res.status = 200;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    res.body =
        "<!doctype html><html><body style='font-family:system-ui;padding:24px'>"
        "<h2>Success</h2>"
        "<p>You are signed in (pqnas_session cookie set).</p>"
        "<p><a href=\"/api/v4/me\">Check session</a></p>"
        "</body></html>";
});

// Polling endpoint (browser)
srv.Get("/api/v4/status", [&](const httplib::Request& req, httplib::Response& res) {
    approvals_prune(now_epoch());


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
		// Always-safe last-hop IP (tunnel will often show 127.0.0.1)
		ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

		// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
		auto it_cf = req.headers.find("CF-Connecting-IP");
		if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

		auto it_xff = req.headers.find("X-Forwarded-For");
		if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

		// User-Agent
		ev.f["ua"] = audit_ua();

        audit.append(ev);
    };

    auto sid = req.get_param_value("sid");
    if (sid.empty()) {
		audit_fail("", "missing_sid", 400);
        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing sid"}}).dump());
        return;
    }

    ApprovalEntry e;
    if (!approvals_get(sid, e)) {
        reply_json(res, 200, json({{"ok",true},{"approved",false}}).dump());
        return;
    }

    long now = now_epoch();
    if (now > e.expires_at) {
        approvals_pop(sid);
        reply_json(res, 200, json({{"ok",true},{"approved",false},{"expired",true}}).dump());
        return;
    }

    reply_json(res, 200, json({{"ok",true},{"approved",true},{"fingerprint",e.fingerprint}}).dump());
});

// Consume approval → set cookie in *browser* response
srv.Post("/api/v4/consume", [&](const httplib::Request& req, httplib::Response& res) {
    approvals_prune(now_epoch());

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
        audit.append(ev);
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

        long now = now_epoch();
        if (now > e.expires_at) {
            approvals_pop(sid);
            audit_fail(sid, "approval_expired", 410);
            reply_json(res, 410, json({{"ok",false},{"error","expired"},{"message","approval expired"}}).dump());
            return;
        }

        // One-time consume
        approvals_pop(sid);

        // AUDIT: consume ok (no cookie value)
        {
            pqnas::AuditEvent ev;
            ev.event = "v4.consume_ok";
            ev.outcome = "ok";
            ev.f["sid"] = sid;
            if (!e.fingerprint.empty()) ev.f["fingerprint"] = e.fingerprint;
            ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            ev.f["ua"] = audit_ua();
            audit.append(ev);
        }

        // Set cookie: HttpOnly + SameSite=Lax. Add Secure if ORIGIN is https.
        const bool secure = (ORIGIN.rfind("https://", 0) == 0);

        std::string cookie = "pqnas_session=" + e.cookie_val + "; Path=/; HttpOnly; SameSite=Lax";
        cookie += "; Max-Age=" + std::to_string(SESS_TTL);
        if (secure) cookie += "; Secure";

        // AUDIT: cookie set (no cookie value)
        {
            pqnas::AuditEvent ev;
            ev.event = "v4.cookie_set";
            ev.outcome = "ok";
            ev.f["sid"] = sid;
            if (!e.fingerprint.empty()) ev.f["fingerprint"] = e.fingerprint;
            ev.f["secure"] = secure ? "true" : "false";
            ev.f["max_age"] = std::to_string(SESS_TTL);
			// Always-safe last-hop IP (tunnel will often show 127.0.0.1)
			ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

			// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
			auto it_cf = req.headers.find("CF-Connecting-IP");
			if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

			auto it_xff = req.headers.find("X-Forwarded-For");
			if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

			// User-Agent
			ev.f["ua"] = audit_ua();


            audit.append(ev);
        }

        res.set_header("Set-Cookie", cookie);
        reply_json(res, 200, json({{"ok",true}}).dump());
    } catch (const std::exception& e) {
        audit_fail("", "bad_json", 400);
        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"},{"detail",e.what()}}).dump());
    }
});


// Debug endpoint: verifies pqnas_session cookie
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

        audit.append(ev);
    };

    auto audit_ok = [&](const std::string& fp_b64, long exp) {
        pqnas::AuditEvent ev;
        ev.event = "v4.me_ok";
        ev.outcome = "ok";
        // fp_b64 is already a derived/encoded identifier; OK to log
        ev.f["fingerprint_b64"] = pqnas::shorten(fp_b64, 120);
        ev.f["exp"] = std::to_string(exp);
		// Always-safe last-hop IP (tunnel will often show 127.0.0.1)
		ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

		// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
		auto it_cf = req.headers.find("CF-Connecting-IP");
		if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

		auto it_xff = req.headers.find("X-Forwarded-For");
		if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

		// User-Agent
		ev.f["ua"] = audit_ua();

        audit.append(ev);
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

    long now = now_epoch();
    if (now > exp) {
		audit_fail("session_expired");
        reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","session expired"}}).dump());
        return;
    }
	audit_ok(fp_b64, exp);
    reply_json(res, 200, json({{"ok",true},{"exp",exp},{"fingerprint_b64",fp_b64}}).dump());
});

    // -------------------------------------------------------------------------
    // Create v4 session (returns qr_uri + st)
    // -------------------------------------------------------------------------
    srv.Post("/api/v4/session", [&](const httplib::Request& req, httplib::Response& res) {
        std::cerr << "[/api/v4/session] hit from "
                  << (req.remote_addr.empty() ? "?" : req.remote_addr)
                  << std::endl;

        long issued_at  = now_epoch();
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
        // AUDIT: session issued (do NOT log st_token itself)
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
			ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr; // optional keep
            auto it = req.headers.find("User-Agent");
            ev.f["ua"] = pqnas::shorten(it == req.headers.end() ? "" : it->second);
            audit.append(ev);
        }

        // Debug: print ST payload JSON too (super helpful)
        {
            std::string st_payload_json;
            if (decode_st_payload_json(st_token, st_payload_json)) {
                std::cerr << "[/api/v4/session] st_payload_json=" << st_payload_json << std::endl;
            } else {
                std::cerr << "[/api/v4/session] st_payload_json=DECODE_FAILED" << std::endl;
            }
        }

        reply_json(res, 200, out.dump());
    });
    // -------------------------------------------------------------------------
    // Render QR as SVG for the browser (qr_uri derived from st + config)
    // GET /api/v4/qr.svg?st=...
    // -------------------------------------------------------------------------
    srv.Get("/api/v4/qr.svg", [&](const httplib::Request& req, httplib::Response& res) {
        auto it = req.params.find("st");
        if (it == req.params.end() || it->second.empty()) {
            res.status = 400;
            res.set_header("Content-Type", "application/json");
            res.body = json({{"ok", false}, {"error", "bad_request"}, {"message", "missing st"}}).dump();
            return;
        }

        const std::string st = it->second;

        // Build dna:// URI exactly like /api/v4/session does
        const std::string qr_uri =
            "dna://auth?v=4&st=" + url_encode(st) +
            "&origin=" + url_encode(ORIGIN) +
            "&app=" + url_encode(APP_NAME);

        try {
            const std::string svg = qr_svg_from_text(qr_uri, /*module_px*/ 6, /*margin*/ 4);
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

    // -------------------------------------------------------------------------
    // Verify v4 response from phone
    // -------------------------------------------------------------------------
    srv.Post("/api/v4/verify", [&](const httplib::Request& req, httplib::Response& res) {
        std::cerr << "[/api/v4/verify] ENTER len=" << req.body.size()
                  << " from " << (req.remote_addr.empty() ? "?" : req.remote_addr)
                  << std::endl;

        auto fail = [&](int code, const std::string& msg, const std::string& detail = "") {
            std::cerr << "[/api/v4/verify] FAIL " << code << " " << msg;
            if (!detail.empty()) std::cerr << " detail=" << detail;
            std::cerr << std::endl;

            json out = {
                {"ok", false},
                {"error", (code == 400 ? "bad_request" : "not_authorized")},
                {"message", msg}
            };
            if (!detail.empty()) out["detail"] = detail;
            reply_json(res, code, out.dump());
        };

        // --- Audit context (avoid secrets) ---
        std::string audit_sid;
        std::string audit_st_hash_b64;
        std::string audit_origin;
        std::string audit_rp_id_hash;
        std::string audit_fp; // fingerprint (computed/claimed; safe)

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
			// Always-safe last-hop IP (tunnel will often show 127.0.0.1)
			ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

			// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
			auto it_cf = req.headers.find("CF-Connecting-IP");
			if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

			auto it_xff = req.headers.find("X-Forwarded-For");
			if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

			// User-Agent
			auto it = req.headers.find("User-Agent");
			ev.f["ua"] = audit_ua();

            audit.append(ev);
        };

        try {
            // 1) Parse JSON
            json body = json::parse(req.body);
            std::cerr << "[/api/v4/verify] body keys=" << body.size() << " (redacted)" << std::endl;


            // Envelope
            if (body.value("type", "") != "dna.auth.response") {
                audit_fail("bad_type", body.value("type",""));
                return fail(400, "invalid type", body.value("type",""));

            }
            int v = body.value("v", 0);
            if (v != 4) {
                audit_fail("bad_version", std::to_string(v));
                return fail(400, "invalid version", std::to_string(v));
            }

            for (auto k : {"st","fingerprint","signature","signed_payload","pubkey_b64"}) {
                if (!body.contains(k)) {
					audit_fail("missing_field", k);
                    return fail(400, std::string("missing field: ") + k);
                }
            }

            std::string st         = body.at("st").get<std::string>();
            std::string claimed_fp = body.at("fingerprint").get<std::string>();
            std::string sig_b64    = body.at("signature").get<std::string>();
            std::string pk_b64     = body.at("pubkey_b64").get<std::string>();

            json sp = body.at("signed_payload");
            if (!sp.is_object()) {
				audit_fail("signed_payload_not_object");
                return fail(400, "signed_payload must be object");
            }
            // Audit: capture safe fields (no secrets)
            audit_origin = sp.value("origin", "");
            audit_rp_id_hash = sp.value("rp_id_hash", "");
            audit_sid = sp.value("sid", "");

            std::cerr << "[/api/v4/verify] signed_payload=" << sp.dump(2) << std::endl;

            // 2) Verify st (Ed25519)
            json st_obj;
            try {
                st_obj = verify_token_v4_ed25519(st, SERVER_PK);
                std::cerr << "[/api/v4/verify] st_obj=" << st_obj.dump(2) << std::endl;
            } catch (const std::exception& e) {
				audit_fail("st_ed25519_invalid", e.what());
                return fail(400, "invalid st", e.what());
            }

            if (st_obj.value("v", 0) != 4 || st_obj.value("typ", "") != "st") {
 				audit_fail("st_claims_invalid",
                           std::string("v=") + std::to_string(st_obj.value("v",0)) + " typ=" + st_obj.value("typ",""));
                return fail(400, "invalid st claims",
                            std::string("v=") + std::to_string(st_obj.value("v",0)) + " typ=" + st_obj.value("typ",""));
            }

            // 3) TTL / time window
            long now = now_epoch();
            long st_exp = st_obj.at("expires_at").get<long>();
            long st_iat = st_obj.at("issued_at").get<long>();
            std::cerr << "[/api/v4/verify] now=" << now
                      << " st_iat=" << st_iat
                      << " st_exp=" << st_exp
                      << std::endl;

            if (now > st_exp) {
				audit_fail("st_expired");
                return fail(410, "st expired");
            }
            if (st_exp <= st_iat) {
				audit_fail("st_time_window_invalid");
                return fail(400, "invalid st time window");
            }
			audit_sid = st_obj.value("sid", audit_sid);
			audit_origin = st_obj.value("origin", audit_origin);
			audit_rp_id_hash = st_obj.value("rp_id_hash", audit_rp_id_hash);

			// 4) st_hash binding
			std::string st_hash = sha256_b64_std_str(st); // standard b64 with padding
			std::string got_st_hash = sp.value("st_hash", "");
			audit_st_hash_b64 = st_hash; // safe derived value

			std::cerr << "[/api/v4/verify] st_hash expected=" << st_hash
          		<< " got=" << got_st_hash
          		<< std::endl;

			if (got_st_hash != st_hash) {
    			// Avoid logging attacker-controlled long strings; keep it short.
    			audit_fail("st_hash_mismatch",
               		std::string("got_len=") + std::to_string(got_st_hash.size()) +
               		" expected_len=" + std::to_string(st_hash.size()));
    			return fail(400, "st_hash mismatch",
	                std::string("got=") + got_st_hash + " expected=" + st_hash);
	}


            // 5) Claim mirroring
            auto req_str = [&](const char* k)->std::string { return sp.at(k).get<std::string>(); };
            auto req_int = [&](const char* k)->long { return sp.at(k).get<long>(); };

            if (req_str("sid") != st_obj.value("sid","")){
				audit_fail("claim_mismatch_sid");
                return fail(400, "claim mismatch: sid", std::string("sp=") + req_str("sid") + " st=" + st_obj.value("sid",""));}
            if (req_str("origin") != st_obj.value("origin","")){
				audit_fail("claim_mismatch_origin");
                return fail(400, "claim mismatch: origin", std::string("sp=") + req_str("origin") + " st=" + st_obj.value("origin",""));}
            if (req_str("rp_id_hash") != st_obj.value("rp_id_hash","")){
				audit_fail("claim_mismatch_ri_id_hash");
                return fail(400, "claim mismatch: rp_id_hash", std::string("sp=") + req_str("rp_id_hash") + " st=" + st_obj.value("rp_id_hash",""));}
            if (req_str("nonce") != st_obj.value("nonce","")){
				audit_fail("claim_mismatch_nonce");
                return fail(400, "claim mismatch: nonce", std::string("sp=") + req_str("nonce") + " st=" + st_obj.value("nonce",""));}
            if (req_int("issued_at") != st_obj.value("issued_at",0L)){
				audit_fail("claim_mismatch_issued_at");
                return fail(400, "claim mismatch: issued_at");}
            if (req_int("expires_at") != st_obj.value("expires_at",0L)){
				audit_fail("claim_mismatch_expires_at");
                return fail(400, "claim mismatch: expires_at");}

            // 6) Origin binding
            if (trim_slashes(st_obj.at("origin").get<std::string>()) != trim_slashes(ORIGIN)) {
                audit_fail("origin_mismatch",
                           std::string("st=") + st_obj.at("origin").get<std::string>() + " cfg=" + ORIGIN);
                return fail(400, "origin mismatch",
                            std::string("st=") + st_obj.at("origin").get<std::string>() + " cfg=" + ORIGIN);
            }

            // 7) RP binding via rp_id_hash (deployment config)
            std::string expected_rp_hash = sha256_b64_std_str(lower_ascii(RP_ID));
            if (st_obj.at("rp_id_hash").get<std::string>() != expected_rp_hash) {
                audit_fail("rp_id_hash_mismatch",
                           std::string("st=") + st_obj.at("rp_id_hash").get<std::string>() + " cfg=" + expected_rp_hash);
                return fail(403, "rp_id_hash mismatch",
                            std::string("st=") + st_obj.at("rp_id_hash").get<std::string>() + " cfg=" + expected_rp_hash);
            }


            // 8) Decode inputs
            std::vector<unsigned char> signature = b64decode_loose(sig_b64);
            std::vector<unsigned char> pubkey    = b64decode_loose(pk_b64);

            std::cerr << "[/api/v4/verify] decoded sizes: pubkey=" << pubkey.size()
                      << " sig=" << signature.size()
                      << std::endl;

            // 9) Identity binding
            std::string computed_fp = fingerprint_from_pubkey_sha3_512_hex(pubkey);
            claimed_fp = lower_ascii(claimed_fp);
            audit_fp = computed_fp; // safe (hash of pubkey)

            std::cerr << "[/api/v4/verify] fingerprint claimed=" << claimed_fp
                      << " computed=" << computed_fp
                      << std::endl;

            if (claimed_fp != computed_fp) {
                audit_fail("fingerprint_mismatch",
                           std::string("claimed=") + pqnas::shorten(claimed_fp) + " computed=" + pqnas::shorten(computed_fp));
                return fail(403, "fingerprint_pubkey_mismatch",
                            std::string("claimed=") + claimed_fp + " computed=" + computed_fp);
            }


            // 10) Policy
            if (!policy_is_allowed(computed_fp)) {
                audit_fail("policy_deny");
                return fail(403, "identity_not_allowed");
            }

            // 11) Canonical bytes
            std::string canonical = canonical_v4_phone_auth(sp);
            std::vector<unsigned char> canonical_bytes(canonical.begin(), canonical.end());

            std::cerr << "[/api/v4/verify] canonical=" << canonical << std::endl;
            std::cerr << "[/api/v4/verify] canonical_len=" << canonical_bytes.size() << std::endl;
            std::string canon_sha = sha256_b64_std_str(canonical);
            std::cerr << "[/api/v4/verify] canonical_sha256_b64=" << canon_sha << "\n" << std::flush;

            // 12) PQ verify (native)
            bool ok = verify_mldsa87_signature_native(pubkey, canonical_bytes, signature);
            std::cerr << "[/api/v4/verify] PQ verify ok=" << (ok ? "true" : "false") << std::endl;

            if (!ok) {
				audit_fail("pq_sig_invalid");
                return fail(403, "invalid_signature", "PQ verify returned false");
            }

            // 13) Issue approval token (at)
            json at_payload = {
                {"v",4},
                {"typ","at"},
                {"sid", st_obj.at("sid")},
                {"st_hash", st_hash},
                {"rp_id_hash", st_obj.at("rp_id_hash")},
                {"fingerprint", computed_fp},
                {"issued_at", now},
                {"expires_at", now + 60}
            };
            std::string at = sign_token_v4_ed25519(at_payload, SERVER_SK);

            // Mint a browser session cookie (pqnas_session) and store it so the browser can consume it.
            // fingerprint_b64 = base64(UTF-8 hex fingerprint) with standard base64 (padding ok).
            std::string fp_b64 = b64_std(reinterpret_cast<const unsigned char*>(computed_fp.data()),
                                         computed_fp.size());

            std::string cookieVal;
            long sess_iat = now;
            long sess_exp = now + SESS_TTL;

            if (session_cookie_mint(COOKIE_KEY, fp_b64, sess_iat, sess_exp, cookieVal)) {
                ApprovalEntry e;
                e.cookie_val = cookieVal;
                e.fingerprint = computed_fp;
                e.expires_at = now + 120; // browser has 2 minutes to consume
                approvals_put(st_obj.value("sid",""), e);
                {
                    pqnas::AuditEvent ev;
                    ev.event = "v4.cookie_minted";
                    ev.outcome = "ok";
                    ev.f["sid"] = st_obj.value("sid","");
                    ev.f["st_hash_b64"] = st_hash;
                    ev.f["rp_id_hash"] = st_obj.value("rp_id_hash","");
                    ev.f["fingerprint"] = computed_fp;
                    ev.f["sess_iat"] = std::to_string(sess_iat);
                    ev.f["sess_exp"] = std::to_string(sess_exp);
					// Always-safe last-hop IP (tunnel will often show 127.0.0.1)
					ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

					// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
					auto it_cf = req.headers.find("CF-Connecting-IP");
					if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

					auto it_xff = req.headers.find("X-Forwarded-For");
					if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

					// User-Agent
					ev.f["ua"] = audit_ua();

                    audit.append(ev);
                }

                std::cerr << "[/api/v4/verify] approval stored sid=" << st_obj.value("sid","")
                          << " cookie_exp=" << sess_exp << std::endl;
            } else {
                audit_fail("cookie_mint_failed");
                std::cerr << "[/api/v4/verify] WARNING: session_cookie_mint failed" << std::endl;
            }

            // AUDIT: verify success (do NOT log 'at')
            {
                pqnas::AuditEvent ev;
                ev.event = "v4.verify_ok";
                ev.outcome = "ok";
                ev.f["sid"] = st_obj.value("sid","");
                ev.f["st_hash_b64"] = st_hash;
                ev.f["origin"] = st_obj.value("origin","");
                ev.f["rp_id_hash"] = st_obj.value("rp_id_hash","");
                ev.f["fingerprint"] = computed_fp;
                // Always-safe last-hop IP (tunnel will often show 127.0.0.1)
				ev.f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;

				// Cloudflare / proxy-provided client IP info (record-only; don't "trust" it)
				auto it_cf = req.headers.find("CF-Connecting-IP");
				if (it_cf != req.headers.end()) ev.f["cf_ip"] = it_cf->second;

				auto it_xff = req.headers.find("X-Forwarded-For");
				if (it_xff != req.headers.end()) ev.f["xff"] = pqnas::shorten(it_xff->second, 120);

				// User-Agent
				ev.f["ua"] = audit_ua();

                audit.append(ev);
            }

            json out = {{"ok",true},{"v",4},{"at",at}};
            std::cerr << "[/api/v4/verify] SUCCESS issuing at=" << at << std::endl;
            reply_json(res, 200, out.dump());
        } catch (const std::exception& e) {
 			audit_fail("exception", e.what());
            return fail(400, "exception", e.what());
        }
    });


    // -----------------------------------------------------------------------------
    // Demo-only approval cache for browser redirect (NOT stateless across nodes)
    // sid -> expires_at (epoch)
    // -----------------------------------------------------------------------------

    srv.Get("/api/v4/me", [&](const httplib::Request& req, httplib::Response& res) {
        // httplib gives raw Cookie header; we parse pqnas_session=...
        auto it = req.headers.find("Cookie");
        if (it == req.headers.end()) {
            reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing cookie"}}).dump());
            return;
        }

        const std::string& cookieHdr = it->second;
        std::string cookieVal;

        // very small cookie parser (enough for pqnas_session)
        // Looks for "pqnas_session=" then reads until ';' or end.
        const std::string k = "pqnas_session=";
        auto pos = cookieHdr.find(k);
        if (pos == std::string::npos) {
            reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","missing pqnas_session"}}).dump());
            return;
        }
        pos += k.size();
        auto end = cookieHdr.find(';', pos);
        cookieVal = cookieHdr.substr(pos, (end == std::string::npos) ? std::string::npos : (end - pos));

        std::string fp_b64;
        long exp = 0;
        if (!session_cookie_verify(COOKIE_KEY, cookieVal, fp_b64, exp)) {
            reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","invalid session"}}).dump());
            return;
        }

        long now = now_epoch();
        if (now > exp) {
            reply_json(res, 401, json({{"ok",false},{"error","unauthorized"},{"message","session expired"}}).dump());
            return;
        }

        reply_json(res, 200, json({
            {"ok", true},
            {"exp", exp},
            {"fingerprint_b64", fp_b64}
        }).dump());
    });




    srv.Post("/api/v4/consume", [&](const httplib::Request& req, httplib::Response& res) {
    approvals_prune(now_epoch());

    try {
        json body = json::parse(req.body);
        std::string sid = body.value("sid", "");
        if (sid.empty()) {
            reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","missing sid"}}).dump());
            return;
        }

        ApprovalEntry e;
        if (!approvals_get(sid, e)) {
            reply_json(res, 404, json({{"ok",false},{"error","not_found"},{"message","not approved"}}).dump());
            return;
        }

        long now = now_epoch();
        if (now > e.expires_at) {
            approvals_pop(sid);
            reply_json(res, 410, json({{"ok",false},{"error","expired"},{"message","approval expired"}}).dump());
            return;
        }

        // One-time consume
        approvals_pop(sid);

        // Set cookie: HttpOnly + SameSite=Lax. Add Secure if ORIGIN is https.
        const bool secure = (ORIGIN.rfind("https://", 0) == 0);

        std::string cookie = "pqnas_session=" + e.cookie_val + "; Path=/; HttpOnly; SameSite=Lax";
        cookie += "; Max-Age=" + std::to_string(SESS_TTL);
        if (secure) cookie += "; Secure";
        res.set_header("Set-Cookie", cookie);

        reply_json(res, 200, json({{"ok",true}}).dump());
    } catch (const std::exception& e) {
        reply_json(res, 400, json({{"ok",false},{"error","bad_request"},{"message","invalid json"},{"detail",e.what()}}).dump());
    }
});


    std::cerr << "PQ-NAS server listening on 0.0.0.0:" << LISTEN_PORT << std::endl;
    srv.listen("0.0.0.0", LISTEN_PORT);
    return 0;
}
