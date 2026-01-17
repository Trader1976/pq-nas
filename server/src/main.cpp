#include <iostream>
#include <string>
#include <ctime>
#include <vector>
#include <cstdlib>
#include <cstring>

#include <sodium.h>
#include <openssl/sha.h>

extern "C" {
#include "qrauth_v4.h"
}

#include "session_cookie.h"
#include "policy.h"

// header-only HTTP server
#include "httplib.h"

// ---- config ----
static unsigned char SERVER_PK[32];
static unsigned char SERVER_SK[64];
static unsigned char COOKIE_KEY[32];

static std::string ORIGIN   = "https://nas.example.com";
static std::string ISS      = "pq-nas";
static std::string AUD      = "dna-messenger";
static std::string SCOPE    = "pqnas.login";
static std::string APP_NAME = "PQ-NAS";

static int REQ_TTL  = 60;
static int SESS_TTL = 8 * 3600;
static int LISTEN_PORT = 8081; // use 8081 to avoid conflicts

static long now_epoch() { return (long)std::time(nullptr); }



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



static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

static std::string random_b64url(size_t nbytes) {
    std::string b(nbytes, '\0');
    randombytes_buf(b.data(), b.size());
    return b64url_enc((const unsigned char*)b.data(), b.size());
}

static bool assert_safe_json_str(const std::string& s) {
    for (char c : s) {
        if (c=='"' || c=='\\' || c=='\n' || c=='\r' || c=='\t') return false;
    }
    return true;
}

// frozen canonical order/template
static std::string build_req_payload_canonical(const std::string& sid,
                                               const std::string& chal,
                                               const std::string& nonce,
                                               long iat, long exp) {
    return std::string("{")
        + "\"aud\":\"" + AUD + "\","
        + "\"chal\":\"" + chal + "\","
        + "\"exp\":" + std::to_string(exp) + ","
        + "\"iat\":" + std::to_string(iat) + ","
        + "\"iss\":\"" + ISS + "\","
        + "\"nonce\":\"" + nonce + "\","
        + "\"origin\":\"" + ORIGIN + "\","
        + "\"scope\":\"" + SCOPE + "\","
        + "\"sid\":\"" + sid + "\","
        + "\"typ\":\"req\","
        + "\"v\":4"
        + "}";
}

static std::string sign_req_token(const std::string& payload_json) {
    unsigned char digest[32];
    SHA256((const unsigned char*)payload_json.data(), payload_json.size(), digest);

    unsigned char sig[64];
    unsigned long long siglen = 0;
    crypto_sign_detached(sig, &siglen, digest, 32, SERVER_SK);

    std::string payload_b64 = b64url_enc((const unsigned char*)payload_json.data(), payload_json.size());
    std::string sig_b64 = b64url_enc(sig, 64);
    return payload_b64 + "." + sig_b64;
}

// tiny JSON getters for MVP: "key":"value" and "key":123
static std::string json_get_str(const std::string& body, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    auto p = body.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    while (p < body.size() && (body[p]==' '||body[p]=='\n'||body[p]=='\r'||body[p]=='\t')) p++;
    if (p >= body.size() || body[p] != '"') return "";
    p++;
    auto q = body.find('"', p);
    if (q == std::string::npos) return "";
    return body.substr(p, q - p);
}
static int json_get_int(const std::string& body, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    auto p = body.find(pat);
    if (p == std::string::npos) return 0;
    p += pat.size();
    while (p < body.size() && (body[p]==' '||body[p]=='\n'||body[p]=='\r'||body[p]=='\t')) p++;
    return std::atoi(body.c_str() + p);
}

static void reply_json(httplib::Response& res, int code, const std::string& json) {
    res.status = code;
    res.set_header("Content-Type", "application/json");
    res.body = json;
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

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    if (!load_env_key("PQNAS_SERVER_PK_B64URL", SERVER_PK, 32) ||
        !load_env_key("PQNAS_SERVER_SK_B64URL", SERVER_SK, 64) ||
        !load_env_key("PQNAS_COOKIE_KEY_B64URL", COOKIE_KEY, 32)) {
        std::cerr << "Missing/invalid env keys. Run ./build/bin/pqnas_keygen > .env.pqnas then: source .env.pqnas\n";
        return 2;
    }

    if (const char* v = std::getenv("PQNAS_ORIGIN")) ORIGIN = v;
    if (const char* v = std::getenv("PQNAS_ISS")) ISS = v;
    if (const char* v = std::getenv("PQNAS_AUD")) AUD = v;
    if (const char* v = std::getenv("PQNAS_SCOPE")) SCOPE = v;
    if (const char* v = std::getenv("PQNAS_APP_NAME")) APP_NAME = v;
    if (const char* v = std::getenv("PQNAS_REQ_TTL")) REQ_TTL = std::atoi(v);
    if (const char* v = std::getenv("PQNAS_SESS_TTL")) SESS_TTL = std::atoi(v);
    if (const char* v = std::getenv("PQNAS_LISTEN_PORT")) LISTEN_PORT = std::atoi(v);

    if (const char* p = std::getenv("PQNAS_POLICY_FILE")) {
        if (!policy_load_allowlist(p)) {
            std::cerr << "Failed policy load: " << p << "\n";
            return 3;
        }
    }

    httplib::Server srv;

    srv.Post("/api/v4/session", [&](const httplib::Request&, httplib::Response& res) {
        long iat = now_epoch();
        long exp = iat + REQ_TTL;

        std::string sid = random_b64url(18);
        std::string chal = random_b64url(32);
        std::string nonce = random_b64url(16);

        if (!assert_safe_json_str(AUD) || !assert_safe_json_str(ISS) ||
            !assert_safe_json_str(ORIGIN) || !assert_safe_json_str(SCOPE) ||
            !assert_safe_json_str(sid) || !assert_safe_json_str(chal) || !assert_safe_json_str(nonce)) {
            return reply_json(res, 500, R"({"ok":false,"error":"server_error","message":"unsafe token field"})");
        }

        std::string payload = build_req_payload_canonical(sid, chal, nonce, iat, exp);
        std::string req_token = sign_req_token(payload);

        // MVP: qr_uri returned as a string; browser/renderer can URL-encode if needed
        std::string qr_uri =
          "dna://auth?v=4&req=" + url_encode(req_token) +
          "&origin=" + url_encode(ORIGIN) +
          "&app=" + url_encode(APP_NAME);

        std::string out = std::string("{")
            + "\"v\":4,"
            + "\"sid\":\"" + sid + "\","
            + "\"expires_at\":" + std::to_string(exp) + ","
            + "\"req\":\"" + req_token + "\","
            + "\"qr_uri\":\"" + qr_uri + "\""
            + "}";

        reply_json(res, 200, out);
    });

    srv.Post("/api/v4/verify", [&](const httplib::Request& r, httplib::Response& res) {
        const std::string& body = r.body;

        int v = json_get_int(body, "v");
        std::string type = json_get_str(body, "type");
        std::string req_token = json_get_str(body, "req");
        std::string proof = json_get_str(body, "proof");

        if (v != 4 || type != "dna.auth.proof" || req_token.empty() || proof.empty()) {
            return reply_json(res, 400, R"({"ok":false,"error":"bad_request","message":"missing/invalid fields"})");
        }

        // strip whitespace (copy/paste safety)
        std::vector<char> rbuf(req_token.begin(), req_token.end()); rbuf.push_back('\0');
        std::vector<char> pbuf(proof.begin(), proof.end()); pbuf.push_back('\0');
        qr_strip_ws_inplace(rbuf.data());
        qr_strip_ws_inplace(pbuf.data());

        qr_err_t rc = qr_verify_proof_token(pbuf.data(), rbuf.data(), SERVER_PK);
        if (rc != QR_OK) {
            if (rc == QR_ERR_REQ_SIG || rc == QR_ERR_REQ_MISMATCH || rc == QR_ERR_FP_BINDING || rc == QR_ERR_PHONE_SIG) {
                return reply_json(res, 403, R"({"ok":false,"error":"not_authorized","message":"verification failed"})");
            }
            return reply_json(res, 400, R"({"ok":false,"error":"bad_request","message":"invalid token format"})");
        }

        qr_proof_claims_t claims{};
        rc = qr_extract_proof_claims(pbuf.data(), &claims);
        if (rc != QR_OK || claims.fingerprint_b64[0] == 0) {
            return reply_json(res, 400, R"({"ok":false,"error":"bad_request","message":"could not extract claims"})");
        }

        std::string fp = claims.fingerprint_b64;
        if (!policy_is_allowed(fp)) {
            return reply_json(res, 403, R"({"ok":false,"error":"not_authorized","message":"identity_not_allowed"})");
        }

        long iat = now_epoch();
        long exp = iat + SESS_TTL;
        std::string cookieVal;
        session_cookie_mint(COOKIE_KEY, fp, iat, exp, cookieVal);

        res.set_header("Set-Cookie", ("pqnas_session=" + cookieVal + "; Path=/; HttpOnly; Secure; SameSite=Lax"));
        reply_json(res, 200, R"({"ok":true,"v":4})");
    });

    srv.Get("/api/v1/me", [&](const httplib::Request& r, httplib::Response& res) {
        auto it = r.headers.find("Cookie");
        if (it == r.headers.end()) {
            return reply_json(res, 401, R"({"ok":false,"error":"unauthorized","message":"missing cookie"})");
        }
        const std::string& cookieHdr = it->second;
        auto p = cookieHdr.find("pqnas_session=");
        if (p == std::string::npos) {
            return reply_json(res, 401, R"({"ok":false,"error":"unauthorized","message":"missing session"})");
        }
        p += std::strlen("pqnas_session=");
        auto q = cookieHdr.find(';', p);
        std::string val = (q == std::string::npos) ? cookieHdr.substr(p) : cookieHdr.substr(p, q - p);

        std::string fp;
        long exp = 0;
        if (!session_cookie_verify(COOKIE_KEY, val, fp, exp)) {
            return reply_json(res, 401, R"({"ok":false,"error":"unauthorized","message":"invalid session"})");
        }
        if (now_epoch() > exp) {
            return reply_json(res, 401, R"({"ok":false,"error":"unauthorized","message":"expired"})");
        }

        std::string out = std::string("{")
            + "\"ok\":true,"
            + "\"fingerprint\":\"" + fp + "\","
            + "\"exp\":" + std::to_string(exp)
            + "}";
        reply_json(res, 200, out);
    });

    std::cout << "PQ-NAS server listening on 0.0.0.0:" << LISTEN_PORT << "\n";
    srv.listen("0.0.0.0", LISTEN_PORT);
    return 0;
}
