#include <drogon/drogon.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <ctime>

extern "C" {
#include "qrauth_v4.h"
}

#include "policy.h"
#include "session_cookie.h"

// ---- globals configured in main.cc ----
unsigned char g_server_pk[32];
unsigned char g_server_sk[64];
unsigned char g_cookie_key[32];

std::string g_origin = "https://nas.example.com";
std::string g_iss = "pq-nas";
std::string g_aud = "dna-messenger";
std::string g_scope = "pqnas.login";
std::string g_app_name = "PQ-NAS";

int g_req_ttl = 60;        // seconds
int g_sess_ttl = 8 * 3600; // seconds

static long now_epoch() { return (long)std::time(nullptr); }

static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(strlen(out.c_str()));
    return out;
}

static std::string random_b64url(size_t nbytes) {
    std::string b(nbytes, '\0');
    randombytes_buf(b.data(), b.size());
    return b64url_enc((const unsigned char*)b.data(), b.size());
}

// Canonical JSON bytes (frozen order/template)
static bool assert_safe_json_str(const std::string& s) {
    for (char c : s) {
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') return false;
    }
    return true;
}

static std::string build_req_payload_canonical(const std::string& sid,
                                               const std::string& chal,
                                               const std::string& nonce,
                                               long iat, long exp) {
    // Order is frozen:
    // aud, chal, exp, iat, iss, nonce, origin, scope, sid, typ, v
    // typ=req, v=4 fixed
    return std::string("{")
        + "\"aud\":\"" + g_aud + "\","
        + "\"chal\":\"" + chal + "\","
        + "\"exp\":" + std::to_string(exp) + ","
        + "\"iat\":" + std::to_string(iat) + ","
        + "\"iss\":\"" + g_iss + "\","
        + "\"nonce\":\"" + nonce + "\","
        + "\"origin\":\"" + g_origin + "\","
        + "\"scope\":\"" + g_scope + "\","
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
    crypto_sign_detached(sig, &siglen, digest, 32, g_server_sk);

    std::string payload_b64 = b64url_enc((const unsigned char*)payload_json.data(), payload_json.size());
    std::string sig_b64 = b64url_enc(sig, 64);
    return payload_b64 + "." + sig_b64;
}

static void jerr(const drogon::HttpResponsePtr& resp, int code, const std::string& err, const std::string& msg) {
    resp->setStatusCode((drogon::HttpStatusCode)code);
    Json::Value j;
    j["ok"] = false;
    j["error"] = err;
    j["message"] = msg;
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    resp->setBody(j.toStyledString());
}

static void route_v4_session(const drogon::HttpRequestPtr&,
                             std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);

    long iat = now_epoch();
    long exp = iat + g_req_ttl;

    std::string sid = random_b64url(18);     // URL-safe token (not strictly fixed size)
    std::string chal = random_b64url(32);    // 32 random bytes -> b64url
    std::string nonce = random_b64url(16);   // 16 random bytes -> b64url

    // Guardrails against JSON injection (inputs are ours, but keep it frozen-safe)
    if (!assert_safe_json_str(g_aud) || !assert_safe_json_str(g_iss) ||
        !assert_safe_json_str(g_origin) || !assert_safe_json_str(g_scope) ||
        !assert_safe_json_str(sid) || !assert_safe_json_str(chal) || !assert_safe_json_str(nonce)) {
        return jerr(resp, 500, "server_error", "unsafe string in token fields"), cb(resp);
    }

    std::string payload = build_req_payload_canonical(sid, chal, nonce, iat, exp);
    std::string req_token = sign_req_token(payload);

    std::string qr_uri = "dna://auth?v=4&req=" + drogon::utils::urlEncode(req_token)
        + "&origin=" + drogon::utils::urlEncode(g_origin)
        + "&app=" + drogon::utils::urlEncode(g_app_name);

    Json::Value j;
    j["v"] = 4;
    j["sid"] = sid;
    j["expires_at"] = (Json::Int64)exp;
    j["req"] = req_token;
    j["qr_uri"] = qr_uri;

    resp->setBody(j.toStyledString());
    cb(resp);
}

static void route_v4_verify(const drogon::HttpRequestPtr& req,
                            std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);

    auto json = req->getJsonObject();
    if (!json) return jerr(resp, 400, "bad_request", "expected json body"), cb(resp);

    int v = (*json).get("v", 0).asInt();
    std::string type = (*json).get("type", "").asString();
    std::string req_token = (*json).get("req", "").asString();
    std::string proof = (*json).get("proof", "").asString();

    if (v != 4 || type != "dna.auth.proof" || req_token.empty() || proof.empty())
        return jerr(resp, 400, "bad_request", "missing/invalid fields"), cb(resp);

    // Optional: strip whitespace (safe for copy/paste)
    std::string req2 = req_token;
    std::string proof2 = proof;
    // make mutable C strings for strip
    std::vector<char> rbuf(req2.begin(), req2.end()); rbuf.push_back('\0');
    std::vector<char> pbuf(proof2.begin(), proof2.end()); pbuf.push_back('\0');
    qr_strip_ws_inplace(rbuf.data());
    qr_strip_ws_inplace(pbuf.data());
    req2 = rbuf.data();
    proof2 = pbuf.data();

    qr_err_t rc = qr_verify_proof_token(pbuf.data(), rbuf.data(), g_server_pk);
    if (rc != QR_OK) {
        // 403 for auth failures, 400 for format
        switch (rc) {
            case QR_ERR_REQ_SIG:
            case QR_ERR_REQ_MISMATCH:
            case QR_ERR_FP_BINDING:
            case QR_ERR_PHONE_SIG:
                return jerr(resp, 403, "not_authorized", "verification failed"), cb(resp);
            default:
                return jerr(resp, 400, "bad_request", "invalid token format"), cb(resp);
        }
    }

    qr_proof_claims_t claims{};
    rc = qr_extract_proof_claims(pbuf.data(), &claims);
    if (rc != QR_OK || claims.fingerprint_b64[0] == 0) {
        return jerr(resp, 400, "bad_request", "could not extract claims"), cb(resp);
    }

    std::string fp_b64 = claims.fingerprint_b64;
    if (!policy_is_allowed(fp_b64)) {
        return jerr(resp, 403, "not_authorized", "identity_not_allowed"), cb(resp);
    }

    // Mint cookie session
    long iat = now_epoch();
    long exp = iat + g_sess_ttl;
    std::string cookieVal;
    session_cookie_mint(g_cookie_key, fp_b64, iat, exp, cookieVal);

    resp->addCookie("pqnas_session", cookieVal, exp, "/", "", true, true, drogon::Cookie::SameSite::kLax);

    Json::Value out;
    out["ok"] = true;
    out["v"] = 4;
    resp->setBody(out.toStyledString());
    cb(resp);
}

static void route_me(const drogon::HttpRequestPtr& req,
                     std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);

    auto c = req->getCookie("pqnas_session");
    if (c.empty()) return jerr(resp, 401, "unauthorized", "missing session cookie"), cb(resp);

    std::string fp;
    long exp = 0;
    if (!session_cookie_verify(g_cookie_key, c, fp, exp)) {
        return jerr(resp, 401, "unauthorized", "invalid session cookie"), cb(resp);
    }
    if (now_epoch() > exp) {
        return jerr(resp, 401, "unauthorized", "session expired"), cb(resp);
    }

    Json::Value j;
    j["ok"] = true;
    j["fingerprint"] = fp;
    j["exp"] = (Json::Int64)exp;
    resp->setBody(j.toStyledString());
    cb(resp);
}

