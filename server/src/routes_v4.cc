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
//
// These globals are initialized during process startup (before any requests).
// They define the server's long-term signing identity (Ed25519) and the symmetric
// cookie MAC/encryption key used to mint browser session cookies.
//
// Security note:
// - g_server_sk must never be logged or shipped to clients.
// - g_cookie_key must be treated as a secret; rotating it invalidates sessions.
unsigned char g_server_pk[32];
unsigned char g_server_sk[64];
unsigned char g_cookie_key[32];

// ---- protocol / relying-party configuration ----
//
// These values are bound into tokens / payloads and define the relying party.
// Treat them as part of the "security context" (origin + issuer + audience + scope).
//
// If you change any of these, you are effectively changing what site/app the
// mobile approval is valid for; update clients and test vectors accordingly.
std::string g_origin = "https://nas.example.com";
std::string g_iss = "pq-nas";
std::string g_aud = "dna-messenger";
std::string g_scope = "pqnas.login";
std::string g_app_name = "PQ-NAS";

// ---- lifetimes ----
//
// g_req_ttl: lifetime of the QR request token (browser -> mobile).
// g_sess_ttl: lifetime of the minted browser session cookie.
//
// Security note:
// - Keep request TTL short to shrink replay window.
// - Cookie TTL can be longer, but should remain bounded and auditable.
int g_req_ttl = 60;        // seconds
int g_sess_ttl = 8 * 3600; // seconds

// Wall-clock seconds since Unix epoch.
//
// Security note:
// - This assumes reasonably correct server time. If you deploy on hosts with
//   unreliable clocks, signature expiry checks and session TTLs can break.
static long now_epoch() { return (long)std::time(nullptr); }

// Base64url encode (no padding), using libsodium variant.
//
// Used for:
// - compact token encoding
// - QR transport
//
// Security note:
// - This is encoding only; it does not provide integrity or confidentiality.
//   Integrity comes from signatures/MACs elsewhere.
static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    // sodium_bin2base64 writes a NUL-terminated string; shrink to actual length.
    out.resize(strlen(out.c_str()));
    return out;
}

// Generate random bytes and return base64url(no padding).
//
// Security note:
// - randombytes_buf uses libsodium's CSPRNG.
// - Output length is variable due to base64 encoding; callers must not assume
//   fixed string length, only sufficient entropy.
static std::string random_b64url(size_t nbytes) {
    std::string b(nbytes, '\0');
    randombytes_buf(b.data(), b.size());
    return b64url_enc((const unsigned char*)b.data(), b.size());
}

// Canonical JSON bytes (frozen order/template)
// -------------------------------------------
// The protocol signs/verifies exact bytes. Therefore, the JSON string must be
// canonical and stable: same field order, same quoting rules, no extra whitespace.
//
// This helper rejects characters that could break the frozen template and cause
// ambiguity (or injection) in the signed bytes.
//
// Security note:
// - This is defense-in-depth. In route_v4_session all inputs are server-generated,
//   but we still want hard guardrails so future changes don't accidentally allow
//   a dangerous character into a signed JSON template.
static bool assert_safe_json_str(const std::string& s) {
    for (char c : s) {
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') return false;
    }
    return true;
}

// Build the canonical "req" payload JSON for v4.
// IMPORTANT: field order is frozen by protocol.
//
// Signed content includes: aud, chal, exp, iat, iss, nonce, origin, scope, sid, typ, v
// where typ=req and v=4 are fixed for request tokens.
//
// Security note:
// - Do not reorder fields.
// - Do not change number formatting.
// - Any change here is a protocol change and must update clients/test vectors.
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

// Create a compact request token: base64url(payload_json) + "." + base64url(signature)
//
// Signature scheme:
// - Hash payload_json with SHA-256
// - Sign digest with Ed25519 (libsodium crypto_sign_detached)
//
// Security rationale:
// - Signing a fixed-size digest avoids signing variable-length data directly.
// - SHA-256 is used as a stable prehash to match other protocol components.
// - Ed25519 provides fast server-side authenticity for server-minted request tokens.
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

// JSON error response helper.
//
// Security note:
// - Keep HTTP responses stable and non-sensitive.
// - Put detailed failure reasons into the audit log, not into public error bodies.
static void jerr(const drogon::HttpResponsePtr& resp, int code, const std::string& err, const std::string& msg) {
    resp->setStatusCode((drogon::HttpStatusCode)code);
    Json::Value j;
    j["ok"] = false;
    j["error"] = err;
    j["message"] = msg;
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    resp->setBody(j.toStyledString());
}

// -----------------------------------------------------------------------------
// GET /api/v4/session
//
// Issues a v4 request token ("req") used by the browser to display a QR code.
// The mobile app later proves approval by producing a "proof" token that binds
// back to this request.
//
// Security properties:
// - req is server-authenticated (Ed25519 signature) to prevent tampering.
// - chal + nonce add uniqueness so approvals can't be trivially replayed.
// - exp limits the time window in which a req can be used.
// - origin + scope bind the token to the relying party and intended action.
//
// Output fields:
// - sid: server-generated request/session id (for UX / debugging / correlation)
// - req: the signed request token
// - qr_uri: dna:// deep link containing req + origin + app for the mobile client
// -----------------------------------------------------------------------------
static void route_v4_session(const drogon::HttpRequestPtr&,
                             std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);

    long iat = now_epoch();
    long exp = iat + g_req_ttl;

    // All token fields are generated by the server (not user input).
    // Entropy note:
    // - sid: correlation id / identifier (18 bytes entropy)
    // - chal: challenge (32 bytes entropy)
    // - nonce: uniqueness / replay resistance (16 bytes entropy)
    std::string sid = random_b64url(18);     // URL-safe token (not strictly fixed size)
    std::string chal = random_b64url(32);    // 32 random bytes -> b64url
    std::string nonce = random_b64url(16);   // 16 random bytes -> b64url

    // Guardrails against JSON injection (inputs are ours, but keep it frozen-safe)
    // If these fail, something is wrong with configuration or token generation.
    if (!assert_safe_json_str(g_aud) || !assert_safe_json_str(g_iss) ||
        !assert_safe_json_str(g_origin) || !assert_safe_json_str(g_scope) ||
        !assert_safe_json_str(sid) || !assert_safe_json_str(chal) || !assert_safe_json_str(nonce)) {
        return jerr(resp, 500, "server_error", "unsafe string in token fields"), cb(resp);
    }

    std::string payload = build_req_payload_canonical(sid, chal, nonce, iat, exp);
    std::string req_token = sign_req_token(payload);

    // dna:// deep link is for convenience; it is not trusted input.
    // The server will still verify req/proof cryptographically in /verify.
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

// -----------------------------------------------------------------------------
// POST /api/v4/verify
//
// Verifies a mobile "proof" for a given server-minted request token ("req").
// On success, mints a browser session cookie (pqnas_session).
//
// High-level verification responsibility:
// - Cryptographic verification and binding is done by qr_verify_proof_token()
//   in the v4 verifier library (PQClean + canonicalization rules).
// - Authorization policy is enforced here via policy_is_allowed().
//
// Failure behavior:
// - Fail closed.
// - Return generic errors to clients.
// - (In the full server) log detailed reason codes to the audit log.
// -----------------------------------------------------------------------------
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

    // Basic schema gate: reject anything that isn't the expected v4 proof envelope.
    if (v != 4 || type != "dna.auth.proof" || req_token.empty() || proof.empty())
        return jerr(resp, 400, "bad_request", "missing/invalid fields"), cb(resp);

    // Optional: strip whitespace (safe for copy/paste)
    // Rationale:
    // Users sometimes copy/paste tokens with line breaks or spaces; stripping
    // whitespace is safe because tokens are base64url-ish and do not use spaces.
    //
    // Security note:
    // This normalization must be consistent with verifier expectations. The verifier
    // ultimately validates signatures, so malformed tokens still fail.
    std::string req2 = req_token;
    std::string proof2 = proof;
    // make mutable C strings for strip
    std::vector<char> rbuf(req2.begin(), req2.end()); rbuf.push_back('\0');
    std::vector<char> pbuf(proof2.begin(), proof2.end()); pbuf.push_back('\0');
    qr_strip_ws_inplace(rbuf.data());
    qr_strip_ws_inplace(pbuf.data());
    req2 = rbuf.data();
    proof2 = pbuf.data();

    // Core v4 verification (library-owned):
    // This call is expected to verify, at minimum (conceptually):
    // - req token Ed25519 signature (server authenticity)
    // - SHA-256(req) binding inside signed payload (anti-tamper)
    // - canonical signed bytes (no ambiguous JSON)
    // - ML-DSA-87 signature via PQClean (post-quantum identity proof)
    // - fingerprint <-> pubkey binding (SHA3-512)
    // - origin/RP binding (depending on v4 design)
    //
    // All heavy crypto and canonicalization should live in qrauth_v4.* for
    // testability and reuse.

    // NOTE: This verifier must be the single source of truth for:
    // - req signature verification
    // - proof signature verification (phone/PQ)
    // - binding to req_token_expected
    // - fingerprint binding checks
    // If any of these are duplicated here, they can drift and create bypasses.
    qr_err_t rc = qr_verify_proof_token(pbuf.data(), rbuf.data(), g_server_pk);
    if (rc != QR_OK) {
        // Response shaping:
        // - 403 for "validly formatted but not authorized/verification failed"
        // - 400 for malformed inputs
        //
        // Security note:
        // Avoid leaking exact verification failure causes to clients.
        // Put exact rc / reason into audit logs instead.
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

    // Extract claims after successful cryptographic verification.
    //
    // IMPORTANT:
    // - claims.fingerprint_b64 is the fingerprint in base64/base64url text form.
    // - This is the identity value we embed into the browser session cookie.
    // - Policy/allowlist must use the same representation (or convert explicitly).
    qr_proof_claims_t claims{};
    rc = qr_extract_proof_claims(pbuf.data(), &claims);
    if (rc != QR_OK || claims.fingerprint_b64[0] == 0) {
        return jerr(resp, 400, "bad_request", "could not extract claims"), cb(resp);
    }

    std::string fp_b64 = claims.fingerprint_b64;

    // POLICY: authorization check (allowlist roles).
    // Crypto verification proves identity; policy decides access.
    if (!policy_is_allowed(fp_b64)) {
        return jerr(resp, 403, "not_authorized", "identity_not_allowed"), cb(resp);
    }

    // Mint cookie session
    //
    // Cookie contents (as designed in session_cookie.*) should include at least:
    // - fingerprint identity
    // - iat/exp
    // - integrity protection (MAC/signature) using g_cookie_key
    //
    // Security note:
    // - Keep cookie short-lived.
    // - Cookie is a bearer credential; protect it with Secure + HttpOnly + SameSite.
    long iat = now_epoch();
    long exp = iat + g_sess_ttl;
    std::string cookieVal;
    // Mint cookie session bound to the verified identity (fingerprint_b64).
    session_cookie_mint(g_cookie_key, fp_b64, iat, exp, cookieVal);

    // Set session cookie for browser.
    //
    // Flags:
    // - HttpOnly: not readable by JS (mitigates XSS exfil).
    // - Secure: only over HTTPS.
    // - SameSite=Lax: mitigates most CSRF while preserving normal top-level navigation.
    // Path "/": cookie applies to all endpoints on this origin.
    resp->addCookie("pqnas_session", cookieVal, exp, "/", "", true, true, drogon::Cookie::SameSite::kLax);

    Json::Value out;
    out["ok"] = true;
    out["v"] = 4;
    resp->setBody(out.toStyledString());
    cb(resp);
}

// -----------------------------------------------------------------------------
// GET /api/v4/me
//
// Validates the pqnas_session cookie and returns the authenticated identity.
// This is the canonical "am I logged in?" endpoint for the browser UI.
//
// Security note:
// - Never trust a fingerprint claim from the client directly.
// - Always verify the cookie integrity and expiry.
// -----------------------------------------------------------------------------
static void route_me(const drogon::HttpRequestPtr& req,
                     std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);

    auto c = req->getCookie("pqnas_session");
    if (c.empty()) return jerr(resp, 401, "unauthorized", "missing session cookie"), cb(resp);

    std::string fp;
    long exp = 0;

    // session_cookie_verify must validate:
    // - integrity (MAC/signature under g_cookie_key)
    // - structure/decoding
    // and return the embedded identity + expiry.
    if (!session_cookie_verify(g_cookie_key, c, fp, exp)) {
        return jerr(resp, 401, "unauthorized", "invalid session cookie"), cb(resp);
    }

    // Expiry is checked both here and (ideally) embedded in the cookie MAC.
    // Keeping this explicit makes the lifetime policy obvious to reviewers.
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
