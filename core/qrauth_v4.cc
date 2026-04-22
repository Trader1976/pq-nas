#include "qrauth_v4.h"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <memory>
#include <string>

#include <jsoncpp/json/json.h>

void qr_strip_ws_inplace(char *s) {
    if (!s) return;
    char *w = s;
    for (char *p = s; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
            *w++ = *p;
        }
    }
    *w = 0;
}

static int b64url_decode(const char *s, unsigned char *out, size_t out_max, size_t *out_len) {
    return sodium_base642bin(
        out, out_max,
        s, strlen(s),
        NULL,
        out_len,
        NULL,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    );
}

static void b64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_max) {
    sodium_bin2base64(out, out_max, in, in_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

static void sha3_512(const unsigned char *data, size_t len, unsigned char out[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

static void sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    SHA256(data, len, out);
}

static int verify_ed25519_detached(const unsigned char pk[32],
                                   const unsigned char sig[64],
                                   const unsigned char *msg, size_t msg_len) {
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msg_len, pk);
}

static int ct_cstr_eq(const char *a, const char *b) {
    if (!a || !b) return 0;

    const size_t a_len = strlen(a);
    const size_t b_len = strlen(b);
    if (a_len != b_len) return 0;

    return sodium_memcmp(a, b, a_len) == 0;
}

#if QR_V4_ENFORCE_TIME
static int qr_now_long(long *out) {
    if (!out) return 0;
    time_t now = time(NULL);
    if (now == (time_t)-1) return 0;
    *out = (long)now;
    return 1;
}
#endif

static int parse_json_object_strict(const char *json,
                                    Json::Value *out,
                                    std::string *errs) {
    if (!json || !out) return 0;

    Json::CharReaderBuilder b;
    b["collectComments"] = false;
    b["allowComments"] = false;
    b["allowTrailingCommas"] = false;
    b["strictRoot"] = true;
    b["failIfExtra"] = true;
    b["rejectDupKeys"] = true;
    b["allowSingleQuotes"] = false;
    b["allowNumericKeys"] = false;

    std::unique_ptr<Json::CharReader> reader(b.newCharReader());

    const char *begin = json;
    const char *end = json + strlen(json);

    return reader->parse(begin, end, out, errs) ? 1 : 0;
}

static int json_require_string(const Json::Value& obj,
                               const char *field,
                               std::string *out) {
    if (!field || !out) return 0;
    if (!obj.isObject() || !obj.isMember(field)) return 0;

    const Json::Value& v = obj[field];
    if (!v.isString()) return 0;

    *out = v.asString();
    return !out->empty();
}

static int json_require_long(const Json::Value& obj,
                             const char *field,
                             long *out) {
    if (!field || !out) return 0;
    if (!obj.isObject() || !obj.isMember(field)) return 0;

    const Json::Value& v = obj[field];

    if (v.isInt64()) {
        Json::Int64 x = v.asInt64();
        *out = (long)x;
        return 1;
    }
    if (v.isUInt64()) {
        Json::UInt64 x = v.asUInt64();
        *out = (long)x;
        return 1;
    }
    if (v.isInt()) {
        *out = (long)v.asInt();
        return 1;
    }
    if (v.isUInt()) {
        *out = (long)v.asUInt();
        return 1;
    }

    return 0;
}

qr_err_t qr_verify_req_token(const char *req_token, const unsigned char server_pk_raw[32]) {
    if (!req_token || !server_pk_raw) return QR_ERR_FORMAT;

    // Accept optional "v4." prefix: v4.<payload>.<sig>
    const char *t = req_token;
    if (strncmp(t, "v4.", 3) == 0) t += 3;

    const char *dot = strchr(t, '.');
    if (!dot) return QR_ERR_FORMAT;

    // payload_b64
    size_t payload_b64_len = (size_t)(dot - t);
    char *payload_b64 = (char*)malloc(payload_b64_len + 1);
    if (!payload_b64) return QR_ERR_FORMAT;
    memcpy(payload_b64, t, payload_b64_len);
    payload_b64[payload_b64_len] = 0;

    // sig_b64 is remainder
    const char *sig_b64 = dot + 1;

    unsigned char payload_bytes[4096];
    size_t payload_len = 0;
    if (b64url_decode(payload_b64, payload_bytes, sizeof(payload_bytes) - 1, &payload_len) != 0) {
        free(payload_b64);
        return QR_ERR_B64;
    }
    free(payload_b64);
    payload_b64 = NULL;

    // NUL-terminate for JSON parsing
    payload_bytes[payload_len] = 0;

    unsigned char sig[128];
    size_t sig_len = 0;
    if (b64url_decode(sig_b64, sig, sizeof(sig), &sig_len) != 0 || sig_len != 64) {
        return QR_ERR_B64;
    }

    // server signs SHA256(payload_bytes)
    unsigned char digest[32];
    sha256(payload_bytes, payload_len, digest);

    if (verify_ed25519_detached(server_pk_raw, sig, digest, 32) != 0) {
        return QR_ERR_REQ_SIG;
    }

#if QR_V4_ENFORCE_TIME
    Json::Value req_obj;
    std::string parse_errs;
    if (!parse_json_object_strict((const char*)payload_bytes, &req_obj, &parse_errs)) {
        return QR_ERR_JSON;
    }

    long exp = 0;
    long now = 0;
    if (!json_require_long(req_obj, "exp", &exp) || exp <= 0) {
        return QR_ERR_JSON;
    }
    if (!qr_now_long(&now)) {
        return QR_ERR_JSON;
    }
    if (now > exp) {
        return QR_ERR_REQ_EXPIRED;
    }
#endif

    return QR_OK;
}

qr_err_t qr_verify_proof_token(
    const char *proof_token,
    const char *req_token_expected,
    const unsigned char server_pk_raw[32]
) {
    if (!proof_token || !req_token_expected || !server_pk_raw) return QR_ERR_FORMAT;

    // Helper: accept optional "v4." prefix on tokens for binding/hash
    const char *req_norm = req_token_expected;
    if (strncmp(req_norm, "v4.", 3) == 0) req_norm += 3;

    // verify server signature of expected req token
    qr_err_t req_rc = qr_verify_req_token(req_token_expected, server_pk_raw);
    if (req_rc != QR_OK) return req_rc;

    // split proof_token: base64url(payload_json).base64url(phone_sig)
    const char *dot = strchr(proof_token, '.');
    if (!dot) return QR_ERR_FORMAT;

    size_t proof_payload_b64_len = (size_t)(dot - proof_token);
    char *proof_payload_b64 = (char*)malloc(proof_payload_b64_len + 1);
    if (!proof_payload_b64) return QR_ERR_FORMAT;
    memcpy(proof_payload_b64, proof_token, proof_payload_b64_len);
    proof_payload_b64[proof_payload_b64_len] = 0;

    const char *phone_sig_b64 = dot + 1;

    unsigned char proof_payload_bytes[8192];
    size_t proof_payload_len = 0;
    if (b64url_decode(proof_payload_b64, proof_payload_bytes, sizeof(proof_payload_bytes) - 1, &proof_payload_len) != 0) {
        free(proof_payload_b64);
        return QR_ERR_B64;
    }
    free(proof_payload_b64);
    proof_payload_b64 = NULL;

    // Ensure NUL-terminated for strict JSON parsing
    proof_payload_bytes[proof_payload_len] = 0;

    unsigned char phone_sig[128];
    size_t phone_sig_len = 0;
    if (b64url_decode(phone_sig_b64, phone_sig, sizeof(phone_sig), &phone_sig_len) != 0 || phone_sig_len != 64) {
        return QR_ERR_B64;
    }

    const char *jsons = (const char*)proof_payload_bytes;

    Json::Value proof_obj;
    std::string parse_errs;
    if (!parse_json_object_strict(jsons, &proof_obj, &parse_errs)) {
        return QR_ERR_JSON;
    }

    std::string pk_b64_s;
    std::string fp_b64_s;
    std::string req_in_proof_s;
    long ts = 0;

    if (!json_require_string(proof_obj, "pk", &pk_b64_s) ||
        !json_require_string(proof_obj, "fingerprint", &fp_b64_s) ||
        !json_require_string(proof_obj, "req", &req_in_proof_s) ||
        !json_require_long(proof_obj, "ts", &ts) ||
        ts <= 0) {
        return QR_ERR_JSON;
    }

    const char *pk_b64 = pk_b64_s.c_str();
    const char *fp_b64 = fp_b64_s.c_str();
    const char *req_in_proof = req_in_proof_s.c_str();

    // proof must bind to expected req token
    const char *reqp_norm = req_in_proof;
    if (strncmp(reqp_norm, "v4.", 3) == 0) reqp_norm += 3;

    if (!ct_cstr_eq(reqp_norm, req_norm)) {
        return QR_ERR_REQ_MISMATCH;
    }

#if QR_V4_ENFORCE_TIME
    long now = 0;
    long skew = 0;

    if (!qr_now_long(&now)) {
        return QR_ERR_JSON;
    }

    skew = (now >= ts) ? (now - ts) : (ts - now);
    if (skew > QR_V4_MAX_SKEW_SEC) {
        return QR_ERR_TS_SKEW;
    }
#endif

    // decode pk (Ed25519 test only)
    unsigned char pk_raw[128];
    size_t pk_len = 0;
    if (b64url_decode(pk_b64, pk_raw, sizeof(pk_raw), &pk_len) != 0 || pk_len != 32) {
        return QR_ERR_PK_DECODE;
    }

    // fingerprint binding: fp == b64url(SHA3-512(pk_raw))
    unsigned char fp_calc_bytes[64];
    sha3_512(pk_raw, 32, fp_calc_bytes);

    char fp_calc_b64[256];
    b64url_encode(fp_calc_bytes, 64, fp_calc_b64, sizeof(fp_calc_b64));
    if (!ct_cstr_eq(fp_calc_b64, fp_b64)) {
        return QR_ERR_FP_BINDING;
    }

    // req_hash_b64 = b64url(SHA256(UTF8(req_norm)))
    unsigned char req_hash_bytes[32];
    sha256((const unsigned char*)req_norm, strlen(req_norm), req_hash_bytes);

    char req_hash_b64[256];
    b64url_encode(req_hash_bytes, 32, req_hash_b64, sizeof(req_hash_b64));

    // message = "DNAQR-V4\n<req_hash_b64>\n<fp_b64>\n<ts>"
    char msg[2048];
    snprintf(msg, sizeof(msg), "DNAQR-V4\n%s\n%s\n%ld", req_hash_b64, fp_b64, ts);

    unsigned char prehash[64];
    sha3_512((const unsigned char*)msg, strlen(msg), prehash);

    // phone signature is Ed25519(TEST) over prehash bytes
    int sig_rc = verify_ed25519_detached(pk_raw, phone_sig, prehash, 64);

    if (sig_rc != 0) return QR_ERR_PHONE_SIG;
    return QR_OK;
}

qr_err_t qr_extract_proof_claims(const char *proof_token, qr_proof_claims_t *out) {
    if (!proof_token || !out) return QR_ERR_FORMAT;

    const char *dot = strchr(proof_token, '.');
    if (!dot) return QR_ERR_FORMAT;

    size_t payload_b64_len = (size_t)(dot - proof_token);
    if (payload_b64_len == 0) return QR_ERR_FORMAT;

    char *payload_b64 = (char*)malloc(payload_b64_len + 1);
    if (!payload_b64) return QR_ERR_FORMAT;
    memcpy(payload_b64, proof_token, payload_b64_len);
    payload_b64[payload_b64_len] = 0;

    unsigned char payload_bytes[8192];
    size_t payload_len = 0;
    if (b64url_decode(payload_b64, payload_bytes, sizeof(payload_bytes) - 1, &payload_len) != 0) {
        free(payload_b64);
        return QR_ERR_B64;
    }
    free(payload_b64);
    payload_b64 = NULL;

    payload_bytes[payload_len] = 0;

    const char *jsons = (const char*)payload_bytes;

    Json::Value proof_obj;
    std::string parse_errs;
    if (!parse_json_object_strict(jsons, &proof_obj, &parse_errs)) {
        return QR_ERR_JSON;
    }

    std::string fp_b64;
    long ts = 0;

    if (!json_require_string(proof_obj, "fingerprint", &fp_b64) ||
        !json_require_long(proof_obj, "ts", &ts) ||
        ts <= 0) {
        return QR_ERR_JSON;
    }

    size_t n = fp_b64.size();
    if (n == 0 || n >= sizeof(out->fingerprint_b64)) {
        return QR_ERR_JSON;
    }

    memcpy(out->fingerprint_b64, fp_b64.c_str(), n + 1);
    out->ts = ts;
    return QR_OK;
}