#include "qrauth_v4.h"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void qr_strip_ws_inplace(char *s) {
    if (!s) return;
    char *w = s;
    for (char *p = s; *p; p++) {
        if (*p!=' ' && *p!='\t' && *p!='\r' && *p!='\n') {
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

static char *json_get_string_dup(const char *json, const char *field) {
    // Minimal extractor: finds "field":"...".
    // For v0 test vectors only. Production should use a real JSON parser or JCS bytes.
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":\"", field);

    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);

    const char *q = strchr(p, '"');
    if (!q) return NULL;

    size_t n = (size_t)(q - p);
    char *v = (char*)malloc(n + 1);
    if (!v) return NULL;
    memcpy(v, p, n);
    v[n] = 0;
    return v;
}

qr_err_t qr_verify_req_token(const char *req_token, const unsigned char server_pk_raw[32]) {
    if (!req_token || !server_pk_raw) return QR_ERR_FORMAT;

    const char *dot = strchr(req_token, '.');
    if (!dot) return QR_ERR_FORMAT;

    // payload_b64
    size_t payload_b64_len = (size_t)(dot - req_token);
    char *payload_b64 = (char*)malloc(payload_b64_len + 1);
    if (!payload_b64) return QR_ERR_FORMAT;
    memcpy(payload_b64, req_token, payload_b64_len);
    payload_b64[payload_b64_len] = 0;

    // sig_b64 is remainder
    const char *sig_b64 = dot + 1;

    unsigned char payload_bytes[4096];
    size_t payload_len = 0;
    if (b64url_decode(payload_b64, payload_bytes, sizeof(payload_bytes), &payload_len) != 0) {
        free(payload_b64);
        return QR_ERR_B64;
    }
    free(payload_b64);

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
    return QR_OK;
}

qr_err_t qr_verify_proof_token(
    const char *proof_token,
    const char *req_token_expected,
    const unsigned char server_pk_raw[32]
) {
    if (!proof_token || !req_token_expected || !server_pk_raw) return QR_ERR_FORMAT;

    // verify server signature of expected req token
    qr_err_t req_rc = qr_verify_req_token(req_token_expected, server_pk_raw);
    if (req_rc != QR_OK) return req_rc;

    // split proof_token
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
    if (b64url_decode(proof_payload_b64, proof_payload_bytes, sizeof(proof_payload_bytes), &proof_payload_len) != 0) {
        free(proof_payload_b64);
        return QR_ERR_B64;
    }
    free(proof_payload_b64);
    proof_payload_bytes[proof_payload_len] = 0;

    unsigned char phone_sig[128];
    size_t phone_sig_len = 0;
    if (b64url_decode(phone_sig_b64, phone_sig, sizeof(phone_sig), &phone_sig_len) != 0 || phone_sig_len != 64) {
        return QR_ERR_B64;
    }

    // crude JSON parsing
    const char *jsons = (const char*)proof_payload_bytes;

    char *pk_b64 = json_get_string_dup(jsons, "pk");
    char *fp_b64 = json_get_string_dup(jsons, "fingerprint");
    char *req_in_proof = json_get_string_dup(jsons, "req");

    const char *tsp = strstr(jsons, "\"ts\":");
    long ts = 0;
    if (tsp) ts = strtol(tsp + 5, NULL, 10);

    if (!pk_b64 || !fp_b64 || !req_in_proof || ts == 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return QR_ERR_JSON;
    }

    // proof must bind to expected req token
    if (strcmp(req_in_proof, req_token_expected) != 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return QR_ERR_REQ_MISMATCH;
    }

    // decode pk
    unsigned char pk_raw[128];
    size_t pk_len = 0;
    if (b64url_decode(pk_b64, pk_raw, sizeof(pk_raw), &pk_len) != 0 || pk_len != 32) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return QR_ERR_PK_DECODE;
    }

    // fingerprint binding: fp == b64url(SHA3-512(pk_raw))
    unsigned char fp_calc_bytes[64];
    sha3_512(pk_raw, 32, fp_calc_bytes);

    char fp_calc_b64[256];
    b64url_encode(fp_calc_bytes, 64, fp_calc_b64, sizeof(fp_calc_b64));
    if (strcmp(fp_calc_b64, fp_b64) != 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return QR_ERR_FP_BINDING;
    }

    // req_hash_b64 = b64url(SHA256(UTF8(req_token_expected)))
    unsigned char req_hash_bytes[32];
    sha256((const unsigned char*)req_token_expected, strlen(req_token_expected), req_hash_bytes);

    char req_hash_b64[256];
    b64url_encode(req_hash_bytes, 32, req_hash_b64, sizeof(req_hash_b64));

    // message = "DNAQR-V4\n<req_hash_b64>\n<fp_b64>\n<ts>"
    char msg[2048];
    snprintf(msg, sizeof(msg), "DNAQR-V4\n%s\n%s\n%ld", req_hash_b64, fp_b64, ts);

    unsigned char prehash[64];
    sha3_512((const unsigned char*)msg, strlen(msg), prehash);

    // phone signature is Ed25519(TEST) over prehash bytes
    int sig_rc = verify_ed25519_detached(pk_raw, phone_sig, prehash, 64);

    free(pk_b64); free(fp_b64); free(req_in_proof);

    if (sig_rc != 0) return QR_ERR_PHONE_SIG;
    return QR_OK;
}
