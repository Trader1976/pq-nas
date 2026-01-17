// Reference verifier for PQ-NAS QR-Auth v4 test vectors
// Requires: libsodium + OpenSSL (linked via pqnas_core)
//
// Run (from repo root):
//   ./build/bin/verify_vectors

#include <sodium.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qrauth_v4.h"

// -------------------- File helpers --------------------

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = 0;
    if (out_len) *out_len = n;
    return buf;
}

// base64url no padding -> bytes
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

// -------------------- Markdown extraction --------------------

static char *extract_fenced(const char *md, const char *header) {
    // Find "## <header>", then next fenced block
    char needle[256];
    snprintf(needle, sizeof(needle), "## %s", header);
    const char *p = strstr(md, needle);
    if (!p) return NULL;

    const char *a = strstr(p, "```");
    if (!a) return NULL;
    a += 3;

    const char *b = strstr(a, "```");
    if (!b) return NULL;

    size_t n = (size_t)(b - a);
    while (n > 0 && (a[0] == '\n' || a[0] == '\r' || a[0] == ' ' || a[0] == '\t')) { a++; n--; }
    while (n > 0 && (a[n-1] == '\n' || a[n-1] == '\r' || a[n-1] == ' ' || a[n-1] == '\t')) n--;

    char *out = (char*)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, a, n);
    out[n] = 0;
    return out;
}

static char *extract_server_pk(const char *md) {
    // Locate "## Server key", then fenced block after "public key"
    const char *p = strstr(md, "## Server key");
    if (!p) return NULL;

    p = strstr(p, "public key");
    if (!p) return NULL;

    const char *a = strstr(p, "```");
    if (!a) return NULL;
    a += 3;

    const char *b = strstr(a, "```");
    if (!b) return NULL;

    size_t n = (size_t)(b - a);
    while (n > 0 && (a[0] == '\n' || a[0] == '\r' || a[0] == ' ' || a[0] == '\t')) { a++; n--; }
    while (n > 0 && (a[n-1] == '\n' || a[n-1] == '\r' || a[n-1] == ' ' || a[n-1] == '\t')) n--;

    char *out = (char*)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, a, n);
    out[n] = 0;
    return out;
}

// -------------------- INVALID hash sanity check --------------------

static void sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    SHA256(data, len, out);
}

// -------------------- main --------------------

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 2;
    }

    size_t md_len = 0;
    unsigned char *md = read_file("pqnas_qrauth_v4_test_vectors.md", &md_len);
    if (!md) {
        fprintf(stderr, "Missing pqnas_qrauth_v4_test_vectors.md in repo root\n");
        return 2;
    }

    char *server_pk_b64 = extract_server_pk((const char*)md);
    char *req_token = extract_fenced((const char*)md, "req_token");
    char *proof_token = extract_fenced((const char*)md, "proof_token");

    if (!server_pk_b64 || !req_token || !proof_token) {
        fprintf(stderr, "Failed to parse vectors file\n");
        free(md);
        return 2;
    }

    // IMPORTANT: markdown fences may wrap lines; tokens must be whitespace-free
    qr_strip_ws_inplace(server_pk_b64);
    qr_strip_ws_inplace(req_token);
    qr_strip_ws_inplace(proof_token);

    unsigned char server_pk[64];
    size_t server_pk_len = 0;
    if (b64url_decode(server_pk_b64, server_pk, sizeof(server_pk), &server_pk_len) != 0 || server_pk_len != 32) {
        fprintf(stderr, "Bad server public key\n");
        free(md);
        return 2;
    }

    // VALID
    if (qr_verify_req_token(req_token, server_pk) != QR_OK) {
        printf("VALID: FAIL (req_token server signature)\n");
        free(md);
        return 1;
    }
    if (qr_verify_proof_token(proof_token, req_token, server_pk) != QR_OK) {
        printf("VALID: FAIL (proof verification)\n");
        free(md);
        return 1;
    }
    printf("VALID: PASS\n");

    // INVALID (hash sanity)
    size_t inv_len = 0;
    unsigned char *inv = read_file("pqnas_qrauth_v4_test_vector_invalid.md", &inv_len);
    if (inv) {
        const char *invs = (const char*)inv;
        char *tampered = extract_fenced(invs, "Tampered req_token (used in signing)");
        char *wronghash = extract_fenced(invs, "Wrong req_hash_b64");

        if (!tampered || !wronghash) {
            printf("INVALID: SKIP (could not parse invalid vector file)\n");
        } else {
            qr_strip_ws_inplace(tampered);
            qr_strip_ws_inplace(wronghash);

            unsigned char wh[32];
            sha256((const unsigned char*)tampered, strlen(tampered), wh);
            char wh_b64[256];
            b64url_encode(wh, 32, wh_b64, sizeof(wh_b64));

            if (strcmp(wh_b64, wronghash) != 0) {
                printf("INVALID: FAIL\n");
                free(inv);
                free(md);
                return 1;
            }

            unsigned char ch[32];
            sha256((const unsigned char*)req_token, strlen(req_token), ch);
            char ch_b64[256];
            b64url_encode(ch, 32, ch_b64, sizeof(ch_b64));

            if (strcmp(ch_b64, wronghash) == 0) {
                printf("INVALID: FAIL\n");
                free(inv);
                free(md);
                return 1;
            }

            printf("INVALID: PASS (expected mismatch detected)\n");
        }
        free(inv);
    } else {
        printf("INVALID: SKIP (file missing)\n");
    }

    // INVALID_PROOF (signature mismatch)
    size_t invp_len = 0;
    unsigned char *invp = read_file("pqnas_qrauth_v4_test_vectors_invalid_proof.md", &invp_len);
    if (invp) {
        char *proof_token_invalid = extract_fenced((const char*)invp, "proof_token_invalid");
        if (!proof_token_invalid) {
            printf("INVALID_PROOF: SKIP (could not parse invalid proof file)\n");
        } else {
            qr_strip_ws_inplace(proof_token_invalid);

            qr_err_t rc = qr_verify_proof_token(proof_token_invalid, req_token, server_pk);
            if (rc == QR_OK) {
                printf("INVALID_PROOF: FAIL (unexpectedly verified)\n");
                free(invp);
                free(md);
                return 1;
            } else {
                printf("INVALID_PROOF: PASS (phone signature mismatch as expected)\n");
            }
        }
        free(invp);
    } else {
        printf("INVALID_PROOF: SKIP (file missing)\n");
    }

    free(md);
    return 0;
}
