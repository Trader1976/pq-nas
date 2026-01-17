// Reference verifier for PQ-NAS QR-Auth v4 test vectors
// Requires: libsodium (ed25519) + OpenSSL (sha256, sha3-512)
//
// Build:
//   cc -O2 -Wall -Wextra -o verify_vectors tools/verify_vectors.c -lsodium -lcrypto
//
// Run (from repo root):
//   ./verify_vectors

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void strip_ws_inplace(char *s) {
    if (!s) return;
    char *w = s;
    for (char *p = s; *p; p++) {
        if (*p!=' ' && *p!='\t' && *p!='\r' && *p!='\n') {
            *w++ = *p;
        }
    }
    *w = 0;
}

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

// base64url no padding -> bytes (libsodium wants padding sometimes; we normalize)
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

static char *extract_fenced(const char *md, const char *header) {
    // naive extraction: find "## <header>", then next "```", then content until next "```"
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
    memcpy(out, a, n);
    out[n] = 0;
    return out;
}

static char *json_get_string_dup(const char *json, const char *field) {
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



static char *extract_server_pk(const char *md) {
    // We expect:
    // ## Server key (Ed25519) — test only
    // ...
    // public key (raw, base64url):
    // ```
    // <pk>
    // ```
    const char *p = strstr(md, "## Server key");
    if (!p) return NULL;

    // Find the line that mentions "public key"
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

static int verify_ed25519_over_digest(const unsigned char pk[32],
                                      const unsigned char sig[64],
                                      const unsigned char *msg, size_t msg_len) {
    // libsodium verifies signature over msg bytes directly
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msg_len, pk);
}

static int verify_req_token(const char *req_token, const unsigned char server_pk[32]) {
    const char *dot = strchr(req_token, '.');
    if (!dot) return -1;

    size_t payload_b64_len = (size_t)(dot - req_token);
    char *payload_b64 = (char*)malloc(payload_b64_len + 1);
    memcpy(payload_b64, req_token, payload_b64_len);
    payload_b64[payload_b64_len] = 0;

    const char *sig_b64 = dot + 1;

    unsigned char payload_bytes[4096];
    size_t payload_len = 0;
    if (b64url_decode(payload_b64, payload_bytes, sizeof(payload_bytes), &payload_len) != 0) {
        free(payload_b64); return -2;
    }

    unsigned char sig[128];
    size_t sig_len = 0;
    if (b64url_decode(sig_b64, sig, sizeof(sig), &sig_len) != 0 || sig_len != 64) {
        free(payload_b64); return -3;
    }

    unsigned char digest[32];
    sha256(payload_bytes, payload_len, digest);

    int rc = verify_ed25519_over_digest(server_pk, sig, digest, 32);
    free(payload_b64);
    return rc; // 0 means OK
}

static void b64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_max) {
    sodium_bin2base64(out, out_max, in, in_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}


static int verify_proof_token(
    const char *proof_token,
    const char *req_token_expected,
    const unsigned char server_pk[32]
) {
    // 1) basic format
    const char *dot = strchr(proof_token, '.');
    if (!dot) return -10;

    // 2) verify server signature on req_token_expected
    if (verify_req_token(req_token_expected, server_pk) != 0) return -11;

    // 3) split proof token
    size_t proof_payload_b64_len = (size_t)(dot - proof_token);
    char *proof_payload_b64 = (char*)malloc(proof_payload_b64_len + 1);
    if (!proof_payload_b64) return -12;
    memcpy(proof_payload_b64, proof_token, proof_payload_b64_len);
    proof_payload_b64[proof_payload_b64_len] = 0;

    const char *phone_sig_b64 = dot + 1;

    unsigned char proof_payload_bytes[8192];
    size_t proof_payload_len = 0;
    if (b64url_decode(proof_payload_b64, proof_payload_bytes, sizeof(proof_payload_bytes), &proof_payload_len) != 0) {
        free(proof_payload_b64);
        return -13;
    }
    free(proof_payload_b64);
    proof_payload_bytes[proof_payload_len] = 0;

    unsigned char phone_sig[128];
    size_t phone_sig_len = 0;
    if (b64url_decode(phone_sig_b64, phone_sig, sizeof(phone_sig), &phone_sig_len) != 0 || phone_sig_len != 64) {
        return -14;
    }

    // 4) crude JSON extraction
    const char *jsons = (const char*)proof_payload_bytes;

    char *pk_b64 = json_get_string_dup(jsons, "pk");
    char *fp_b64 = json_get_string_dup(jsons, "fingerprint");
    char *req_in_proof = json_get_string_dup(jsons, "req");

    const char *tsp = strstr(jsons, "\"ts\":");
    long ts = 0;
    if (tsp) ts = strtol(tsp + 5, NULL, 10);

    if (!pk_b64 || !fp_b64 || !req_in_proof || ts == 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return -15;
    }

    // 5) ensure proof binds to req_token_expected
    if (strcmp(req_in_proof, req_token_expected) != 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return -16;
    }

    // 6) decode pk
    unsigned char pk_raw[128];
    size_t pk_len = 0;
    if (b64url_decode(pk_b64, pk_raw, sizeof(pk_raw), &pk_len) != 0 || pk_len != 32) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return -17;
    }

    // 7) fingerprint binding: fp == b64url(sha3_512(pk_raw))
    unsigned char fp_calc_bytes[64];
    sha3_512(pk_raw, 32, fp_calc_bytes);
    char fp_calc_b64[256];
    b64url_encode(fp_calc_bytes, 64, fp_calc_b64, sizeof(fp_calc_b64));
    if (strcmp(fp_calc_b64, fp_b64) != 0) {
        free(pk_b64); free(fp_b64); free(req_in_proof);
        return -18;
    }

    // 8) req_hash_b64 = b64url(sha256(utf8(req_token_expected)))
    unsigned char req_hash_bytes[32];
    sha256((const unsigned char*)req_token_expected, strlen(req_token_expected), req_hash_bytes);
    char req_hash_b64[256];
    b64url_encode(req_hash_bytes, 32, req_hash_b64, sizeof(req_hash_b64));

    // 9) signing message = "DNAQR-V4\n<req_hash_b64>\n<fp_b64>\n<ts>"
    char msg[2048];
    snprintf(msg, sizeof(msg), "DNAQR-V4\n%s\n%s\n%ld", req_hash_b64, fp_b64, ts);

    unsigned char prehash[64];
    sha3_512((const unsigned char*)msg, strlen(msg), prehash);

    // 10) verify phone signature (Ed25519 TEST) over prehash
    int rc = verify_ed25519_over_digest(pk_raw, phone_sig, prehash, 64);

    free(pk_b64); free(fp_b64); free(req_in_proof);
    return rc; // 0 means OK, non-zero means signature fail
}





int main(void)
{
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
    fprintf(stderr, "server_pk_b64 extracted: '%s'\n", server_pk_b64 ? server_pk_b64 : "(null)");

    char *req_token = extract_fenced((const char*)md, "req_token");
    char *proof_token = extract_fenced((const char*)md, "proof_token");
    if (!server_pk_b64 || !req_token || !proof_token) {
        fprintf(stderr, "Failed to parse vectors file\n");
        return 2;
    }

    /* IMPORTANT: markdown code fences may wrap/contain newlines/spaces */
    strip_ws_inplace(server_pk_b64);
    strip_ws_inplace(req_token);
    strip_ws_inplace(proof_token);


    unsigned char server_pk[64];
    size_t server_pk_len = 0;
    if (b64url_decode(server_pk_b64, server_pk, sizeof(server_pk), &server_pk_len) != 0 || server_pk_len != 32) {
        fprintf(stderr, "Bad server public key\n");
        return 2;
    }

    // Validate server signature on req_token
    if (verify_req_token(req_token, server_pk) != 0) {
        printf("VALID: FAIL (req_token server signature)\n");
        return 1;
    }

    // Parse proof token minimal fields without a JSON library:
    // We'll extract pk, fingerprint, ts, req from the proof payload bytes by simple string search.
    // (Reference code; production should use a JSON parser.)

    const char *dot = strchr(proof_token, '.');
    if (!dot) { printf("VALID: FAIL (proof token format)\n"); return 1; }

    size_t proof_payload_b64_len = (size_t)(dot - proof_token);
    char *proof_payload_b64 = (char*)malloc(proof_payload_b64_len + 1);
    memcpy(proof_payload_b64, proof_token, proof_payload_b64_len);
    proof_payload_b64[proof_payload_b64_len] = 0;
    const char *phone_sig_b64 = dot + 1;

    unsigned char proof_payload_bytes[8192];
    size_t proof_payload_len = 0;
    if (b64url_decode(proof_payload_b64, proof_payload_bytes, sizeof(proof_payload_bytes), &proof_payload_len) != 0) {
        printf("VALID: FAIL (proof payload b64)\n"); return 1;
    }
    proof_payload_bytes[proof_payload_len] = 0;

    unsigned char phone_sig[128];
    size_t phone_sig_len = 0;
    if (b64url_decode(phone_sig_b64, phone_sig, sizeof(phone_sig), &phone_sig_len) != 0 || phone_sig_len != 64) {
        printf("VALID: FAIL (phone sig b64)\n"); return 1;
    }

    // crude JSON field extraction
    const char *jsons = (const char*)proof_payload_bytes;

    char *pk_b64 = json_get_string_dup(jsons, "pk");
    char *fp_b64 = json_get_string_dup(jsons, "fingerprint");
    char *req_in_proof = json_get_string_dup(jsons, "req");


    // ts is number
    const char *tsp = strstr(jsons, "\"ts\":");
    long ts = 0;
    if (tsp) ts = strtol(tsp + 5, NULL, 10);

    if (!pk_b64 || !fp_b64 || !req_in_proof || ts == 0) {
        printf("VALID: FAIL (parse proof json)\n");
        return 1;
    }

    // Ensure req in proof == req_token
    if (strcmp(req_in_proof, req_token) != 0) {
        printf("VALID: FAIL (req mismatch)\n");
        return 1;
    }

    // Fingerprint binding: fp == b64url(sha3_512(pk_raw))
    unsigned char pk_raw[128];
    size_t pk_len = 0;
    if (b64url_decode(pk_b64, pk_raw, sizeof(pk_raw), &pk_len) != 0 || pk_len != 32) {
        printf("VALID: FAIL (pk decode)\n");
        return 1;
    }

    unsigned char fp_calc_bytes[64];
    sha3_512(pk_raw, 32, fp_calc_bytes);
    char fp_calc_b64[256];
    b64url_encode(fp_calc_bytes, 64, fp_calc_b64, sizeof(fp_calc_b64));
    if (strcmp(fp_calc_b64, fp_b64) != 0) {
        printf("VALID: FAIL (fingerprint binding)\n");
        return 1;
    }

    // req_hash_b64 = b64url(sha256(utf8(req_token)))
    unsigned char req_hash_bytes[32];
    sha256((const unsigned char*)req_token, strlen(req_token), req_hash_bytes);
    char req_hash_b64[256];
    b64url_encode(req_hash_bytes, 32, req_hash_b64, sizeof(req_hash_b64));

    // message = "DNAQR-V4\n<req_hash_b64>\n<fp_b64>\n<ts>"
    char msg[2048];
    snprintf(msg, sizeof(msg), "DNAQR-V4\n%s\n%s\n%ld", req_hash_b64, fp_b64, ts);

    unsigned char prehash[64];
    sha3_512((const unsigned char*)msg, strlen(msg), prehash);

    // verify phone ed25519 signature over prehash bytes
    if (verify_ed25519_over_digest(pk_raw, phone_sig, prehash, 64) != 0) {
        printf("VALID: FAIL (phone signature)\n");
        return 1;
    }

    // Verify VALID proof token
    if (verify_proof_token(proof_token, req_token, server_pk) != 0) {
        printf("VALID: FAIL (phone signature)\n");
        return 1;
    }
    printf("VALID: PASS\n");

    /* -------------------- INVALID (hash sanity) -------------------- */
    size_t inv_len = 0;
    unsigned char *inv = read_file("pqnas_qrauth_v4_test_vector_invalid.md", &inv_len);
    if (inv) {
        const char *invs = (const char*)inv;

        char *tampered = extract_fenced(invs, "Tampered req_token (used in signing)");
        char *wronghash = extract_fenced(invs, "Wrong req_hash_b64");

        if (!tampered || !wronghash) {
            printf("INVALID: SKIP (could not parse invalid vector file)\n");
        } else {
            strip_ws_inplace(tampered);
            strip_ws_inplace(wronghash);

            unsigned char wh[32];
            sha256((const unsigned char*)tampered, strlen(tampered), wh);
            char wh_b64[256];
            b64url_encode(wh, 32, wh_b64, sizeof(wh_b64));

            if (strcmp(wh_b64, wronghash) != 0) {
                printf("INVALID: FAIL\n");
                free(inv);
                return 1;
            }

            unsigned char ch[32];
            sha256((const unsigned char*)req_token, strlen(req_token), ch);
            char ch_b64[256];
            b64url_encode(ch, 32, ch_b64, sizeof(ch_b64));

            if (strcmp(ch_b64, wronghash) == 0) {
                printf("INVALID: FAIL\n");
                free(inv);
                return 1;
            }

            printf("INVALID: PASS (expected mismatch detected)\n");
        }

        free(inv);
    } else {
        printf("INVALID: SKIP (file missing)\n");
    }

    /* -------------------- INVALID_PROOF (signature mismatch) -------------------- */
    size_t invp_len = 0;
    unsigned char *invp = read_file("pqnas_qrauth_v4_test_vectors_invalid_proof.md", &invp_len);
    if (invp) {
        char *proof_token_invalid = extract_fenced((const char*)invp, "proof_token_invalid");
        if (!proof_token_invalid) {
            printf("INVALID_PROOF: SKIP (could not parse invalid proof file)\n");
        } else {
            strip_ws_inplace(proof_token_invalid);

            int rc = verify_proof_token(proof_token_invalid, req_token, server_pk);
            if (rc == 0) {
                printf("INVALID_PROOF: FAIL (unexpectedly verified)\n");
                free(invp);
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