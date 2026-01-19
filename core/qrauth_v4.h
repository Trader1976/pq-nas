#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
    qrauth_v4.h (C API)
    ===================

    This header exposes the v4 QR-auth verification API used by the server.

    Roles / responsibilities
    ------------------------
    - Parsing + format validation of tokens
    - Verification of request token authenticity (server Ed25519 signature)
    - Verification of proof token authenticity (phone signature; PQClean in full v4)
    - Binding checks (proof must bind to the exact req_token_expected)
    - Identity binding (fingerprint <-> public key binding, per protocol rules)

    Security design note
    --------------------
    The server should treat these functions as the *single source of truth* for
    cryptographic verification and binding checks. The server's "policy" layer
    (allowlist roles) should be applied only after QR_OK is returned.
    */

    // Error codes (0 = success).
    //
    // Convention:
    // - QR_ERR_FORMAT/B64/JSON are input/parse failures (HTTP 400).
    // - Signature/binding errors are authorization failures (HTTP 403).
    typedef enum {
        QR_OK = 0,
        QR_ERR_FORMAT = 10,     // Token envelope/segments malformed
        QR_ERR_B64 = 11,        // base64/base64url decode failed
        QR_ERR_JSON = 12,       // payload JSON parse failed

        QR_ERR_SERVER_PK = 20,  // server_pk_raw missing/invalid length/etc
        QR_ERR_REQ_SIG = 21,    // req_token signature invalid (not minted by server)

        QR_ERR_REQ_MISMATCH = 30, // proof does not bind to the exact req_token_expected
        QR_ERR_PK_DECODE = 31,    // public key decode/parse failure (format depends on protocol)
        QR_ERR_FP_BINDING = 32,   // fingerprint <-> public key binding failed

        QR_ERR_PHONE_SIG = 40,  // phone signature invalid (identity proof failed)
    } qr_err_t;

    // Proof claims (extracted from proof_token payload).
    //
    // IMPORTANT:
    // - fingerprint_b64 is a textual base64/base64url representation of the user's fingerprint.
    // - It is NOT hex. Callers must not treat it as hex without explicit conversion.
    // - ts is a timestamp extracted from the proof payload (units/semantics defined by protocol).
    //
    // Size note:
    // fingerprint_b64[128] leaves room for typical base64url strings; callers should still
    // treat it as untrusted data and validate length/charset if needed.
    typedef struct {
        char fingerprint_b64[128];
        long ts;
    } qr_proof_claims_t;

    // Extract proof claims without performing full verification.
    //
    // Security note:
    // Callers should normally prefer qr_verify_proof_token() first. Extracting claims from an
    // unverified token must not be used for authorization decisions.
    qr_err_t qr_extract_proof_claims(const char *proof_token, qr_proof_claims_t *out);

    // Remove all ASCII whitespace chars from string in-place.
    // Useful for tokens copied from markdown code fences (line-wrapping etc).
    //
    // Security note:
    // This is safe only if the token grammar never includes whitespace. For base64url tokens
    // that is typically true.
    void qr_strip_ws_inplace(char *s);

    // Verify req_token using server public key (Ed25519) over SHA256(req_payload_bytes).
    // server_pk_raw must be 32 bytes.
    //
    // Security purpose:
    // Ensures the request token shown to the user was minted by this server and not tampered with.
    qr_err_t qr_verify_req_token(const char *req_token, const unsigned char server_pk_raw[32]);

    // Verify proof_token and bind it to the exact req_token_expected.
    //
    // proof_token = base64url(payload_json) "." base64url(phone_sig)
    // req_token_expected is the *exact* request token string that this proof must bind to.
    //
    // Security properties (conceptual):
    // - verifies req_token signature (server authenticity)
    // - verifies phone signature (identity proof; PQClean ML-DSA-87 in full v4 design)
    // - enforces binding: proof must reference req_token_expected
    // - enforces fingerprint binding rules (fingerprint <-> public key)
    qr_err_t qr_verify_proof_token(
        const char *proof_token,
        const char *req_token_expected,
        const unsigned char server_pk_raw[32]
    );

#ifdef __cplusplus
}
#endif
