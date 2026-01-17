#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Error codes (0 = success)
    typedef enum {
        QR_OK = 0,

        QR_ERR_FORMAT = 10,
        QR_ERR_B64 = 11,
        QR_ERR_JSON = 12,

        QR_ERR_SERVER_PK = 20,
        QR_ERR_REQ_SIG = 21,

        QR_ERR_REQ_MISMATCH = 30,
        QR_ERR_PK_DECODE = 31,
        QR_ERR_FP_BINDING = 32,

        QR_ERR_PHONE_SIG = 40,
    } qr_err_t;

    // Remove all ASCII whitespace chars from string in-place.
    // Useful for tokens copied from markdown code fences (line-wrapping etc).
    void qr_strip_ws_inplace(char *s);

    // Verify req_token using server public key (Ed25519) over SHA256(req_payload_bytes).
    // server_pk_raw must be 32 bytes.
    qr_err_t qr_verify_req_token(const char *req_token, const unsigned char server_pk_raw[32]);

    // Verify proof_token (Ed25519 TEST) over prehash bytes.
    // Also verifies req_token signature (server) and fingerprint binding.
    // proof_token = base64url(payload_json).base64url(phone_sig)
    // req_token_expected is the *exact* req_token string you expect proof to bind to.
    qr_err_t qr_verify_proof_token(
        const char *proof_token,
        const char *req_token_expected,
        const unsigned char server_pk_raw[32]
    );

#ifdef __cplusplus
}
#endif
