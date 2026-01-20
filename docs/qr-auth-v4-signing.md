## QR-Auth v4 Signing Rules (Frozen)

This document freezes the signing/verification rules for the **currently deployed v4 flow** in PQ-NAS.

Where rules are implemented inside the verifier (`qr_verify_proof_token`), the proof token is treated as an **opaque, self-contained object**. The server relies on the verifier as the single source of truth for proof parsing, binding, and cryptographic verification.

---

## Encoding conventions

- Token segment separator is ASCII `.` (0x2E).
- JSON strings are UTF-8.
- Base64 encoding used in request/proof tokens is **base64url** with **no padding** unless explicitly stated otherwise.
- If any canonical text is defined, newlines are ASCII LF only (`\n`, 0x0A).

---

## 1) Request token (`req`) — server-issued

### Wire format

req := payload_b64 "." sig_b64


Where:

- `payload_b64` = base64url(no padding) of `payload_bytes`
- `sig_b64`     = base64url(no padding) of `sig_bytes` (64 bytes)

### Payload bytes

`payload_bytes` are the exact UTF-8 bytes of the **canonical JSON** payload produced by the server:

- stable key order
- no whitespace
- exact byte preservation

(Verification recomputes the hash over these exact bytes.)

### Hashing + signature rule (server)

Compute:

- `digest32 = SHA-256(payload_bytes)`  (32 raw bytes)

Signature:

- `sig_bytes64 = Ed25519.Sign(server_sk, digest32)`

Important:
- The Ed25519 message is **exactly the 32 digest bytes** (not hex, not base64).

### Verification rule (server)

Verifier recomputes:

- `digest32 = SHA-256(payload_bytes)`
- `Ed25519.Verify(server_pk, sig_bytes64, digest32) == true`

---

## 2) Proof token (`proof`) — phone-issued (opaque)

### Wire format

proof := proof_payload_b64 "." proof_sig_b64


Where:

- `proof_payload_b64` = base64url(no padding) of opaque `proof_payload_bytes`
- `proof_sig_b64`     = base64url(no padding) of opaque `proof_sig_bytes`

### Verification rule (server)

The server verifies the proof using the verifier library:

```c
qr_verify_proof_token(proof, req_expected, server_pk_raw) == QR_OK
This function is the single source of truth for proof validation.

Conceptually, successful verification enforces all of the following:

req signature is valid for this server (server authenticity)

proof is bound to the exact req_expected string (request binding)

origin / relying-party binding checks succeed

identity proof signature verifies (post-quantum capable; PQClean ML-DSA-87 / Dilithium-class)

fingerprint ↔ public key binding checks succeed

any additional verifier-internal format, timestamp, and replay rules succeed

If verification fails, the server must fail closed (HTTP 403 for auth failures, 400 for format errors).

Extracted claims (post-verification)

After QR_OK, the server may extract claims:

qr_proof_claims_t {
  char fingerprint_b64[128];
  long ts;
}

Notes:

fingerprint_b64 is the canonical identity string used by PQ-NAS policy, cookies, and audit logs.

The proof token format and exact signature preimages are intentionally not re-specified here to avoid drift; they are defined by the verifier implementation.

3) Token whitespace handling (transport convenience)

qr_strip_ws_inplace(char*) removes ASCII whitespace characters from a token string.

Freeze rule:

Whitespace stripping is allowed only as a pre-processing step on incoming token strings that may have been copied through wrapped transports (e.g., markdown).

After stripping, the token string used for hashing/binding must be the stripped version consistently.

Never apply whitespace stripping to decoded JSON/payload bytes; payload bytes must remain exactly as signed.

Practical:

Apply whitespace stripping to incoming req and proof strings before verification.

Do not modify decoded payload bytes.

4) Summary: what is hashed, what is signed
req token

hashed: SHA-256(payload_bytes)

signed: Ed25519 over the 32 raw digest bytes

proof token

verified: by qr_verify_proof_token(proof, req_expected, server_pk_raw)

identity output: fingerprint_b64 + ts (claims extracted post-verification)