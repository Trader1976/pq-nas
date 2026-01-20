> ## v4 Stateless QR Auth — Locked Working Spec (PQ-NAS)
>
> This document reflects the **current, working, end-to-end implementation**
> used by **PQ-NAS** and **DNA-Messenger**.
>
> It is **implementation-driven**: the code is authoritative.
> This document exists to describe what the system actually does today.
>
> ---
>
> ### QR URI format (what the browser renders as QR)
>
> ```
> dna://auth?v=4&req=<URL-ENCODED_REQ>&origin=<URL-ENCODED_ORIGIN>&app=<URL-ENCODED_APP_NAME>
> ```
>
> Notes:
> - `req` MUST be URL-encoded when placed into the QR URI.
> - `origin` is the HTTPS base URL of the relying party / web UI
    >   (often a Cloudflare Tunnel URL).
> - `app` is a display label shown in the phone UI (e.g. "PQ-NAS").
>
> ---
>
> ### /api/v4/session response (server → browser)
>
> `POST /api/v4/session` returns JSON:
>
> - `v` (4)
> - `sid` (session id; informational only)
> - `expires_at` (epoch seconds)
> - `req` (the signed server request token)
> - `qr_uri` (ready-to-render DNA URI)
>
> Notes:
> - `req` is the **authoritative server-issued token**.
> - The server does **not** store session state for `req`.
>
> ---
>
> ### Server request token `req` (Ed25519, stateless)
>
> **Wire format:**
>
> ```
> base64url_no_pad(payload_json) "." base64url_no_pad(signature)
> ```
>
> **Signing rule:**
> - Signature algorithm: **Ed25519**
> - Signature input: `SHA256(payload_json_bytes)`
> - Signed using the server’s long-term Ed25519 private key
>
> **Payload encoding:**
> - Canonical JSON
> - Stable key order
> - No whitespace
> - Exact byte preservation is critical
>
> **The `req` payload includes:**
>
> ```
> aud, chal, exp, iat, iss, nonce, origin, scope, sid, typ="req", v=4
> ```
>
> ---
>
> ### Phone proof submission (phone → server)
>
> The phone produces **one opaque proof token**.
> The server does **not** accept partially structured cryptographic fields.
>
> `POST /api/v4/verify` with JSON:
>
> ```json
> {
>   "type": "dna.auth.proof",
>   "v": 4,
>   "req": "<exact req token string>",
>   "proof": "<opaque proof token>"
> }
> ```
>
> Notes:
> - `req` MUST match **exactly** the token issued by the server.
> - `proof` is a self-contained structure produced by the phone.
>
> ---
>
> ### Proof verification (CRITICAL)
>
> The server verifies the proof using:
>
> ```c
> qr_verify_proof_token(proof, req, server_pk)
> ```
>
> Conceptually, verification enforces **all** of the following:
>
> 1. **Server authenticity**
     >    - `req` signature is verified using the server’s Ed25519 public key
>
> 2. **Request binding**
     >    - Proof is bound to the *exact* `req` string
>    - Replay against a different request is rejected
>
> 3. **Canonical signing**
     >    - Signatures verify over canonical, byte-stable payloads
>
> 4. **Identity proof**
     >    - Phone signature is verified using post-quantum–capable algorithms  
            >      (ML-DSA-87 / Dilithium-class via PQClean)
>
> 5. **Fingerprint binding**
     >    - Identity fingerprint is cryptographically bound to the public key
>
> 6. **Origin binding**
     >    - Proof is bound to the expected relying-party origin
>
> Verification is **fail-closed**.
>
> ---
>
> ### Extracted claims
>
> After successful verification, the server may extract claims:
>
> ```c
> typedef struct {
>     char fingerprint_b64[128];
>     long ts;
> } qr_proof_claims_t;
> ```
>
> Notes:
> - `fingerprint_b64` is the **canonical identity string** used by PQ-NAS.
> - This value is treated as opaque by policy and session layers.
>
> ---
>
> ### Authorization and session minting
>
> - Cryptographic verification proves identity.
> - Authorization is enforced separately via fingerprint allowlist.
> - On success, the server mints a **short-lived browser session cookie**
    >   with `HttpOnly`, `Secure`, and `SameSite=Lax`.
>
> ---
>
> ### Statelessness clarification
>
> - Verification is **stateless**: no authentication session state is required
    >   to verify a proof.
> - The system is **not globally stateless**: audit logs, allowlists, and
    >   one-time consume semantics are intentionally stateful.
>
> ---
>
> ### Status
>
> This specification is **locked to the current working implementation**.
>
> Any change to:
> - payload fields or order
> - hashing or signature rules
> - identity representation
> - binding semantics
>
> MUST be accompanied by:
> - code changes
> - updated test vectors
> - updates to this document
>
> **Do not diverge silently.**
