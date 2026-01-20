> ## QR Auth v4 (Stateless) — Current Working Behavior (PQ-NAS)
>
> This document describes the **current, working server-side behavior**
> of **PQ-NAS v4 stateless QR authentication**.
>
> The DNA-Messenger app is considered **feature-frozen** for v4.
> The server implementation MUST match the app’s behavior exactly.
>
> ---
>
> ### Endpoints
>
> #### Create session + QR
>
> `POST /api/v4/session`
>
> Returns JSON:
>
> - `v` (4)
> - `sid` (session id; informational only)
> - `expires_at` (epoch seconds)
> - `req` (signed server request token)
> - `qr_uri` (dna://auth URI rendered as a QR code by the browser)
>
> Notes:
> - `req` is the authoritative, server-issued token.
> - The server does **not** store authentication session state for `req`.
>
> ---
>
> #### Verify phone proof
>
> `POST /api/v4/verify`
>
> Accepts JSON:
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
> The server performs **fail-closed verification**, enforcing:
>
> - Ed25519 verification of the server-issued `req` token
> - Binding of the proof to the *exact* `req` string
> - Canonical payload verification
> - Post-quantum–capable signature verification
    >   (ML-DSA-87 / Dilithium-class via PQClean)
> - Cryptographic fingerprint ↔ public key binding
> - Origin / relying-party binding
> - Allowlist-based authorization (user/admin)
>
> On success:
> - A short-lived browser session cookie is minted
> - Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax`
>
> No access token is returned in the response body.
>
> ---
>
> ### Identity representation
>
> After successful verification, the server extracts:
>
> ```c
> char fingerprint_b64[128];
> ```
>
> Notes:
> - `fingerprint_b64` is the **canonical identity string** used by PQ-NAS
> - Policy checks, session cookies, and audit logs use this value
> - The fingerprint is treated as opaque outside the verifier
>
> ---
>
> ### Required environment variables
>
> #### Cryptographic keys (base64url, no padding)
>
> - `PQNAS_SERVER_PK_B64URL` — server Ed25519 public key (32 bytes)
> - `PQNAS_SERVER_SK_B64URL` — server Ed25519 private key (64 bytes)
> - `PQNAS_COOKIE_KEY_B64URL` — symmetric key for session cookies (32 bytes)
>
> #### Relying-party binding
>
> - `PQNAS_ORIGIN`
    >   - MUST match the HTTPS origin embedded in the QR code
>   - Typically the active Cloudflare Tunnel URL
>
> #### Operational
>
> - `PQNAS_LISTEN_PORT`
> - `PQNAS_REQ_TTL`   — request token lifetime (seconds)
> - `PQNAS_SESS_TTL`  — browser session lifetime (seconds)
>
> ---
>
> ### Native crypto library requirement (Linux)
>
> Post-quantum verification is performed inside the verifier library.
> The server dynamically links against `libdna_lib.so`.
>
> Ensure the library is discoverable at runtime:
>
> - Place `libdna_lib.so` next to the server binary, and/or
> - Set `LD_LIBRARY_PATH` to include its directory
>
> Example:
>
> ```
> LD_LIBRARY_PATH=./build/bin ./build/bin/pqnas_server
> ```
>
> ---
>
> ### Common failure: incorrect origin / tunnel mismatch
>
> If the phone displays:
>
> ```
> Network error: Failed host lookup: '<old-tunnel>.trycloudflare.com'
> ```
>
> Then the QR code contains an outdated origin.
>
> Fix by ensuring:
> - `PQNAS_ORIGIN` matches the currently active tunnel URL
> - The server is restarted after changing the tunnel
> - Newly generated QR codes embed the updated origin
>
> ---
>
> ### Status
>
> This document reflects **current working behavior**.
>
> Any change to:
> - request token format
> - verification rules
> - identity representation
> - cookie semantics
>
> MUST be accompanied by:
> - server code changes
> - updated test vectors
> - updates to this document
>
> **Do not diverge silently.**
