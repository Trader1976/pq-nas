## v4 Stateless QR Auth — Locked Working Spec (PQ-NAS)

This document reflects the current working, end-to-end implementation used by PQ-NAS + DNA-Messenger.

### QR URI format (what the browser renders as QR)
dna://auth?v=4&st=<URL-ENCODED_ST>&origin=<URL-ENCODED_ORIGIN>&app=<URL-ENCODED_APP_NAME>

Notes:
- `st` MUST be URL-encoded when placed into the QR URI.
- `origin` is the HTTPS base URL of the relying party / web UI (often the Cloudflare tunnel URL).
- `app` is a display label shown in the phone UI (e.g. "PQ-NAS").

### /api/v4/session response (server -> browser)
POST /api/v4/session returns JSON:
- v (4)
- sid (session id)
- expires_at (epoch seconds)
- st (the signed server token)
- req (same as st; kept for compatibility/debug)
- qr_uri (ready-to-render DNA URI)

### Server token `st` (Ed25519, stateless)
Wire format:
v4.<payload_b64url_no_pad>.<sig_b64url_no_pad>

Signing rule:
- signature is Ed25519 over RAW payload bytes (the JSON bytes)
- payload is canonical JSON with stable order and no whitespace

The `st` payload includes:
aud, chal, expires_at, issued_at, iss, nonce, origin, rp_id, rp_id_hash, scope, sid, typ="st", v=4

### Phone response envelope (phone -> server)
POST /api/v4/verify with JSON:
{
"type": "dna.auth.response",
"v": 4,
"st": "<the st token string>",
"fingerprint": "<sha3_512(pubkey) hex lowercase>",
"pubkey_b64": "<base64 pubkey bytes>",
"signature": "<base64 signature bytes>",
"session_id": "<string>",
"signed_payload": {
"expires_at": <int>,
"issued_at": <int>,
"nonce": "<string>",
"origin": "<string>",
"rp_id_hash": "<string>",
"session_id": "<string>",
"sid": "<string>",
"st_hash": "<string>"
}
}

### Canonical signing bytes for PQ signature (CRITICAL)
The PQ signature verifies over canonical JSON bytes created from signed_payload fields in THIS EXACT ORDER:
expires_at, issued_at, nonce, origin, rp_id_hash, session_id, sid, st_hash

No whitespace, stable key order.

### st_hash computation (CRITICAL)
st_hash = base64( SHA256( st_string_bytes ) )  using STANDARD base64 WITH padding (=)

This must match Python’s base64.b64encode output behavior.

### Fingerprint computation (CRITICAL)
fingerprint = sha3_512(pubkey_bytes) as lowercase hex
(pubkey_bytes are the raw decoded pubkey bytes from pubkey_b64)

### PQ verification function (current working)
We verify using the function exported by libdna_lib.so:
qgp_dsa87_verify(sig, siglen, msg, msglen, pk)

Important:
- Return value convention: 0 = valid, nonzero = invalid (this is the Dilithium verify convention).
