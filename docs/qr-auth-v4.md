## QR-Auth v4 — Request Token (req_token)

The server issues a request token (req_token) when initiating authentication.

Payload (JSON, UTF-8, no whitespace guarantees required):

{
"v": 4,
"typ": "req",
"sid": "...",
"origin": "...",
"nonce": "...",
"issued_at": ...,
"expires_at": ...
}

The payload is base64url-encoded (no padding), then signed by the server
using Ed25519 over SHA-256(payload_bytes).
