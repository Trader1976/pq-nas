## QR-Auth v4 — Request Token (`req`)

The server issues a request token (`req`) when initiating authentication.
This token is server-authenticated and short-lived. It is not a login by itself.

### Payload (canonical JSON, UTF-8)

The payload is encoded as **canonical JSON**:
- stable key order
- no whitespace
- exact byte preservation (the server verifies signatures over these exact bytes)

Fields included:

- `v` (4)
- `typ` ("req")
- `sid` (string)
- `origin` (HTTPS origin)
- `nonce` (string)
- `chal` (string)
- `aud` (string)
- `iss` (string)
- `scope` (string)
- `iat` (epoch seconds)
- `exp` (epoch seconds)

### Wire format

base64url_no_pad(payload_json_bytes) "." base64url_no_pad(signature)


### Signing rule

- Compute `digest = SHA256(payload_json_bytes)`
- Compute `signature = Ed25519_sign(digest, server_sk)`
