## QR Auth v4 (Stateless) — Current Working Behavior

PQ-NAS implements v4 stateless QR authentication compatible with DNA-Messenger (feature freeze on the app side, so server must match the app exactly).

### Endpoints

#### Create session + QR
POST /api/v4/session

Returns:
- `sid`, `expires_at`, `st`, and `qr_uri` (dna://auth URI that the browser renders as a QR code)

#### Verify phone response
POST /api/v4/verify

Accepts the DNA-Messenger response envelope, verifies:
- Ed25519 `st` token validity + TTL
- `st_hash` binding (SHA256(st) -> standard base64 with padding)
- origin + rp_id_hash binding
- fingerprint(pubkey) matches claimed fingerprint (sha3_512(pubkey) hex)
- PQ signature validity using `qgp_dsa87_verify` from `libdna_lib.so`

On success returns:
- `{ "ok": true, "v": 4, "at": "v4.<payload>.<sig>" }`

### Required environment variables

Keys (base64url no padding):
- `PQNAS_SERVER_PK_B64URL` (32 bytes)
- `PQNAS_SERVER_SK_B64URL` (64 bytes)
- `PQNAS_COOKIE_KEY_B64URL` (32 bytes)

Deployment binding:
- `PQNAS_ORIGIN` (must match the tunnel/website origin shown in the QR)
- `PQNAS_RP_ID` (domain; rp_id_hash is derived from lowercase rp_id)

Operational:
- `PQNAS_LISTEN_PORT`
- `PQNAS_REQ_TTL`
- `PQNAS_SESS_TTL`

### Native library requirement (Linux)
PQ verification currently loads `libdna_lib.so` and calls `qgp_dsa87_verify`.
Make sure it is discoverable at runtime:
- copy `libdna_lib.so` next to the server binary, and/or
- export `LD_LIBRARY_PATH` to include its directory

Example:
LD_LIBRARY_PATH=./build/bin ./build/bin/pqnas_server

### Common failure: wrong tunnel/origin
If the phone shows:
Network error: Failed host lookup: '<old-tunnel>.trycloudflare.com'
then the QR contains the wrong origin.

Fix by ensuring:
- `PQNAS_ORIGIN` is set to the currently active tunnel URL
- the QR URI uses that `origin` value when generated
