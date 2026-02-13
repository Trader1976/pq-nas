# QR-Auth v5 — Request Token (`st`) and Browser Finalization

QR-Auth v5 is a short-lived, server-authenticated sign-in request that is approved by a DNA identity (mobile) and then **finalized in the browser** by consuming an approval and receiving a **browser session cookie**.

v5 is designed to be **stateless-ready** on the browser side:
- the browser polls using `k`, a correlation key derived from the signed request token (`st`)
- the server stores approval/pending state keyed by `k` (not by `sid`)

---

## 1) Request Token (`st`) — what it is

The server issues a signed request token (`st`) when initiating authentication.

- `st` is **not** a login by itself.
- `st` is **server-authenticated** and **short-lived**.
- `st` is embedded into the QR URI and scanned by the DNA mobile client.
- `st` is also used by the browser to poll status via `k = SHA256(st) (base64 std)`.

> Terminology:
> - **st** = signed request token (server-issued)
> - **k** = correlation key derived from st, used for polling + consume
> - **pending** = server knows this sign-in request but it’s not approved yet
> - **approved** = server has minted a cookie for this request and is ready to hand it to the browser on consume

---

## 2) `st` payload (canonical JSON, UTF-8)

The payload is encoded as **canonical JSON**:
- stable key order
- no whitespace
- exact byte preservation (server verifies signatures over these exact bytes)

Fields included (v5 request token payload):

- `v` (5)
- `typ` ("req")
- `sid` (string) *(optional legacy correlation; do not rely on it for v5)*
- `origin` (HTTPS origin, e.g. `https://example.com`)
- `nonce` (string)
- `chal` (string)
- `aud` (string)
- `iss` (string)
- `scope` (string)
- `iat` (epoch seconds)
- `exp` (epoch seconds)

> Notes:
> - `origin` is the server’s expected web origin binding.
> - `chal`/`nonce` are fresh per session issuance.
> - `sid` may exist for debugging/legacy, but v5 correlation should use `k` derived from `st`.

---

## 3) `st` wire format

Same compact signed-token format:
  base64url_no_pad(payload_json_bytes) "." base64url_no_pad(signature)

---

## 4) Signing rule

- Compute `digest = SHA256(payload_json_bytes)`
- Compute `signature = Ed25519_sign(digest, server_sk)`

---

## 5) Correlation key (`k`) — v5 polling/consume key

v5 derives a correlation key from the **signed request token**:
  k = base64_std( SHA256( st_bytes ) )

Where:
- `st_bytes` is the exact UTF-8 string of the request token (the full `<b64url(payload)>.<b64url(sig)>`)
- `base64_std` is standard base64 (may include `+` and `/` and `=` padding)

### URL/query caveat
If `k` is transported in query parameters, `+` may be decoded as space by some stacks. Normalize by replacing spaces back to `+` and trimming whitespace.

---

## 6) QR URI format (what the browser shows)

The QR code encodes a URI like:
  dna://auth?v=5&st=<urlencoded(st)>&origin=<urlencoded(origin)>&app=<urlencoded(app)>

Minimum:
- `v=5`
- `st=...`
- `origin=...`
- `app=...` (server-defined app label)

The mobile client scans this, verifies the request token (`st`), and then calls server verify.

---

## 7) Server endpoints (web + mobile)

### 7.1 Browser: create sign-in request

**POST `/api/v5/session`**

Returns JSON containing:
- `st` (signed request token)
- `k` (derived correlation key)
- `exp` / `iat`
- `qr_svg` (URL to QR SVG or SVG payload, implementation dependent)

The server may immediately mark `k` as pending with reason `"awaiting_scan"`.

---

### 7.2 Mobile: verify + request approval (DNA client)

The DNA client submits a verification payload to the server’s verify endpoint (implementation uses the shared verify logic).

On success:
- server performs crypto verification + binding checks (origin/rp_id, fingerprint bindings, signature validity)
- server enforces **fail-closed** policy:
    - unknown fingerprint → create disabled user → return 403 "user disabled"
    - disabled user → return 403 "user disabled"
    - enabled user → proceed

If enabled:
- server mints a browser session cookie value (signed cookie token)
- server stores an **approval entry** keyed by `approval_key` where:

  approval_key = st_hash_b64 (v5)

Where `st_hash_b64` is the server’s stored/derived hash value bound to the verified request token.

The server also stores/updates pending state reason `"pending_admin"` when user is not enabled.

> v5 keying rule:
> - v4 used `sid` for correlation
> - v5 should key approval/pending by the request token hash (stateless-ready)

---

### 7.3 Browser: poll status

**POST `/api/v5/status`** with JSON body:

- preferred: `{ "k": "<k>" }`
- fallback: `{ "st": "<st>" }` (server derives `k`)

Returns:
- `state: "pending"` + `reason` (e.g. `"awaiting_scan"` or `"pending_admin"`)
- OR `state: "approved"` (or `approved: true`)
- OR `state: "missing"` (server no longer has this request)

---

### 7.4 Browser: consume approval → receive cookie

**POST `/api/v5/consume`** with JSON body:

- preferred: `{ "k": "<k>" }`
- fallback: `{ "st": "<st>" }`
- legacy: `{ "sid": "<sid>" }` (avoid for v5)

Server behavior:
1) Resolve approval key from `k` (or derive from `st`)
2) Require approval entry exists, else `409 not_approved`
3) Emit `Set-Cookie` header:
    - cookie name: `pqnas_session`
    - cookie value: `<signed-cookie-token>`
    - attributes: `Path=/; HttpOnly; SameSite=None; Secure`
4) Return JSON `{ ok:true, state:"consumed", ... }`
5) Browser verifies cookie by calling `/api/v4/me` and then redirects to `/app`

Important:
- `SameSite=None` requires `Secure` in modern browsers.
- If you are testing without HTTPS, browsers may drop `Secure` cookies.

---

## 8) Admin approval UX (fail-closed)

When the server returns 403 "user disabled" during verification:
- browser should redirect to `/wait-approval?k=<k>` (or `st=` fallback)
- the wait page polls `/api/v5/status`
- when approved, it automatically calls `/api/v5/consume` and finalizes sign-in.

---

## 9) Security notes

- `st` is short-lived and server-authenticated (signed by server).
- The browser never “logs in” using `st` directly; it only uses it to correlate an approval flow.
- Approvals are one-time consumable; server should `pop` approval state on consume.
- Cookie integrity is enforced server-side by verifying the signed cookie token on every request.
- Prefer `k` for correlation to avoid relying on `sid`.

---

