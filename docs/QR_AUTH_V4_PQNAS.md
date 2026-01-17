PQ-NAS QR-Auth v4 (Stateless) Spec
1) Entities

Origin Server (PQ-NAS): generates login requests and signs the request token

Verifier: can be the same box or separate nodes; must be able to validate without DB/session state

Client Browser: displays QR, later presents proof to get a browser session

DNA-Messenger (Phone): user approval + signs a canonical payload with DNA identity key

2) Token Types
A) req — Request Token (server-signed, stateless)

This is what the QR encodes (or a URL containing it).

Purpose: prove the QR request was issued by the NAS and hasn’t expired.
Verifier checks: server signature + expiry + origin + audience.

B) proof — Approval Proof (phone-signed)

This is what the phone returns (to NAS over HTTPS or via browser paste/deeplink/redirect).

Purpose: prove the user approved and signed the request challenge with their DNA identity.

3) QR contents (what’s encoded)

Recommended format: URL with a single req parameter.

Example:

https://nas.example.com/qrauth?v=4&req=<BASE64URL(req_token)>


You can also use an app link/custom scheme, but HTTPS URL is easiest.


4) Request token (req_token) format
4.1 Fields (JSON)
{
  "v": 4,
  "typ": "req",
  "iss": "pq-nas",
  "aud": "dna-messenger",
  "origin": "https://nas.example.com",
  "sid": "Tr85XMc-udOkg4D-CTOKuw4-0brHQX_U",
  "chal": "b64url(random_32_bytes)",
  "iat": 1768620000,
  "exp": 1768620060,
  "scope": "pqnas.login",
  "nonce": "b64url(random_16_bytes)"
}
4.2 Canonicalization for server signature

To avoid “JSON ordering” problems, the server signs:

SHA256(canonical_json(req_fields))

Canonical JSON rules (MUST):

UTF-8

No whitespace outside strings

Keys sorted lexicographically

Numbers are base-10 with no leading zeros

Strings must be standard JSON escaping

Arrays preserve order

(Implementation: RFC 8785 JCS is perfect if available; otherwise implement minimal JCS subset.)4.3 req_token encoding

req_token = BASE64URL( canonical_json(req_fields) ) + "." + BASE64URL(server_sig)

Where:

server_sig = Sign(server_signing_key, SHA256(canonical_json(req_fields)))

Server signature algorithm:

for v0 you can use Ed25519 (fast and easy)

later you can switch to Dilithium/ML-DSA when you want

The phone does not need to verify the server signature in v0 (optional), but it’s good UX/security if it can.

5) Approval proof (proof) format (phone-signed)
5.1 Fields (JSON)
{
  "v": 4,
  "typ": "proof",
  "req": "<BASE64URL(req_token)>",
  "fingerprint": "<sha3-512-hex>",
  "pk": "<base64url(public_key_bytes)>",
  "pk_alg": "ML-DSA-87",
  "ts": 1768620005,
  "device": {
    "app": "dna-messenger",
    "ver": "0.99.105",
    "platform": "android"
  }
}

Important: proof includes the full req_token (or its hash). This is what makes the flow stateless on the verifier.

5.2 What exactly the phone signs

To prevent ambiguity, the phone signs a deterministic signing string derived from the req token.

Signing input:

msg = "DNAQR-V4\n" + SHA256(req_token_bytes) + "\n" + fingerprint + "\n" + ts

Where:

req_token_bytes is the raw bytes of the req_token string (ASCII/UTF-8)

SHA256(req_token_bytes) is 32 bytes, then encode as lowercase hex (or base64url—pick one and freeze it)

Pick one and freeze it; I recommend hex here to avoid padding mistakes.

So the message is literally:

DNAQR-V4
<64 hex chars of sha256(req_token)>
<fingerprint hex>
<unix ts>

Then:

sig = Sign(DNA_identity_private_key, SHA3-512(msg_bytes)) (or SHA256; choose one; just freeze it)

Encode signature as base64url without padding

5.3 Proof encoding

proof_token = BASE64URL(canonical_json(proof_fields_without_sig)) + "." + BASE64URL(sig)

Where proof_fields_without_sig includes everything except sig.

6) Verification steps (fully stateless)

Given proof_token:

Parse into (proof_payload_b64, sig_b64)

Decode proof_payload JSON

Verify proof_payload.v == 4, typ == "proof"

Extract req_token from proof_payload.req

Verify req_token:

parse (req_payload_b64, server_sig_b64)

verify server signature over SHA256(canonical_json(req_payload))

check exp >= now and iat <= now + skew

check origin matches configured allowed origins

check scope == "pqnas.login"

Verify fingerprint↔pk binding:

fingerprint == SHA3-512(pk_bytes) (or whatever your DNA fingerprint definition is—freeze it)

Recompute signing message:

msg = "DNAQR-V4\n" + sha256_hex(req_token) + "\n" + fingerprint + "\n" + ts

Verify phone signature using pk and pk_alg

Check ts freshness window (e.g., ±60s)

If all pass → issue browser session token bound to fingerprint + permissions

No DB/session storage required.

Replay resistance:

req_token expires quickly (e.g., 60–120s)

verifier checks exp and ts

for stricter anti-replay you can add an optional tiny cache of recently seen sha256(req_token) for exp duration (not required for stateless mode, but cheap)

7) Canonicalization summary (freeze this early)

You’ll have fewer “base64 decode signature thing” bugs if you lock these choices now:

All binary blobs are base64url without padding

req_token and proof_token are payload_b64 + "." + sig_b64

Canonical JSON uses JCS / RFC 8785 rules (or your minimal equivalent)

Phone signs a text message derived from:

hash of the req_token string

fingerprint

timestamp

Hash choice is frozen (e.g., SHA256 for req_token hashing; SHA3-512 for message prehash if you want DNA-style consistency)

8) Minimal endpoints for PQ-NAS v0

GET / → shows QR

GET /api/v4/qr/req → returns req_token (and maybe QR svg)

POST /api/v4/qr/proof → accepts proof_token, returns browser session token/cookie

GET /app → file UI (requires session)

What I’d lock right now (recommended exact picks)

If you want the least pain:

JCS (RFC 8785) canonical JSON

req server signature: Ed25519 for v0

phone signature: your existing PQClean Dilithium/ML-DSA choice (whatever DNA identity uses)

hashes:

sha256(req_token_string) for binding

sha3_512(msg) before PQ signature (optional; if your verifier expects prehash)
