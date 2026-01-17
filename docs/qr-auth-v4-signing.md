QR-Auth v4 Signing Rules (Frozen)
Encoding conventions

All Base64 is base64url, no padding (= never appears).

All “strings” are UTF-8 bytes.

Tokens use ASCII . as a separator.

Newlines inside signed messages are ASCII LF: 0x0A (\n) only.
1) req_token (server-issued)
   Format
   req_token := payload_b64 "." sig_b64

Where:

payload_b64 = base64url-no-padding of payload_bytes

sig_b64 = base64url-no-padding of sig_bytes

Payload bytes

payload_bytes are the exact UTF-8 bytes of your JSON payload string.

Important: in your current code, the verifier does not parse JSON. It treats the decoded payload bytes as an opaque byte string. So whatever bytes you sign are the bytes that must verify.

Hashing rule (server)

Compute:
    digest32 = SHA-256(payload_bytes)



    The Ed25519 message is exactly the 32 digest bytes (not hex, not base64).

Verification rule

Verifier does:

digest32 = SHA-256(payload_bytes)
Ed25519.Verify(pk_server, sig_bytes64, digest32) == true

2) proof_token (phone-issued)
   Format
   proof_token := proof_payload_b64 "." phone_sig_b64

Where:

proof_payload_b64 = base64url-no-padding of proof_payload_bytes

phone_sig_b64 = base64url-no-padding of phone_sig_bytes

Proof payload bytes

proof_payload_bytes are UTF-8 bytes of a JSON string that must contain:

"pk":"<base64url(pk_raw_32)>"

"fingerprint":"<base64url(sha3_512(pk_raw_32))>"

"req":"<req_token_exact_string>"

"ts":<unix_seconds_integer>

The current implementation extracts those fields by substring search.

Fingerprint binding (required)

Let pk_raw_32 be the decoded "pk" value (32 bytes).

Compute:
fp_calc_64 = SHA3-512(pk_raw_32)
fp_calc_b64 = base64url(fp_calc_64)
Require:
fp_calc_b64 == value_of("fingerprint")
Request binding (required)

Require:
fp_calc_b64 == value_of("fingerprint")


Where req_token_expected is the exact string presented to the phone (including the dot and signature).
Request-hash (for phone message)

Compute:
req_hash_32 = SHA-256( UTF8(req_token_expected) )
req_hash_b64 = base64url(req_hash_32)
Note: the SHA-256 input is the UTF-8 bytes of the full req_token string, not the decoded payload.

Canonical phone message bytes

Construct this ASCII/UTF-8 string exactly:
message_str =
"DNAQR-V4\n" +
req_hash_b64 + "\n" +
fp_b64 + "\n" +
ts_decimal
Where:

\n is LF (0x0A)

fp_b64 is the fingerprint field string (base64url, no padding)

ts_decimal is the base-10 ASCII representation of ts with no spaces, no plus sign.

Then:
message_bytes = UTF8(message_str)
Prehash rule (phone)

Compute:
prehash_64 = SHA3-512(message_bytes)

Signature rule (phone, Ed25519 test)

Compute:
The Ed25519 message is exactly the 64 prehash bytes.

Verification rule

Verifier recomputes all steps above and runs:
Ed25519.Verify(pk_raw_32, phone_sig_bytes64, prehash_64) == true

3) Token whitespace handling

Your helper:

qr_strip_ws_inplace(char*) removes ASCII whitespace from a token string.

Freeze rule:
Whitespace stripping is allowed only as a pre-processing step on the token strings if they came from markdown/wrapped transport. After stripping, the token string used for hashing/binding must be the stripped one consistently on both sides.

Practical: apply qr_strip_ws_inplace() to:

incoming req_token and proof_token strings before verification

never apply it to decoded payload JSON (payload bytes must remain exactly as signed)
4) Summary: “what is hashed, what is signed”

req_token

hashed: SHA-256(payload_bytes)

signed: Ed25519 over the 32 digest bytes

proof_token

hashed (for binding): SHA-256(UTF8(req_token_string)) → base64url

message built: "DNAQR-V4\n" + req_hash_b64 + "\n" + fingerprint_b64 + "\n" + ts

hashed: SHA3-512(message_bytes)

signed: Ed25519 over the 64 prehash bytes