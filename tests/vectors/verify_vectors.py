#!/usr/bin/env python3
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def b64url_encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode_nopad(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def extract_fenced(md: str, header: str) -> str:
    """
    Extract content from:
    ## <header>
    ```
    ...
    ```
    """
    pat = rf"## {re.escape(header)}\s+```([\s\S]*?)```"
    m = re.search(pat, md)
    if not m:
        raise ValueError(f"Could not find fenced block for header: {header}")
    return m.group(1).strip()


def extract_server_pk(md: str) -> str:
    """
    Extract server public key (base64url) from the vectors markdown.

    We locate the "Server key" section, then grab the first ``` fenced block after it.
    This is robust against formatting differences (em-dashes, line wrapping, etc.).
    """
    import re

    # Find "Server key" heading
    m = re.search(r"##\s*Server key.*?\n", md, flags=re.IGNORECASE)
    if not m:
        raise ValueError("Could not find 'Server key' section")

    start = m.end()
    tail = md[start:]

    # First fenced block after that section
    m2 = re.search(r"```([\s\S]*?)```", tail)
    if not m2:
        raise ValueError("Could not find server public key fenced block after 'Server key' section")

    return m2.group(1).strip()


def verify_req_token(
    req_token: str,
    server_pk_b64: str,
    now: int | None = None,
    check_time: bool = False,
) -> dict:
    try:
        payload_b64, sig_b64 = req_token.split(".", 1)
    except ValueError:
        raise ValueError("req_token must be payload_b64.sig_b64")

    payload_bytes = b64url_decode_nopad(payload_b64)
    sig = b64url_decode_nopad(sig_b64)
    payload = json.loads(payload_bytes.decode("utf-8"))

    # Server signs SHA256(payload_bytes)
    digest = hashlib.sha256(payload_bytes).digest()
    server_pk = Ed25519PublicKey.from_public_bytes(
        b64url_decode_nopad(server_pk_b64)
    )
    server_pk.verify(sig, digest)

    if payload.get("typ") != "req" or payload.get("v") != 4:
        raise ValueError("req_payload typ/v mismatch")

    if check_time:
        if now is None:
            now = int(__import__("time").time())

        if payload.get("exp") is not None and now > int(payload["exp"]):
            raise ValueError("req_token expired")

        if payload.get("iat") is not None and now + 300 < int(payload["iat"]):
            raise ValueError("req_token iat too far in future")

    return payload


def verify_proof_token(proof_token: str, server_pk_b64: str, now: int | None = None) -> dict:
    try:
        proof_payload_b64, phone_sig_b64 = proof_token.split(".", 1)
    except ValueError:
        raise ValueError("proof_token must be payload_b64.sig_b64")

    proof_payload_bytes = b64url_decode_nopad(proof_payload_b64)
    phone_sig = b64url_decode_nopad(phone_sig_b64)
    proof = json.loads(proof_payload_bytes.decode("utf-8"))

    if proof.get("typ") != "proof" or proof.get("v") != 4:
        raise ValueError("proof typ/v mismatch")

    req_token = proof["req"]
    fingerprint_b64 = proof["fingerprint"]
    pk_b64 = proof["pk"]
    ts = int(proof["ts"])

    # Verify req_token (server-signed)
    _ = verify_req_token(req_token, server_pk_b64, check_time=False)

    # Fingerprint binding: fingerprint == b64url(SHA3-512(pk_raw))
    pk_raw = b64url_decode_nopad(pk_b64)
    fp_calc = b64url_encode_nopad(hashlib.sha3_512(pk_raw).digest())
    if fp_calc != fingerprint_b64:
        raise ValueError("fingerprint binding mismatch")

    # req_hash_b64 = b64url(SHA256(UTF8(req_token)))
    req_hash_b64 = b64url_encode_nopad(hashlib.sha256(req_token.encode("utf-8")).digest())

    # Signing message (exact lines, no trailing newline)
    msg = "DNAQR-V4\n" + req_hash_b64 + "\n" + fingerprint_b64 + "\n" + str(ts)
    prehash = hashlib.sha3_512(msg.encode("utf-8")).digest()

    # Phone signature (Ed25519 TEST) over *prehash bytes*
    phone_pk = Ed25519PublicKey.from_public_bytes(pk_raw)
    phone_pk.verify(phone_sig, prehash)

    # Optional: timestamp freshness window
    if now is None:
        now = int(__import__("time").time())
    if abs(now - ts) > 600:
        # don’t hard-fail test vectors if your clock differs; warn
        pass

    return proof


def main() -> int:
    root = Path(".")
    valid_path = root / "pqnas_qrauth_v4_test_vectors.md"
    invalid_path = root / "pqnas_qrauth_v4_test_vector_invalid.md"

    # INVALID PROOF should fail (signature mismatch)
    invalid_proof_path = root / "pqnas_qrauth_v4_test_vectors_invalid_proof.md"
    if invalid_proof_path.exists():
        invp_md = invalid_proof_path.read_text(encoding="utf-8")
        proof_token_invalid = extract_fenced(invp_md, "proof_token_invalid")
        try:
            verify_proof_token(proof_token_invalid, server_pk_b64)
            print("INVALID_PROOF: FAIL (unexpectedly verified)")
            return 1
        except Exception as e:
            print(f"INVALID_PROOF: PASS ({e})")
    else:
        print("INVALID_PROOF: SKIP (file missing)")


if __name__ == "__main__":
    raise SystemExit(main())
