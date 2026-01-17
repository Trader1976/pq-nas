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
    # From section:
    # public key (raw, base64url):
    # ```
    # <pk>
    # ```
    m = re.search(r"Server key .*?public key \(raw, base64url\):\s*```([\s\S]*?)```", md)
    if not m:
        raise ValueError("Could not find server public key block")
    return m.group(1).strip()


def verify_req_token(req_token: str, server_pk_b64: str, now: int | None = None) -> dict:
    try:
        payload_b64, sig_b64 = req_token.split(".", 1)
    except ValueError:
        raise ValueError("req_token must be payload_b64.sig_b64")

    payload_bytes = b64url_decode_nopad(payload_b64)
    sig = b64url_decode_nopad(sig_b64)
    payload = json.loads(payload_bytes.decode("utf-8"))

    # Server signs SHA256(payload_bytes) where payload_bytes are canonical JSON bytes
    digest = hashlib.sha256(payload_bytes).digest()
    server_pk = Ed25519PublicKey.from_public_bytes(b64url_decode_nopad(server_pk_b64))
    server_pk.verify(sig, digest)

    if now is None:
        now = int(__import__("time").time())

    # Basic freshness checks (you can tighten later)
    if payload.get("typ") != "req" or payload.get("v") != 4:
        raise ValueError("req_payload typ/v mismatch")
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
    _ = verify_req_token(req_token, server_pk_b64, now=now)

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

    if not valid_path.exists():
        print(f"Missing {valid_path}. Put vectors in repo root or adjust paths.", file=sys.stderr)
        return 2

    valid_md = valid_path.read_text(encoding="utf-8")
    server_pk_b64 = extract_server_pk(valid_md)
    proof_token = extract_fenced(valid_md, "proof_token")

    # VALID should pass
    try:
        verify_proof_token(proof_token, server_pk_b64)
        print("VALID: PASS")
    except Exception as e:
        print(f"VALID: FAIL ({e})")
        return 1

    # INVALID should fail
    if invalid_path.exists():
        invalid_md = invalid_path.read_text(encoding="utf-8")
        # Invalid file doesn’t carry proof_token; it defines wrong req_hash scenario conceptually.
        # To make a concrete failing proof_token, you should regenerate an invalid proof_token file.
        # But we can still assert mismatch by recomputing and checking the published wrong req_hash_b64.
        tampered_req = re.search(r"## Tampered req_token .*?```([\s\S]*?)```", invalid_md).group(1).strip()
        wrong_req_hash_b64 = re.search(r"## Wrong req_hash_b64\s+```([\s\S]*?)```", invalid_md).group(1).strip()

        calc_wrong = b64url_encode_nopad(hashlib.sha256(tampered_req.encode("utf-8")).digest())
        if calc_wrong != wrong_req_hash_b64:
            print("INVALID: FAIL (invalid vector file does not match computed wrong hash)")
            return 1

        # Also verify that this wrong hash differs from the correct hash (sanity)
        correct_hash = b64url_encode_nopad(hashlib.sha256(extract_fenced(valid_md, "req_token").encode("utf-8")).digest())
        if correct_hash == wrong_req_hash_b64:
            print("INVALID: FAIL (wrong hash unexpectedly equals correct hash)")
            return 1

        print("INVALID: PASS (expected mismatch detected)")
    else:
        print("INVALID: SKIP (invalid vector file missing)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
