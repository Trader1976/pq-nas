#!/usr/bin/env python3
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url_encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode_nopad(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def extract_fenced(md: str, header: str) -> str:
    pat = rf"## {re.escape(header)}\s+```([\s\S]*?)```"
    m = re.search(pat, md)
    if not m:
        raise ValueError(f"Could not find fenced block for header: {header}")
    return m.group(1).strip()


def main() -> int:
    valid_path = Path("pqnas_qrauth_v4_test_vectors.md")
    out_path = Path("pqnas_qrauth_v4_test_vectors_invalid_proof.md")

    md = valid_path.read_text(encoding="utf-8")

    # Extract from valid vectors
    req_token = extract_fenced(md, "req_token")
    proof_token = extract_fenced(md, "proof_token")

    proof_payload_b64, _ = proof_token.split(".", 1)
    proof_payload_bytes = b64url_decode_nopad(proof_payload_b64)
    proof = json.loads(proof_payload_bytes.decode("utf-8"))

    fingerprint_b64 = proof["fingerprint"]
    ts = int(proof["ts"])

    # Tamper req_token ONLY for hash
    tampered_req_token = req_token[:-1] + ("A" if req_token[-1] != "A" else "B")

    wrong_req_hash_b64 = b64url_encode_nopad(
        hashlib.sha256(tampered_req_token.encode("utf-8")).digest()
    )

    # Build signing message with WRONG hash
    signing_message = (
            "DNAQR-V4\n"
            + wrong_req_hash_b64 + "\n"
            + fingerprint_b64 + "\n"
            + str(ts)
    )

    prehash = hashlib.sha3_512(signing_message.encode("utf-8")).digest()

    # Phone TEST private key: 0x2e repeated
    phone_sk = Ed25519PrivateKey.from_private_bytes(bytes([0x2E]) * 32)
    invalid_sig = phone_sk.sign(prehash)
    invalid_sig_b64 = b64url_encode_nopad(invalid_sig)

    proof_token_invalid = proof_payload_b64 + "." + invalid_sig_b64

    out_md = (
            "# PQ-NAS QR-Auth v4 Test Vector — INVALID PROOF (signature mismatch)\n\n"
            "This vector is a **full invalid proof_token** that MUST FAIL at phone "
            "signature verification.\n\n"
            "It reuses the exact same **proof_payload_b64** as the valid vector, but the "
            "signature is generated using a tampered `req_hash_b64`.\n\n"
            "---\n\n"
            "## req_token (verified)\n"
            "```\n" + req_token + "\n```\n\n"
                                  "## tampered_req_token (used ONLY for wrong hash during signing)\n"
                                  "```\n" + tampered_req_token + "\n```\n\n"
                                                                 "## wrong_req_hash_b64\n"
                                                                 "```\n" + wrong_req_hash_b64 + "\n```\n\n"
                                                                                                "## signing_message (used for INVALID signature)\n"
                                                                                                "```\n" + signing_message + "\n```\n\n"
                                                                                                                            "## proof_token_invalid\n"
                                                                                                                            "```\n" + proof_token_invalid + "\n```\n\n"
                                                                                                                                                            "Expected verifier outcome:\n"
                                                                                                                                                            "- req_token server signature: ✅ PASS\n"
                                                                                                                                                            "- fingerprint binding: ✅ PASS\n"
                                                                                                                                                            "- phone signature: ❌ FAIL (as intended)\n"
    )

    out_path.write_text(out_md, encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
