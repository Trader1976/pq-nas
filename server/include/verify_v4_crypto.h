#pragma once

#include <array>
#include <string>
#include <vector>
#include <cstddef>

#include <nlohmann/json.hpp>

namespace pqnas {

    // sha256 -> standard base64 WITH padding (matches Python base64.b64encode)
    std::string sha256_b64_std_str(const std::string& s);

    // Trim trailing "/" only (to make origins comparable)
    std::string trim_slashes(std::string s);

    // Fingerprint = sha3-512(pubkey) rendered as lowercase hex
    std::string fingerprint_from_pubkey_sha3_512_hex(const std::vector<unsigned char>& pubkey);

    // Canonical bytes for v4 phone signature verification
    std::string canonical_v4_phone_auth(const nlohmann::json& sp);

    // Verify server-issued Ed25519 token:
    // Wire format: v4.<payload_b64url_no_pad>.<sig_b64url_no_pad>
    // Returns parsed JSON payload on success; throws std::runtime_error on failure.
    nlohmann::json verify_token_v4_ed25519(const std::string& token,
                                          const unsigned char pk[32]);

    // Native PQ verification via libdna_lib.so symbol qgp_dsa87_verify
    bool verify_mldsa87_signature_native(const std::vector<unsigned char>& pubkey,
                                         const std::vector<unsigned char>& msg,
                                         const std::vector<unsigned char>& sig);

    // Standard base64 (WITH padding)
    std::string b64_std(const unsigned char* data, size_t len);

} // namespace pqnas
