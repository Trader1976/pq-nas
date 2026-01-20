#pragma once
#include <array>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace pqnas {

    long now_epoch();
    std::string lower_ascii(std::string s);

    std::vector<unsigned char> b64decode_loose(const std::string& in);

    // --- add these ---
    std::string sha256_b64_std_str(const std::string& s);
    std::string trim_slashes(std::string s);
    std::string fingerprint_from_pubkey_sha3_512_hex(const std::vector<unsigned char>& pubkey);

    // canonical bytes for v4 phone auth signature
    std::string canonical_v4_phone_auth(const nlohmann::json& sp);

    // verify v4.<payload_b64>.<sig_b64> token using Ed25519 pk
    nlohmann::json verify_token_v4_ed25519(const std::string& token, const unsigned char pk[32]);

} // namespace pqnas
