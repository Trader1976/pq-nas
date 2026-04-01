#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pq {

    // Thin reusable ML-KEM-768 backend wrapper for the DNA / PQ-NAS ecosystem.
    // This layer is intentionally small and does not know anything about shares,
    // envelopes, CEKs, files, browsers, or PQ-NAS routes.

    struct MlKem768Keypair {
        std::vector<std::uint8_t> public_key;
        std::vector<std::uint8_t> secret_key;
    };

    struct MlKem768EncapResult {
        std::vector<std::uint8_t> ciphertext;
        std::vector<std::uint8_t> shared_secret;
    };

    bool mlkem768_available();
    std::string mlkem768_backend_name();

    bool mlkem768_keygen(MlKem768Keypair* out, std::string* err);

    bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                              MlKem768EncapResult* out,
                              std::string* err);

    bool mlkem768_decapsulate(const std::vector<std::uint8_t>& secret_key,
                              const std::vector<std::uint8_t>& ciphertext,
                              std::vector<std::uint8_t>* out_shared_secret,
                              std::string* err);

    bool mlkem768_selftest(std::string* err);

} // namespace dnanexus::pq