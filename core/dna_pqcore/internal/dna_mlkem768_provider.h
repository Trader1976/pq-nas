#pragma once

#include "../dna_mlkem768_backend.h"

#include <string>
#include <vector>

namespace dnanexus::pq::internal {

    bool mlkem768_provider_available();
    std::string mlkem768_provider_name();

    MlKem768Status mlkem768_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

    // Keep these only if dna_mlkem768_provider_stub.cpp is still compiled.
    bool mlkem768_stub_provider_available();
    std::string mlkem768_stub_provider_name();

    MlKem768Status mlkem768_stub_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_stub_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_stub_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

} // namespace dnanexus::pq::internal