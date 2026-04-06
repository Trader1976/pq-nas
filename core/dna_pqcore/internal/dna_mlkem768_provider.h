#pragma once

#include "dna_mlkem768_backend.h"

#include <string>
#include <vector>

namespace dnanexus::pq::internal {

    enum class MlKem768ProviderId {
        native = 1,
        stub = 2,
        dna = 3,
    };

    MlKem768ProviderId mlkem768_active_provider_id();

    // Native provider declarations.
    MlKem768Status mlkem768_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

    bool mlkem768_provider_available();
    std::string mlkem768_provider_name();

    // Stub provider declarations.
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

    // DNA-native provider skeleton declarations.
    bool mlkem768_dna_provider_available();
    std::string mlkem768_dna_provider_name();

    MlKem768Status mlkem768_dna_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_dna_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_dna_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

} // namespace dnanexus::pq::internal