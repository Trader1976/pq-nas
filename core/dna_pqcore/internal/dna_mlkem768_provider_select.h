#pragma once

#include "internal/dna_mlkem768_provider.h"

#include <string>
#include <vector>

namespace dnanexus::pq::internal {

    MlKem768ProviderId mlkem768_selected_provider_id();
    bool mlkem768_selected_provider_available();
    std::string mlkem768_selected_provider_name();

    bool mlkem768_provider_available_by_id(MlKem768ProviderId id);
    std::string mlkem768_provider_name_by_id(MlKem768ProviderId id);

    MlKem768Status mlkem768_provider_keygen_by_id(MlKem768ProviderId id,
                                                  MlKem768Keypair* out);

    MlKem768Status mlkem768_provider_encapsulate_by_id(
        MlKem768ProviderId id,
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_provider_decapsulate_by_id(
        MlKem768ProviderId id,
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

    // Internal-only selector override for tests/dev.
    // Supported overrides:
    // - native
    // - dna
    //
    // Unsupported:
    // - stub
    bool mlkem768_set_selected_provider_override(MlKem768ProviderId id);
    void mlkem768_clear_selected_provider_override();
    bool mlkem768_has_selected_provider_override();

    MlKem768Status mlkem768_selected_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_selected_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_selected_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

} // namespace dnanexus::pq::internal