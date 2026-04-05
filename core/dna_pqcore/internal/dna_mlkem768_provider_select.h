#pragma once

#include "internal/dna_mlkem768_provider.h"

#include <string>
#include <vector>

namespace dnanexus::pq::internal {

    MlKem768ProviderId mlkem768_selected_provider_id();
    bool mlkem768_selected_provider_available();
    std::string mlkem768_selected_provider_name();

    MlKem768Status mlkem768_selected_provider_keygen(MlKem768Keypair* out);

    MlKem768Status mlkem768_selected_provider_encapsulate(
        const std::vector<std::uint8_t>& public_key,
        MlKem768EncapResult* out);

    MlKem768Status mlkem768_selected_provider_decapsulate(
        const std::vector<std::uint8_t>& secret_key,
        const std::vector<std::uint8_t>& ciphertext,
        std::vector<std::uint8_t>* out_shared_secret);

} // namespace dnanexus::pq::internal