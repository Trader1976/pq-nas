#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track deterministic IND-CPA keygen algebra skeleton.
    //
    // This step intentionally starts from rho and sigma directly.
    // It does NOT yet do:
    // - d -> (rho, sigma) derivation
    // - public-key packing
    // - secret-key packing
    // - full KEM wiring
    //
    // It only builds the algebra core for ML-KEM-768:
    //
    //   A_hat  <- matrix_ntt(rho)
    //   s,e    <- noisevec_eta2(sigma, nonce schedule)
    //   s_hat  <- NTT(s)
    //   e_hat  <- NTT(e)
    //   t_hat  <- tomont(A_hat * s_hat) + e_hat
    //
    // All objects remain array-level for clarity.

    constexpr std::size_t kMlkemKeygenSkelK = 3;
    constexpr std::size_t kMlkemKeygenSkelN = 256;
    constexpr std::size_t kMlkemKeygenSkelSeedBytes = 32;

    // Build the deterministic algebra core of IND-CPA keygen from rho and sigma.
    //
    // Nonce schedule used here:
    // - s uses eta=2 with nonces 0,1,2
    // - e uses eta=2 with nonces 3,4,5
    //
    // Outputs:
    // - s_hat: NTT(s)
    // - e_hat: NTT(e)
    // - t_hat: tomont(A_hat * s_hat) + e_hat
    bool mlkem_indcpa_keygen_algebra_skeleton(
        std::int16_t s_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
        std::int16_t e_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
        std::int16_t t_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
        const std::uint8_t rho[kMlkemKeygenSkelSeedBytes],
        const std::uint8_t sigma[kMlkemKeygenSkelSeedBytes],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn