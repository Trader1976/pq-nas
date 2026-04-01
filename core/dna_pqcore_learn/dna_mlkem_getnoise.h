#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track "getnoise" layer.
    //
    // This is the exact bridge:
    //
    //   seed(32) + nonce(1)
    //     -> SHAKE-256 expansion
    //     -> 64*eta bytes
    //     -> CBD_eta
    //     -> 256 coefficients
    //
    // Still deterministic and isolated.
    // No matrix generation, no IND-CPA wiring yet.

    constexpr std::size_t kMlkemGetNoiseN = 256;
    constexpr std::size_t kMlkemGetNoiseSeedBytes = 32;

    // Produce one CBD_eta=2 polynomial from seed + nonce.
    // Output coefficients are in {-2, -1, 0, 1, 2}.
    bool mlkem_getnoise_eta2(std::int16_t coeffs[kMlkemGetNoiseN],
                             const std::uint8_t seed[kMlkemGetNoiseSeedBytes],
                             std::uint8_t nonce,
                             std::string* err);

    // Produce one CBD_eta=3 polynomial from seed + nonce.
    // Output coefficients are in {-3, -2, -1, 0, 1, 2, 3}.
    bool mlkem_getnoise_eta3(std::int16_t coeffs[kMlkemGetNoiseN],
                             const std::uint8_t seed[kMlkemGetNoiseSeedBytes],
                             std::uint8_t nonce,
                             std::string* err);

} // namespace pqnas::dna_pqcore_learn