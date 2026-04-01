#pragma once

#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Centered binomial distribution sampling layer for the learning track.
    //
    // This step is intentionally deterministic:
    // - input is already-expanded byte material
    // - output is the 256 coefficient array
    //
    // We are NOT doing PRF/XOF expansion yet.
    // We are only implementing the pure byte -> CBD polynomial step.
    //
    // FIPS 203 SamplePolyCBD_eta takes 64*eta input bytes and outputs 256
    // coefficients, with eta in {2, 3}.

    constexpr std::size_t kMlkemCbdN = 256;
    constexpr std::size_t kMlkemCbdEta2Bytes = 64 * 2; // 128
    constexpr std::size_t kMlkemCbdEta3Bytes = 64 * 3; // 192

    // Sample one polynomial from CBD with eta = 2.
    // Output coefficients are in {-2, -1, 0, 1, 2}.
    void mlkem_poly_cbd_eta2(std::int16_t coeffs[kMlkemCbdN],
                             const std::uint8_t bytes[kMlkemCbdEta2Bytes]);

    // Sample one polynomial from CBD with eta = 3.
    // Output coefficients are in {-3, -2, -1, 0, 1, 2, 3}.
    void mlkem_poly_cbd_eta3(std::int16_t coeffs[kMlkemCbdN],
                             const std::uint8_t bytes[kMlkemCbdEta3Bytes]);

} // namespace pqnas::dna_pqcore_learn