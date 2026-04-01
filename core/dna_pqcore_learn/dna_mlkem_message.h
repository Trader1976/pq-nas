#pragma once

#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track message polynomial helpers.
    //
    // This is the direct bridge used by IND-CPA encrypt/decrypt:
    //
    //   message bytes <-> polynomial with 256 coefficients
    //
    // We keep this array-level and deterministic.
    // No ciphertext packing yet.

    constexpr std::size_t kMlkemMessageBytes = 32;
    constexpr std::size_t kMlkemMessageN = 256;

    // For q = 3329, the "1" representative used by the Kyber/ML-KEM message
    // polynomial is (q + 1) / 2 = 1665.
    constexpr std::int16_t kMlkemMessageOneCoeff = 1665;

    // Encode 32 message bytes into one 256-coefficient message polynomial.
    //
    // Bit 0 -> coefficient 0
    // Bit 1 -> coefficient (q+1)/2 = 1665
    void mlkem_poly_frommsg(std::int16_t coeffs[kMlkemMessageN],
                            const std::uint8_t msg[kMlkemMessageBytes]);

    // Decode one 256-coefficient message polynomial back into 32 message bytes.
    //
    // Coefficients are interpreted mod q.
    void mlkem_poly_tomsg(std::uint8_t msg[kMlkemMessageBytes],
                          const std::int16_t coeffs[kMlkemMessageN]);

} // namespace pqnas::dna_pqcore_learn