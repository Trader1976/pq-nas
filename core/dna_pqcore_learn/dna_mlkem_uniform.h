#pragma once

#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track uniform rejection sampler.
    //
    // This is the byte -> coefficient layer used by seed-driven matrix generation.
    //
    // It parses 12-bit candidates from input bytes in the standard ML-KEM / Kyber
    // way:
    //   d1 = b0 + 256 * (b1 & 0x0f)
    //   d2 = (b1 >> 4) + 16 * b2
    //
    // Any candidate < q is accepted as one coefficient in [0, q).
    //
    // This step is intentionally deterministic and isolated.
    // We are NOT doing the SHAKE-128 matrix/XOF wrapper yet.

    constexpr std::size_t kMlkemUniformN = 256;

    // Fill up to max_coeffs output coefficients from the input byte stream.
    // Returned value is the number of accepted coefficients actually written.
    //
    // Output coefficients are canonical in [0, q).
    std::size_t mlkem_rej_uniform(std::int16_t* coeffs,
                                  std::size_t max_coeffs,
                                  const std::uint8_t* bytes,
                                  std::size_t bytes_len);

} // namespace pqnas::dna_pqcore_learn