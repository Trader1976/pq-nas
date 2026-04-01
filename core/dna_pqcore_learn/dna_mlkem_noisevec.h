#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track noise-vector generation layer.
    //
    // This is the k=3 vector wrapper over the existing single-poly getnoise
    // functions. It keeps the work deterministic and array-level.
    //
    // For ML-KEM-768, k = 3 and each vector contains 3 polynomials of 256
    // coefficients each.

    constexpr std::size_t kMlkemNoiseVecK = 3;
    constexpr std::size_t kMlkemNoiseVecN = 256;
    constexpr std::size_t kMlkemNoiseVecSeedBytes = 32;

    // Generate one k=3 vector of eta=2 noise polynomials.
    //
    // Uses consecutive nonces:
    //   nonce0, nonce0 + 1, nonce0 + 2
    bool mlkem_noisevec_eta2(
        std::int16_t vec[kMlkemNoiseVecK][kMlkemNoiseVecN],
        const std::uint8_t seed[kMlkemNoiseVecSeedBytes],
        std::uint8_t nonce0,
        std::string* err);

    // Generate one k=3 vector of eta=3 noise polynomials.
    //
    // Uses consecutive nonces:
    //   nonce0, nonce0 + 1, nonce0 + 2
    bool mlkem_noisevec_eta3(
        std::int16_t vec[kMlkemNoiseVecK][kMlkemNoiseVecN],
        const std::uint8_t seed[kMlkemNoiseVecSeedBytes],
        std::uint8_t nonce0,
        std::string* err);

} // namespace pqnas::dna_pqcore_learn