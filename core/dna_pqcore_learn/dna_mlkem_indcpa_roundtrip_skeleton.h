#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track deterministic IND-CPA roundtrip algebra skeleton.
    //
    // This step wires together:
    //
    //   keygen algebra skeleton
    //   encrypt algebra skeleton
    //   decrypt algebra skeleton
    //
    // It still does NOT do:
    // - d -> (rho, sigma) derivation
    // - message encode / decode
    // - ciphertext compression / packing
    // - public / secret key packing
    // - full K-PKE / KEM wiring
    //
    // So the recovered polynomial is the pre-decode message polynomial.

    constexpr std::size_t kMlkemRoundtripSkelK = 3;
    constexpr std::size_t kMlkemRoundtripSkelN = 256;
    constexpr std::size_t kMlkemRoundtripSkelSeedBytes = 32;

    // Run the deterministic IND-CPA algebra roundtrip.
    //
    // Inputs:
    // - rho, sigma: deterministic keygen seeds
    // - coins:      deterministic encryption randomness
    // - m:          message polynomial in standard polynomial domain
    //
    // Outputs:
    // - t_hat:      public-key polynomial vector in NTT representation
    // - u:          ciphertext vector polynomial in standard polynomial domain
    // - v:          ciphertext polynomial in standard polynomial domain
    // - m_poly_dec: recovered pre-decode message polynomial
    bool mlkem_indcpa_roundtrip_algebra_skeleton(
        std::int16_t t_hat[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN],
        std::int16_t u[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN],
        std::int16_t v[kMlkemRoundtripSkelN],
        std::int16_t m_poly_dec[kMlkemRoundtripSkelN],
        const std::uint8_t rho[kMlkemRoundtripSkelSeedBytes],
        const std::uint8_t sigma[kMlkemRoundtripSkelSeedBytes],
        const std::uint8_t coins[kMlkemRoundtripSkelSeedBytes],
        const std::int16_t m[kMlkemRoundtripSkelN],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn