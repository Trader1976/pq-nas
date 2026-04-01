#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-step constants/helpers for the ML-KEM / Kyber NTT layer.
    //
    // This step does NOT implement the NTT yet.
    // It only introduces:
    //   - 7-bit bit-reversal helper
    //   - centered representative helper
    //   - published 128-entry zeta table used by the reference NTT

    constexpr std::size_t kMlkemNttZetaCount = 128;
    constexpr std::int16_t kMlkemNttRootOfUnity = 17;
    constexpr std::int16_t kMlkemInvNttFinalFactor = 1441;

    // 7-bit bit-reversal used in the NTT exponent ordering.
    std::uint8_t mlkem_brv7(std::uint8_t x);

    // Return centered representative in [-q/2, q/2].
    std::int16_t mlkem_centered_mod_q(std::int32_t a);

    // Published zeta table used by the reference NTT.
    const std::array<std::int16_t, kMlkemNttZetaCount>& mlkem_ntt_zetas();

} // namespace pqnas::dna_pqcore_learn