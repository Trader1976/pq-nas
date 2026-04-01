#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Real learn-track start of the NTT layer.
    //
    // Current scope:
    //   - forward zeta table
    //   - fqmul in NTT context
    //   - one Cooley-Tukey butterfly block
    //   - one full forward NTT layer
    //
    // Still NOT implemented yet:
    //   - full poly_ntt()
    //   - inverse NTT
    //   - basemul / pointwise multiply

    constexpr std::size_t kMlkemNttN = 256;
    constexpr std::size_t kMlkemNttZetaCount = 128;
    constexpr std::int16_t kMlkemInvNttTomontFactor = 1441;

    // Forward NTT zeta table, in signed-centered form.
    const std::array<std::int16_t, kMlkemNttZetaCount>& mlkem_ntt_zetas();

    // NTT-side Montgomery multiplication.
    //
    // result ≡ a * b * R^{-1} mod q
    //
    // Returned in signed-centered representative form.
    std::int16_t mlkem_fqmul_signed(std::int16_t a, std::int16_t b);

    // Compute one Cooley-Tukey butterfly block with a fixed zeta.
    //
    // Preconditions:
    // - coeffs points to 256 coefficients
    // - 1 <= len <= 128
    // - start + 2*len <= 256
    // - zeta is a signed-centered NTT twiddle
    //
    // This intentionally does NOT reduce the add/sub outputs.
    void mlkem_ntt_butterfly_block(std::int16_t coeffs[kMlkemNttN],
                                   std::int16_t zeta,
                                   std::size_t start,
                                   std::size_t len);

    // Compute one full forward NTT layer, matching the clean vendored structure.
    //
    // Layer numbering follows the clean C implementation:
    //   layer = 1..7
    //
    // Twiddle indices used by a layer are:
    //   [ 2^(layer-1) , ..., 2^layer - 1 ]
    void mlkem_ntt_layer(std::int16_t coeffs[kMlkemNttN], unsigned layer);

} // namespace pqnas::dna_pqcore_learn