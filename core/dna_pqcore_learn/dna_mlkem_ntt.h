#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

// Learn-track NTT layer at coefficient-array level.
//
// Current scope:
//   - forward zeta table
//   - fqmul in NTT context
//   - one Cooley-Tukey butterfly block
//   - one full forward NTT layer
//   - full forward NTT on one 256-coefficient polynomial
//   - one inverse NTT layer
//   - full inverse NTT with tomont scaling
//   - one NTT-domain base multiplication unit for a degree-1 pair
//   - full NTT-domain polynomial pointwise multiplication
//   - full polynomial multiplication via NTT pipeline
//
// Still NOT implemented yet:
//   - wrappers over the existing learn-track polynomial/polyvec types
//   - sampling / CBD / matrix generation / IND-CPA layers

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

// Compute one full forward NTT layer.
//
// Layer numbering:
//   layer = 1..7
void mlkem_ntt_layer(std::int16_t coeffs[kMlkemNttN], unsigned layer);

// Compute the full forward NTT in place.
//
// Input:
// - normal-order coefficients
//
// Output:
// - bit-reversed-order NTT coefficients
void mlkem_poly_ntt_forward(std::int16_t coeffs[kMlkemNttN]);

// Compute one full inverse NTT layer.
//
// Layer numbering:
//   layer = 1..7
void mlkem_invntt_layer(std::int16_t coeffs[kMlkemNttN], unsigned layer);

// Compute full inverse NTT with the usual tomont scaling.
//
// Input:
// - bit-reversed-order coefficients
//
// Output:
// - normal-order coefficients, congruent to Montgomery-domain values mod q
void mlkem_poly_invntt_tomont(std::int16_t coeffs[kMlkemNttN]);

// Base multiplication in F_q[X] / (X^2 - zeta), where zeta is the
// NTT twiddle for that degree-1 slot.
//
// Inputs a_pair and b_pair are:
//   a0 + a1*X
//   b0 + b1*X
//
// Output out_pair is:
//   c0 + c1*X = (a0 + a1*X)(b0 + b1*X) mod (X^2 - zeta)
void mlkem_basemul_pair(std::int16_t out_pair[2],
                        const std::int16_t a_pair[2],
                        const std::int16_t b_pair[2],
                        std::int16_t zeta);

// Full NTT-domain polynomial multiplication.
//
// Inputs a_ntt and b_ntt are in the same bit-reversed NTT representation
// produced by mlkem_poly_ntt_forward().
//
// Output out_ntt is the NTT-domain pointwise product, using the usual
// ML-KEM / Kyber pairing pattern over 64 quadratic slots.
void mlkem_poly_basemul_montgomery(std::int16_t out_ntt[kMlkemNttN],
                                   const std::int16_t a_ntt[kMlkemNttN],
                                   const std::int16_t b_ntt[kMlkemNttN]);

// Full polynomial multiplication via the NTT pipeline.
//
// Input:
// - a_std, b_std: normal-order coefficient arrays
//
// Output:
// - out_std: normal-order product polynomial
//
// Important:
// - output is in the standard polynomial domain
// - output is congruent mod q to the negacyclic product in Z_q[X]/(X^256 + 1)
// - output is not promised to be canonicalized to [0, q)
void mlkem_poly_mul_via_ntt(std::int16_t out_std[kMlkemNttN],
                            const std::int16_t a_std[kMlkemNttN],
                            const std::int16_t b_std[kMlkemNttN]);

} // namespace pqnas::dna_pqcore_learn