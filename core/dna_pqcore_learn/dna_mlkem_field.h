#pragma once

#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Small finite-field arithmetic layer for the learning track.
    //
    // This step is intentionally self-contained:
    // - q is fixed explicitly as 3329 here
    // - we still include dna_mlkem_params_768.h because this belongs to the
    //   ML-KEM-768 learning path
    //
    // Later NTT / inverse-NTT / pointwise multiplication will build on this.

    constexpr std::int32_t kMlkemFieldQ = 3329;

    constexpr std::int32_t kMlkemMontgomeryRLog = 16;
    constexpr std::int32_t kMlkemMontgomeryR = 1 << kMlkemMontgomeryRLog;

    // For q = 3329, Kyber / ML-KEM uses:
    constexpr std::int32_t kMlkemMontgomeryQinv = 62209; // q^(-1) relation in mod 2^16 form
    constexpr std::int32_t kMlkemMontgomeryRModQ = 2285; // 2^16 mod q
    constexpr std::int32_t kMlkemMontgomeryR2ModQ = 1353; // (2^16)^2 mod q

    // Barrett constant with shift 26.
    constexpr std::int32_t kMlkemBarrettV = 20159;

    // Return canonical representative in [0, q).
    std::int16_t mlkem_canonicalize_q(std::int32_t a);

    // True iff coeff is already canonical in [0, q).
    bool mlkem_is_canonical_q(std::int16_t a);

    // Barrett reduction mod q.
    // Returned value is reduced mod q but not guaranteed canonical.
    std::int16_t mlkem_barrett_reduce(std::int16_t a);

    // Montgomery reduction with R = 2^16.
    // Returns a * R^{-1} mod q in the usual reduced residue form.
    std::int16_t mlkem_montgomery_reduce(std::int32_t a);

    // Convert standard-domain canonical residue a into Montgomery domain: a*R mod q.
    std::int16_t mlkem_to_montgomery(std::int16_t a);

    // Convert Montgomery-domain residue back to canonical standard domain.
    std::int16_t mlkem_from_montgomery(std::int16_t a_mont);

    // Multiply two Montgomery-domain residues and keep result in Montgomery domain.
    // Returned value is canonicalized for learning-track clarity.
    std::int16_t mlkem_montgomery_mul(std::int16_t a_mont, std::int16_t b_mont);

} // namespace pqnas::dna_pqcore_learn