#pragma once

#include "dna_mlkem_params_768.h"

#include <array>
#include <cstdint>
#include <cstddef>

namespace dnanexus::pqlearn::mlkem768 {

    // Plain polynomial over Z_q[X] / (X^N + 1) represented by N coefficients.
    // At this stage this is only a storage + helper type.
    // No NTT, compression, sampling, or serialization yet.
    struct Poly {
        std::array<std::int16_t, kN> coeffs{};
    };

    // Coefficient helpers.
    bool coeff_is_canonical(std::int32_t x);
    std::int16_t coeff_normalize(std::int32_t x);

    // Basic polynomial helpers.
    void poly_zero(Poly* p);
    bool poly_is_canonical(const Poly& p);
    bool poly_equal(const Poly& a, const Poly& b);

    // Coefficient-wise arithmetic modulo q.
    // These are simple learning helpers for now, not optimized routines.
    Poly poly_add_mod_q(const Poly& a, const Poly& b);
    Poly poly_sub_mod_q(const Poly& a, const Poly& b);

} // namespace dnanexus::pqlearn::mlkem768