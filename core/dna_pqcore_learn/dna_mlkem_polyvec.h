#pragma once

#include "dna_mlkem_poly.h"

#include <array>
#include <cstddef>

namespace dnanexus::pqlearn::mlkem768 {

    // ML-KEM-768 uses k = 3 polynomials in a vector.
    // This is the basic shape used later for public-key and secret-key material.
    struct PolyVec {
        std::array<Poly, kK> polys{};
    };

    // Basic helpers.
    void polyvec_zero(PolyVec* v);
    bool polyvec_is_canonical(const PolyVec& v);
    bool polyvec_equal(const PolyVec& a, const PolyVec& b);

    // Coefficient-wise vector arithmetic modulo q.
    PolyVec polyvec_add_mod_q(const PolyVec& a, const PolyVec& b);
    PolyVec polyvec_sub_mod_q(const PolyVec& a, const PolyVec& b);

} // namespace dnanexus::pqlearn::mlkem768