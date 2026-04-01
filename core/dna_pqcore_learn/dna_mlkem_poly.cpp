#include "dna_mlkem_poly.h"

namespace dnanexus::pqlearn::mlkem768 {

    bool coeff_is_canonical(std::int32_t x) {
        return in_canonical_range(x);
    }

    std::int16_t coeff_normalize(std::int32_t x) {
        return static_cast<std::int16_t>(mod_q(x));
    }

    void poly_zero(Poly* p) {
        if (!p) return;
        p->coeffs.fill(0);
    }

    bool poly_is_canonical(const Poly& p) {
        for (std::size_t i = 0; i < kN; ++i) {
            if (!coeff_is_canonical(p.coeffs[i])) return false;
        }
        return true;
    }

    bool poly_equal(const Poly& a, const Poly& b) {
        for (std::size_t i = 0; i < kN; ++i) {
            if (a.coeffs[i] != b.coeffs[i]) return false;
        }
        return true;
    }

    Poly poly_add_mod_q(const Poly& a, const Poly& b) {
        Poly out;
        for (std::size_t i = 0; i < kN; ++i) {
            const std::int32_t sum =
                static_cast<std::int32_t>(a.coeffs[i]) +
                static_cast<std::int32_t>(b.coeffs[i]);
            out.coeffs[i] = coeff_normalize(sum);
        }
        return out;
    }

    Poly poly_sub_mod_q(const Poly& a, const Poly& b) {
        Poly out;
        for (std::size_t i = 0; i < kN; ++i) {
            const std::int32_t diff =
                static_cast<std::int32_t>(a.coeffs[i]) -
                static_cast<std::int32_t>(b.coeffs[i]);
            out.coeffs[i] = coeff_normalize(diff);
        }
        return out;
    }

} // namespace dnanexus::pqlearn::mlkem768