#include "dna_mlkem_polyvec.h"

namespace dnanexus::pqlearn::mlkem768 {

    void polyvec_zero(PolyVec* v) {
        if (!v) return;
        for (std::size_t i = 0; i < kK; ++i) {
            poly_zero(&v->polys[i]);
        }
    }

    bool polyvec_is_canonical(const PolyVec& v) {
        for (std::size_t i = 0; i < kK; ++i) {
            if (!poly_is_canonical(v.polys[i])) return false;
        }
        return true;
    }

    bool polyvec_equal(const PolyVec& a, const PolyVec& b) {
        for (std::size_t i = 0; i < kK; ++i) {
            if (!poly_equal(a.polys[i], b.polys[i])) return false;
        }
        return true;
    }

    PolyVec polyvec_add_mod_q(const PolyVec& a, const PolyVec& b) {
        PolyVec out;
        for (std::size_t i = 0; i < kK; ++i) {
            out.polys[i] = poly_add_mod_q(a.polys[i], b.polys[i]);
        }
        return out;
    }

    PolyVec polyvec_sub_mod_q(const PolyVec& a, const PolyVec& b) {
        PolyVec out;
        for (std::size_t i = 0; i < kK; ++i) {
            out.polys[i] = poly_sub_mod_q(a.polys[i], b.polys[i]);
        }
        return out;
    }

} // namespace dnanexus::pqlearn::mlkem768