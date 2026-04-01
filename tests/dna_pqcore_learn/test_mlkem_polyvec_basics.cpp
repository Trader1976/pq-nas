#include "dna_mlkem_polyvec.h"

#include <iostream>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    PolyVec a;
    PolyVec b;
    polyvec_zero(&a);
    polyvec_zero(&b);

    if (!polyvec_is_canonical(a)) return 1;
    if (!polyvec_is_canonical(b)) return 1;
    if (!polyvec_equal(a, b)) return 1;

    // Fill vectors with deterministic canonical values.
    for (std::size_t p = 0; p < kK; ++p) {
        for (std::size_t i = 0; i < kN; ++i) {
            a.polys[p].coeffs[i] = coeff_normalize(static_cast<std::int32_t>(p * 100 + i * 3 + 7));
            b.polys[p].coeffs[i] = coeff_normalize(static_cast<std::int32_t>(p * 200 + i * 5 + 11));
        }
    }

    if (!polyvec_is_canonical(a)) return 1;
    if (!polyvec_is_canonical(b)) return 1;
    if (polyvec_equal(a, b)) return 1;

    const PolyVec sum = polyvec_add_mod_q(a, b);
    const PolyVec back = polyvec_sub_mod_q(sum, b);

    if (!polyvec_is_canonical(sum)) return 1;
    if (!polyvec_equal(back, a)) return 1;

    // Spot-check a few values to confirm vector indexing is sane.
    {
        const std::int32_t want =
            mod_q(static_cast<std::int32_t>(a.polys[0].coeffs[0]) +
                  static_cast<std::int32_t>(b.polys[0].coeffs[0]));
        if (sum.polys[0].coeffs[0] != want) return 1;
    }
    {
        const std::int32_t want =
            mod_q(static_cast<std::int32_t>(a.polys[2].coeffs[17]) +
                  static_cast<std::int32_t>(b.polys[2].coeffs[17]));
        if (sum.polys[2].coeffs[17] != want) return 1;
    }

    std::cout << "[dna-pqcore-learn] polyvec basics ok"
              << " k=" << kK
              << " n=" << kN
              << std::endl;

    return 0;
}