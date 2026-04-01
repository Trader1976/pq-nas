#include "dna_mlkem_poly.h"

#include <iostream>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    // Coefficient normalization basics.
    if (!coeff_is_canonical(0)) return 1;
    if (!coeff_is_canonical(kQ - 1)) return 1;
    if (coeff_is_canonical(kQ)) return 1;

    if (coeff_normalize(0) != 0) return 1;
    if (coeff_normalize(kQ) != 0) return 1;
    if (coeff_normalize(-1) != kQ - 1) return 1;
    if (coeff_normalize(kQ + 7) != 7) return 1;
    if (coeff_normalize(-kQ - 9) != kQ - 9) return 1;

    Poly a;
    Poly b;
    poly_zero(&a);
    poly_zero(&b);

    if (!poly_is_canonical(a)) return 1;
    if (!poly_is_canonical(b)) return 1;
    if (!poly_equal(a, b)) return 1;

    // Set a few coefficients by hand.
    a.coeffs[0] = coeff_normalize(10);
    a.coeffs[1] = coeff_normalize(kQ - 3);
    a.coeffs[2] = coeff_normalize(1234);

    b.coeffs[0] = coeff_normalize(20);
    b.coeffs[1] = coeff_normalize(10);
    b.coeffs[2] = coeff_normalize(kQ - 234);

    if (!poly_is_canonical(a)) return 1;
    if (!poly_is_canonical(b)) return 1;
    if (poly_equal(a, b)) return 1;

    const Poly sum = poly_add_mod_q(a, b);
    if (!poly_is_canonical(sum)) return 1;
    if (sum.coeffs[0] != 30) return 1;
    if (sum.coeffs[1] != 7) return 1;         // (q-3)+10 mod q = 7
    if (sum.coeffs[2] != 1000) return 1;      // 1234 + (q-234) mod q = 1000

    const Poly diff = poly_sub_mod_q(a, b);
    if (!poly_is_canonical(diff)) return 1;
    if (diff.coeffs[0] != kQ - 10) return 1;  // 10-20 mod q
    if (diff.coeffs[1] != kQ - 13) return 1;  // (q-3)-10 mod q
    if (diff.coeffs[2] != 1468) return 1;     // 1234-(q-234) mod q = 1468

    // Add then subtract should recover original polynomial.
    const Poly back = poly_sub_mod_q(sum, b);
    if (!poly_equal(back, a)) return 1;

    std::cout << "[dna-pqcore-learn] poly basics ok"
              << " n=" << kN
              << " q=" << kQ
              << std::endl;

    return 0;
}