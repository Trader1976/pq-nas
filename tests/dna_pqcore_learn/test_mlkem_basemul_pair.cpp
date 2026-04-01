#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] basemul pair test failed: " << msg << "\n";
    return false;
}

std::int16_t ref_canonical64(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

std::int16_t ref_centered_mod_q(std::int32_t a) {
    std::int16_t r = mlkem_canonicalize_q(a);
    if (r > (kMlkemFieldQ / 2)) {
        r = static_cast<std::int16_t>(r - kMlkemFieldQ);
    }
    return r;
}

std::int16_t ref_fqmul(std::int16_t a, std::int16_t b) {
    const std::int32_t prod =
        static_cast<std::int32_t>(a) * static_cast<std::int32_t>(b);
    return ref_centered_mod_q(mlkem_montgomery_reduce(prod));
}

void ref_basemul_pair(std::int16_t out_pair[2],
                      const std::int16_t a_pair[2],
                      const std::int16_t b_pair[2],
                      std::int16_t zeta) {
    const std::int16_t t0 = ref_fqmul(a_pair[1], b_pair[1]);
    const std::int16_t t1 = ref_fqmul(t0, zeta);
    const std::int16_t t2 = ref_fqmul(a_pair[0], b_pair[0]);

    const std::int16_t t3 = ref_fqmul(a_pair[0], b_pair[1]);
    const std::int16_t t4 = ref_fqmul(a_pair[1], b_pair[0]);

    out_pair[0] = static_cast<std::int16_t>(t1 + t2);
    out_pair[1] = static_cast<std::int16_t>(t3 + t4);
}

// Basemul outputs live in the R^{-1}-scaled domain because fqmul()
// returns x * y * R^{-1} mod q.
//
// So for a ring-meaning test, we compute the expected quotient-ring product
// in standard domain and then map it into the same R^{-1}-scaled domain.
std::int16_t ref_scale_std_to_basemul_domain(std::int16_t x_std) {
    const std::int16_t x = mlkem_canonicalize_q(x_std);
    return mlkem_canonicalize_q(
        mlkem_montgomery_reduce(static_cast<std::int32_t>(x))
    );
}

bool check_direct_formula(const std::int16_t a_pair[2],
                          const std::int16_t b_pair[2],
                          std::int16_t zeta) {
    std::int16_t got[2]{};
    std::int16_t exp[2]{};

    mlkem_basemul_pair(got, a_pair, b_pair, zeta);
    ref_basemul_pair(exp, a_pair, b_pair, zeta);

    if (got[0] != exp[0]) return fail("direct formula c0 mismatch");
    if (got[1] != exp[1]) return fail("direct formula c1 mismatch");

    return true;
}

bool check_ring_meaning(const std::int16_t a_pair[2],
                        const std::int16_t b_pair[2],
                        std::int16_t zeta_mont) {
    // zeta table entries are Montgomery-form twiddles in centered form.
    // Convert the twiddle back to standard domain for the quotient-ring meaning.
    const std::int16_t zeta_std = mlkem_from_montgomery(zeta_mont);

    const std::int16_t a0 = mlkem_canonicalize_q(a_pair[0]);
    const std::int16_t a1 = mlkem_canonicalize_q(a_pair[1]);
    const std::int16_t b0 = mlkem_canonicalize_q(b_pair[0]);
    const std::int16_t b1 = mlkem_canonicalize_q(b_pair[1]);

    // Standard-domain quotient-ring product in F_q[X] / (X^2 - zeta_std).
    //
    // Use 64-bit arithmetic here so larger learning-test values do not overflow
    // before modular reduction.
    const std::int16_t expected0_std = ref_canonical64(
        static_cast<std::int64_t>(a0) * static_cast<std::int64_t>(b0) +
        static_cast<std::int64_t>(a1) * static_cast<std::int64_t>(b1) *
            static_cast<std::int64_t>(zeta_std)
    );

    const std::int16_t expected1_std = ref_canonical64(
        static_cast<std::int64_t>(a0) * static_cast<std::int64_t>(b1) +
        static_cast<std::int64_t>(a1) * static_cast<std::int64_t>(b0)
    );

    std::int16_t got[2]{};
    mlkem_basemul_pair(got, a_pair, b_pair, zeta_mont);

    // Compare in the same domain:
    // basemul output == expected_standard * R^{-1} mod q.
    const std::int16_t actual0_scaled = mlkem_canonicalize_q(got[0]);
    const std::int16_t actual1_scaled = mlkem_canonicalize_q(got[1]);

    const std::int16_t expected0_scaled =
        ref_scale_std_to_basemul_domain(expected0_std);
    const std::int16_t expected1_scaled =
        ref_scale_std_to_basemul_domain(expected1_std);

    if (actual0_scaled != expected0_scaled) return fail("ring meaning c0 mismatch");
    if (actual1_scaled != expected1_scaled) return fail("ring meaning c1 mismatch");

    return true;
}

bool check_commutative(const std::int16_t a_pair[2],
                       const std::int16_t b_pair[2],
                       std::int16_t zeta) {
    std::int16_t ab[2]{};
    std::int16_t ba[2]{};

    mlkem_basemul_pair(ab, a_pair, b_pair, zeta);
    mlkem_basemul_pair(ba, b_pair, a_pair, zeta);

    if (ab[0] != ba[0]) return fail("commutative c0 mismatch");
    if (ab[1] != ba[1]) return fail("commutative c1 mismatch");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNttZetaCount == 128, "test assumes 128 zetas");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    const auto& zetas = mlkem_ntt_zetas();

    if (zetas[64] != -1103) return fail("zetas[64]");
    if (zetas[65] != 430) return fail("zetas[65]");
    if (zetas[127] != 1628) return fail("zetas[127]");

    {
        const std::int16_t a[2] = {1, 2};
        const std::int16_t b[2] = {3, 4};
        if (!check_direct_formula(a, b, zetas[64])) return 1;
        if (!check_ring_meaning(a, b, zetas[64])) return 1;
        if (!check_commutative(a, b, zetas[64])) return 1;
    }

    {
        const std::int16_t a[2] = {-7, 11};
        const std::int16_t b[2] = {5, -9};
        if (!check_direct_formula(a, b, zetas[65])) return 1;
        if (!check_ring_meaning(a, b, zetas[65])) return 1;
        if (!check_commutative(a, b, zetas[65])) return 1;
    }

    {
        const std::int16_t a[2] = {
            static_cast<std::int16_t>(1234),
            static_cast<std::int16_t>(2500)
        };
        const std::int16_t b[2] = {
            static_cast<std::int16_t>(321),
            static_cast<std::int16_t>(2222)
        };
        if (!check_direct_formula(a, b, zetas[79])) return 1;
        if (!check_ring_meaning(a, b, zetas[79])) return 1;
        if (!check_commutative(a, b, zetas[79])) return 1;
    }

    {
        const std::int16_t a[2] = {0, 0};
        const std::int16_t b[2] = {0, 0};
        if (!check_direct_formula(a, b, zetas[127])) return 1;
        if (!check_ring_meaning(a, b, zetas[127])) return 1;
        if (!check_commutative(a, b, zetas[127])) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] basemul pair ok"
        << " zeta64=" << zetas[64]
        << " zeta127=" << zetas[127]
        << "\n";

    return 0;
}