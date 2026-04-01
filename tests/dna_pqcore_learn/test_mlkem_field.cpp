#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_params_768.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

std::int16_t ref_canonical(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

std::int16_t ref_mul(std::int16_t a, std::int16_t b) {
    return ref_canonical(static_cast<std::int64_t>(a) * static_cast<std::int64_t>(b));
}

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] field test failed: " << msg << "\n";
    return false;
}

} // namespace

int main() {
    static_assert(kMlkemFieldQ == 3329, "test assumes ML-KEM q = 3329");

    if (mlkem_canonicalize_q(0) != 0) return fail("canonicalize 0");
    if (mlkem_canonicalize_q(1) != 1) return fail("canonicalize 1");
    if (mlkem_canonicalize_q(kMlkemFieldQ) != 0) return fail("canonicalize q");
    if (mlkem_canonicalize_q(kMlkemFieldQ + 7) != 7) return fail("canonicalize q+7");
    if (mlkem_canonicalize_q(-1) != (kMlkemFieldQ - 1)) return fail("canonicalize -1");
    if (mlkem_canonicalize_q(-kMlkemFieldQ) != 0) return fail("canonicalize -q");
    if (mlkem_canonicalize_q(-(kMlkemFieldQ + 9)) != (kMlkemFieldQ - 9)) return fail("canonicalize -(q+9)");

    if (!mlkem_is_canonical_q(0)) return fail("is_canonical 0");
    if (!mlkem_is_canonical_q(kMlkemFieldQ - 1)) return fail("is_canonical q-1");
    if (mlkem_is_canonical_q(-1)) return fail("is_canonical -1");
    if (mlkem_is_canonical_q(kMlkemFieldQ)) return fail("is_canonical q");

    for (std::int32_t x = -100000; x <= 100000; x += 257) {
        const auto got = mlkem_canonicalize_q(x);
        const auto exp = ref_canonical(x);
        if (got != exp) return fail("canonicalize sweep");
    }

    for (std::int32_t x = -8 * kMlkemFieldQ; x <= 8 * kMlkemFieldQ; ++x) {
        const auto got = mlkem_canonicalize_q(
            mlkem_barrett_reduce(static_cast<std::int16_t>(x))
        );
        const auto exp = ref_canonical(x);
        if (got != exp) return fail("barrett sweep");
    }

    for (std::int16_t a = 0; a < kMlkemFieldQ; ++a) {
        const auto a_mont = mlkem_to_montgomery(a);
        if (!mlkem_is_canonical_q(a_mont)) return fail("to_montgomery not canonical");

        const auto roundtrip = mlkem_from_montgomery(a_mont);
        if (roundtrip != a) return fail("montgomery roundtrip");
    }

    for (std::int16_t a = 0; a < kMlkemFieldQ; a += 17) {
        for (std::int16_t b = 0; b < kMlkemFieldQ; b += 31) {
            const auto a_mont = mlkem_to_montgomery(a);
            const auto b_mont = mlkem_to_montgomery(b);

            const auto prod_mont = mlkem_montgomery_mul(a_mont, b_mont);
            if (!mlkem_is_canonical_q(prod_mont)) return fail("montgomery mul not canonical");

            const auto got = mlkem_from_montgomery(prod_mont);
            const auto exp = ref_mul(a, b);

            if (got != exp) return fail("montgomery mul sweep");
        }
    }

    std::cout
        << "[dna-pqcore-learn] field math ok"
        << " q=" << kMlkemFieldQ
        << " mont_r_mod_q=" << kMlkemMontgomeryRModQ
        << " r2_mod_q=" << kMlkemMontgomeryR2ModQ
        << "\n";

    return 0;
}