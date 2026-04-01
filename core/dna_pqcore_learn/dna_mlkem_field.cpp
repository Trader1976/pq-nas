#include "dna_mlkem_field.h"

namespace pqnas::dna_pqcore_learn {

static_assert(kMlkemFieldQ == 3329, "dna_mlkem_field assumes ML-KEM q = 3329");

std::int16_t mlkem_canonicalize_q(std::int32_t a) {
    std::int32_t r = a % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

bool mlkem_is_canonical_q(std::int16_t a) {
    return a >= 0 && a < kMlkemFieldQ;
}

std::int16_t mlkem_barrett_reduce(std::int16_t a) {
    // Reference-style Barrett reduction:
    // t = floor((v*a + 2^25) / 2^26)
    // r = a - t*q
    //
    // Result is reduced mod q but may still be negative or non-canonical.
    constexpr std::int32_t kShift = 26;
    constexpr std::int32_t kRound = 1 << (kShift - 1);

    const std::int32_t x = static_cast<std::int32_t>(a);
    const std::int32_t t = ((kMlkemBarrettV * x) + kRound) >> kShift;
    return static_cast<std::int16_t>(x - t * kMlkemFieldQ);
}

std::int16_t mlkem_montgomery_reduce(std::int32_t a) {
    // Reference-style Montgomery reduction for q = 3329, R = 2^16.
    //
    // We intentionally mirror the usual Kyber arithmetic shape here.
    const std::int16_t t =
        static_cast<std::int16_t>(
            static_cast<std::uint32_t>(a) * static_cast<std::uint32_t>(kMlkemMontgomeryQinv)
        );

    const std::int32_t u =
        (a - static_cast<std::int32_t>(t) * kMlkemFieldQ) >> 16;

    return static_cast<std::int16_t>(u);
}

std::int16_t mlkem_to_montgomery(std::int16_t a) {
    const std::int16_t c = mlkem_canonicalize_q(a);

    // montgomery_reduce(a * R^2) = a * R mod q
    return mlkem_canonicalize_q(
        mlkem_montgomery_reduce(
            static_cast<std::int32_t>(c) * kMlkemMontgomeryR2ModQ
        )
    );
}

std::int16_t mlkem_from_montgomery(std::int16_t a_mont) {
    // montgomery_reduce(a * R) = a mod q
    return mlkem_canonicalize_q(
        mlkem_montgomery_reduce(static_cast<std::int32_t>(a_mont))
    );
}

std::int16_t mlkem_montgomery_mul(std::int16_t a_mont, std::int16_t b_mont) {
    // If both inputs are in Montgomery domain, the output stays there:
    // montgomery_reduce((aR) * (bR)) = abR mod q
    const std::int32_t prod =
        static_cast<std::int32_t>(a_mont) * static_cast<std::int32_t>(b_mont);

    return mlkem_canonicalize_q(mlkem_montgomery_reduce(prod));
}

} // namespace pqnas::dna_pqcore_learn