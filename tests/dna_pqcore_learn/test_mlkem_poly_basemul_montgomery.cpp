#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] poly basemul montgomery test failed: " << msg << "\n";
    return false;
}

std::int16_t ref_canonical64(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

void ref_poly_basemul_montgomery(std::int16_t out_ntt[kMlkemNttN],
                                 const std::int16_t a_ntt[kMlkemNttN],
                                 const std::int16_t b_ntt[kMlkemNttN]) {
    const auto& zetas = mlkem_ntt_zetas();

    for (std::size_t i = 0; i < (kMlkemNttN / 4); ++i) {
        const std::int16_t zeta = zetas[64 + i];

        mlkem_basemul_pair(&out_ntt[4 * i],
                           &a_ntt[4 * i],
                           &b_ntt[4 * i],
                           zeta);

        const std::int16_t neg_zeta = static_cast<std::int16_t>(-zeta);

        mlkem_basemul_pair(&out_ntt[4 * i + 2],
                           &a_ntt[4 * i + 2],
                           &b_ntt[4 * i + 2],
                           neg_zeta);
    }
}

void naive_negacyclic_mul(std::int16_t out[kMlkemNttN],
                          const std::int16_t a[kMlkemNttN],
                          const std::int16_t b[kMlkemNttN]) {
    std::array<std::int64_t, kMlkemNttN> acc{};
    acc.fill(0);

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        const std::int64_t ai = mlkem_canonicalize_q(a[i]);

        for (std::size_t j = 0; j < kMlkemNttN; ++j) {
            const std::int64_t bj = mlkem_canonicalize_q(b[j]);
            const std::size_t deg = i + j;

            if (deg < kMlkemNttN) {
                acc[deg] += ai * bj;
            } else {
                acc[deg - kMlkemNttN] -= ai * bj;
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        out[i] = ref_canonical64(acc[i]);
    }
}

bool check_direct_slotwise_reference(const std::array<std::int16_t, kMlkemNttN>& a_ntt,
                                     const std::array<std::int16_t, kMlkemNttN>& b_ntt) {
    std::array<std::int16_t, kMlkemNttN> got{};
    std::array<std::int16_t, kMlkemNttN> exp{};

    mlkem_poly_basemul_montgomery(got.data(), a_ntt.data(), b_ntt.data());
    ref_poly_basemul_montgomery(exp.data(), a_ntt.data(), b_ntt.data());

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        if (got[i] != exp[i]) {
            return fail("slotwise reference mismatch");
        }
    }

    return true;
}

bool check_full_pipeline(const std::array<std::int16_t, kMlkemNttN>& a_std,
                         const std::array<std::int16_t, kMlkemNttN>& b_std) {
    auto a_ntt = a_std;
    auto b_ntt = b_std;
    std::array<std::int16_t, kMlkemNttN> prod_ntt{};
    std::array<std::int16_t, kMlkemNttN> expected_std{};

    mlkem_poly_ntt_forward(a_ntt.data());
    mlkem_poly_ntt_forward(b_ntt.data());

    mlkem_poly_basemul_montgomery(prod_ntt.data(), a_ntt.data(), b_ntt.data());
    mlkem_poly_invntt_tomont(prod_ntt.data());

    naive_negacyclic_mul(expected_std.data(), a_std.data(), b_std.data());

    // Important domain point:
    //
    //   invntt_tomont(ntt(a)) = to_montgomery(a)
    //
    // but after basemul there is already an extra R^{-1} factor from fqmul,
    // so
    //
    //   invntt_tomont(basemul(ntt(a), ntt(b)))
    //
    // lands back in the STANDARD polynomial domain.
    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        const std::int16_t expected = expected_std[i];
        const std::int16_t actual = mlkem_canonicalize_q(prod_ntt[i]);

        if (actual != expected) {
            return fail("full pipeline mismatch");
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNttN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    const auto& zetas = mlkem_ntt_zetas();
    if (zetas[64] != -1103) return fail("zetas[64]");
    if (zetas[127] != 1628) return fail("zetas[127]");

    // 1) Direct NTT-domain slotwise reference check.
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        for (std::size_t i = 0; i < kMlkemNttN; ++i) {
            a[i] = static_cast<std::int16_t>((static_cast<int>(i % 11) - 5) * 9);
            b[i] = static_cast<std::int16_t>((static_cast<int>(i % 7) - 3) * 13);
        }

        if (!check_direct_slotwise_reference(a, b)) return 1;
    }

    // 2) Sparse polynomial: 1 * 1 = 1.
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        a[0] = 1;
        b[0] = 1;

        if (!check_full_pipeline(a, b)) return 1;
    }

    // 3) x * x = x^2.
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        a[1] = 1;
        b[1] = 1;

        if (!check_full_pipeline(a, b)) return 1;
    }

    // 4) x^255 * x = -1 in Z_q[X]/(X^256 + 1).
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        a[255] = 1;
        b[1] = 1;

        if (!check_full_pipeline(a, b)) return 1;
    }

    // 5) Small mixed coefficients.
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        for (std::size_t i = 0; i < kMlkemNttN; ++i) {
            a[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
            b[i] = static_cast<std::int16_t>((static_cast<int>((i * 5) % 9) - 4) * 2);
        }

        if (!check_full_pipeline(a, b)) return 1;
    }

    // 6) Canonical nonnegative pattern.
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};

        for (std::size_t i = 0; i < kMlkemNttN; ++i) {
            a[i] = static_cast<std::int16_t>((17 * static_cast<int>(i) + 3) % kMlkemFieldQ);
            b[i] = static_cast<std::int16_t>((29 * static_cast<int>(i) + 11) % kMlkemFieldQ);
        }

        if (!check_full_pipeline(a, b)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] poly basemul montgomery ok"
        << " slots=" << (kMlkemNttN / 4)
        << " zeta64=" << zetas[64]
        << "\n";

    return 0;
}