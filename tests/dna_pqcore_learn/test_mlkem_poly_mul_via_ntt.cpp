#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] poly mul via ntt test failed: " << msg << "\n";
    return false;
}

std::int16_t ref_canonical64(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

std::int32_t max_abs(const std::array<std::int16_t, kMlkemNttN>& coeffs) {
    std::int32_t m = 0;
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        const std::int32_t v = coeffs[i];
        const std::int32_t a = (v < 0) ? -v : v;
        if (a > m) m = a;
    }
    return m;
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

bool check_case(const std::array<std::int16_t, kMlkemNttN>& a,
                const std::array<std::int16_t, kMlkemNttN>& b) {
    std::array<std::int16_t, kMlkemNttN> got{};
    std::array<std::int16_t, kMlkemNttN> exp{};
    std::array<std::int16_t, kMlkemNttN> got_swapped{};

    mlkem_poly_mul_via_ntt(got.data(), a.data(), b.data());
    mlkem_poly_mul_via_ntt(got_swapped.data(), b.data(), a.data());
    naive_negacyclic_mul(exp.data(), a.data(), b.data());

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        const std::int16_t actual = mlkem_canonicalize_q(got[i]);
        const std::int16_t expected = exp[i];
        if (actual != expected) {
            return fail("product mismatch");
        }

        const std::int16_t swapped = mlkem_canonicalize_q(got_swapped[i]);
        if (swapped != expected) {
            return fail("commutativity mismatch");
        }
    }

    if (max_abs(got) > 8 * kMlkemFieldQ) {
        return fail("output bound exceeded");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNttN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // 1) zero * zero
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        if (!check_case(a, b)) return 1;
    }

    // 2) 1 * 1 = 1
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        a[0] = 1;
        b[0] = 1;
        if (!check_case(a, b)) return 1;
    }

    // 3) x * x = x^2
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        a[1] = 1;
        b[1] = 1;
        if (!check_case(a, b)) return 1;
    }

    // 4) x^255 * x = -1 in Z_q[X]/(X^256 + 1)
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        a[255] = 1;
        b[1] = 1;
        if (!check_case(a, b)) return 1;
    }

    // 5) small signed patterns
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        for (std::size_t i = 0; i < kMlkemNttN; ++i) {
            a[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
            b[i] = static_cast<std::int16_t>((static_cast<int>((i * 5) % 9) - 4) * 2);
        }
        if (!check_case(a, b)) return 1;
    }

    // 6) canonical nonnegative patterns
    {
        std::array<std::int16_t, kMlkemNttN> a{};
        std::array<std::int16_t, kMlkemNttN> b{};
        for (std::size_t i = 0; i < kMlkemNttN; ++i) {
            a[i] = static_cast<std::int16_t>((17 * static_cast<int>(i) + 3) % kMlkemFieldQ);
            b[i] = static_cast<std::int16_t>((29 * static_cast<int>(i) + 11) % kMlkemFieldQ);
        }
        if (!check_case(a, b)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] poly mul via ntt ok"
        << " n=" << kMlkemNttN
        << " q=" << kMlkemFieldQ
        << "\n";

    return 0;
}