#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"
#include "dna_mlkem_tomont.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] tomont test failed: " << msg << "\n";
    return false;
}

bool poly_equal_canonical(const std::int16_t* a,
                          const std::int16_t* b,
                          std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (mlkem_canonicalize_q(a[i]) != mlkem_canonicalize_q(b[i])) {
            return false;
        }
    }
    return true;
}

bool check_poly_case(const std::array<std::int16_t, kMlkemTomontN>& src) {
    std::array<std::int16_t, kMlkemTomontN> got{};
    std::array<std::int16_t, kMlkemTomontN> exp_coeffwise{};
    std::array<std::int16_t, kMlkemTomontN> exp_via_ntt{};

    for (std::size_t i = 0; i < kMlkemTomontN; ++i) {
        got[i] = src[i];
        exp_coeffwise[i] = mlkem_to_montgomery(src[i]);
        exp_via_ntt[i] = src[i];
    }

    mlkem_poly_tomont(got.data());

    // Direct coefficient-wise meaning:
    // poly_tomont(a)[i] == to_montgomery(a[i]) mod q.
    if (!poly_equal_canonical(got.data(), exp_coeffwise.data(), kMlkemTomontN)) {
        return fail("coefficient-wise tomont mismatch");
    }

    // Stronger transform relation:
    // invntt_tomont(ntt(a)) == poly_tomont(a) mod q.
    mlkem_poly_ntt_forward(exp_via_ntt.data());
    mlkem_poly_invntt_tomont(exp_via_ntt.data());

    if (!poly_equal_canonical(got.data(), exp_via_ntt.data(), kMlkemTomontN)) {
        return fail("ntt/invntt_tomont relation mismatch");
    }

    return true;
}

bool check_vec_case(const std::int16_t src[kMlkemTomontK][kMlkemTomontN]) {
    std::int16_t got[kMlkemTomontK][kMlkemTomontN]{};
    std::int16_t exp[kMlkemTomontK][kMlkemTomontN]{};

    for (std::size_t j = 0; j < kMlkemTomontK; ++j) {
        for (std::size_t i = 0; i < kMlkemTomontN; ++i) {
            got[j][i] = src[j][i];
            exp[j][i] = src[j][i];
        }
        mlkem_poly_tomont(exp[j]);
    }

    mlkem_vec_tomont(got);

    for (std::size_t j = 0; j < kMlkemTomontK; ++j) {
        if (!poly_equal_canonical(got[j], exp[j], kMlkemTomontN)) {
            return fail("vec_tomont mismatch");
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemTomontN == 256, "test assumes N = 256");
    static_assert(kMlkemTomontK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // 1) zero polynomial
    {
        std::array<std::int16_t, kMlkemTomontN> a{};
        if (!check_poly_case(a)) return 1;
    }

    // 2) small signed pattern
    {
        std::array<std::int16_t, kMlkemTomontN> a{};
        for (std::size_t i = 0; i < a.size(); ++i) {
            a[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
        }
        if (!check_poly_case(a)) return 1;
    }

    // 3) canonical nonnegative pattern
    {
        std::array<std::int16_t, kMlkemTomontN> a{};
        for (std::size_t i = 0; i < a.size(); ++i) {
            a[i] = static_cast<std::int16_t>((17 * static_cast<int>(i) + 3) % kMlkemFieldQ);
        }
        if (!check_poly_case(a)) return 1;
    }

    // 4) sparse basis-like case
    {
        std::array<std::int16_t, kMlkemTomontN> a{};
        a[0] = 1;
        a[1] = -1;
        a[255] = 2;
        if (!check_poly_case(a)) return 1;
    }

    // 5) vector case
    {
        std::int16_t vec[kMlkemTomontK][kMlkemTomontN]{};

        for (std::size_t j = 0; j < kMlkemTomontK; ++j) {
            for (std::size_t i = 0; i < kMlkemTomontN; ++i) {
                vec[j][i] = static_cast<std::int16_t>(
                    ((static_cast<int>(i) * static_cast<int>(7 + j)) +
                     static_cast<int>(11 * j) - 5) % 23
                );
            }
        }

        if (!check_vec_case(vec)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] tomont ok"
        << " n=" << kMlkemTomontN
        << " k=" << kMlkemTomontK
        << "\n";

    return 0;
}