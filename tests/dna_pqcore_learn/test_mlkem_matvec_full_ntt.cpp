#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] matvec full ntt test failed: " << msg << "\n";
    return false;
}

std::int16_t ref_canonical64(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

bool coeffs_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

void naive_negacyclic_mul(std::int16_t out[kMlkemMatvecN],
                          const std::int16_t a[kMlkemMatvecN],
                          const std::int16_t b[kMlkemMatvecN]) {
    std::array<std::int64_t, kMlkemMatvecN> acc{};
    acc.fill(0);

    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        const std::int64_t ai = mlkem_canonicalize_q(a[i]);

        for (std::size_t j = 0; j < kMlkemMatvecN; ++j) {
            const std::int64_t bj = mlkem_canonicalize_q(b[j]);
            const std::size_t deg = i + j;

            if (deg < kMlkemMatvecN) {
                acc[deg] += ai * bj;
            } else {
                acc[deg - kMlkemMatvecN] -= ai * bj;
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        out[i] = ref_canonical64(acc[i]);
    }
}

void add_poly_mod_q(std::int16_t acc[kMlkemMatvecN],
                    const std::int16_t addend[kMlkemMatvecN]) {
    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) + static_cast<std::int64_t>(addend[i])
        );
    }
}

void ntt_to_standard_poly(std::int16_t out_std[kMlkemMatvecN],
                          const std::int16_t in_ntt[kMlkemMatvecN]) {
    std::array<std::int16_t, kMlkemMatvecN> tmp{};

    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        tmp[i] = in_ntt[i];
    }

    mlkem_poly_invntt_tomont(tmp.data());

    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        out_std[i] = mlkem_from_montgomery(tmp[i]);
    }
}

bool check_case(const std::array<std::uint8_t, kMlkemMatrixGenSeedBytes>& rho,
                int vec_variant) {
    std::string err;

    std::int16_t matrix_ntt[kMlkemMatvecK][kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t matrix_std[kMlkemMatvecK][kMlkemMatvecK][kMlkemMatvecN]{};

    std::int16_t vec_std[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]{};

    std::int16_t got_ntt[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t row_ref_ntt[kMlkemMatvecK][kMlkemMatvecN]{};

    std::int16_t got_std[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t expected_std[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t tmp_std[kMlkemMatvecN]{};

    if (!mlkem_matrix_ntt(matrix_ntt, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_ntt failed");
    }

    for (std::size_t row = 0; row < kMlkemMatvecK; ++row) {
        for (std::size_t col = 0; col < kMlkemMatvecK; ++col) {
            ntt_to_standard_poly(matrix_std[row][col], matrix_ntt[row][col]);
        }
    }

    for (std::size_t j = 0; j < kMlkemMatvecK; ++j) {
        for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
            int v = 0;

            if (vec_variant == 0) {
                v = ((static_cast<int>(i) * static_cast<int>(7 + j)) +
                     static_cast<int>(13 * j) - 19) % 23;
            } else {
                v = ((static_cast<int>(i) * static_cast<int>(11 + 2 * j)) +
                     static_cast<int>(17 * j) + 5) % kMlkemFieldQ;
            }

            vec_std[j][i] = static_cast<std::int16_t>(v);
            vec_ntt[j][i] = vec_std[j][i];
        }

        mlkem_poly_ntt_forward(vec_ntt[j]);
    }

    mlkem_matvec_mul_ntt(got_ntt, matrix_ntt, vec_ntt);

    // Direct reference: full helper must match three independent row helpers.
    for (std::size_t row = 0; row < kMlkemMatvecK; ++row) {
        mlkem_matvec_mul_row_ntt(row_ref_ntt[row], matrix_ntt[row], vec_ntt);

        if (!coeffs_equal(got_ntt[row], row_ref_ntt[row], kMlkemMatvecN)) {
            return fail("row helper equivalence mismatch");
        }
    }

    // Stronger external check: each output row, after inverse NTT, must equal
    // the standard-domain sum of negacyclic products.
    for (std::size_t row = 0; row < kMlkemMatvecK; ++row) {
        for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
            got_std[row][i] = got_ntt[row][i];
            expected_std[row][i] = 0;
        }

        mlkem_poly_invntt_tomont(got_std[row]);

        for (std::size_t col = 0; col < kMlkemMatvecK; ++col) {
            naive_negacyclic_mul(tmp_std, matrix_std[row][col], vec_std[col]);
            add_poly_mod_q(expected_std[row], tmp_std);
        }

        for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
            const std::int16_t actual = mlkem_canonicalize_q(got_std[row][i]);
            if (actual != expected_std[row][i]) {
                return fail("full pipeline mismatch");
            }
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemMatvecK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemMatvecN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Seed 1: 00 01 02 ... 1f
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
        }

        if (!check_case(rho, 0)) return 1;
        if (!check_case(rho, 1)) return 1;
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        if (!check_case(rho, 0)) return 1;
        if (!check_case(rho, 1)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] matvec full ntt ok"
        << " k=" << kMlkemMatvecK
        << " n=" << kMlkemMatvecN
        << "\n";

    return 0;
}