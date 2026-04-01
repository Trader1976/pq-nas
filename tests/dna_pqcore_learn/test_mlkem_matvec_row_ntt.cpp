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
    std::cerr << "[dna-pqcore-learn] matvec row ntt test failed: " << msg << "\n";
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
                std::uint8_t row_index) {
    std::string err;

    std::int16_t row_ntt[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t row_std[kMlkemMatvecK][kMlkemMatvecN]{};

    std::int16_t vec_std[kMlkemMatvecK][kMlkemMatvecN]{};
    std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]{};

    std::int16_t got_ntt[kMlkemMatvecN]{};
    std::int16_t ref_ntt[kMlkemMatvecN]{};
    std::int16_t tmp_ntt[kMlkemMatvecN]{};

    std::int16_t got_std[kMlkemMatvecN]{};
    std::int16_t expected_std[kMlkemMatvecN]{};
    std::int16_t tmp_std[kMlkemMatvecN]{};

    // Build one matrix row in NTT representation and also recover a standard
    // polynomial representative for each entry.
    for (std::size_t col = 0; col < kMlkemMatvecK; ++col) {
        if (!mlkem_matrix_entry_ntt(row_ntt[col], rho.data(), row_index,
                                    static_cast<std::uint8_t>(col), &err)) {
            std::cerr << err << "\n";
            return fail("mlkem_matrix_entry_ntt failed");
        }

        ntt_to_standard_poly(row_std[col], row_ntt[col]);
    }

    // Build a deterministic standard-domain vector and also its NTT form.
    for (std::size_t j = 0; j < kMlkemMatvecK; ++j) {
        for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
            const int v =
                ((static_cast<int>(i) * static_cast<int>(7 + j)) +
                 static_cast<int>(13 * j) - 19) % 23;
            vec_std[j][i] = static_cast<std::int16_t>(v);
            vec_ntt[j][i] = vec_std[j][i];
        }

        mlkem_poly_ntt_forward(vec_ntt[j]);
    }

    // Row helper under test.
    mlkem_matvec_mul_row_ntt(got_ntt, row_ntt, vec_ntt);

    // Direct internal reference:
    // sum_j basemul(row_ntt[j], vec_ntt[j]).
    mlkem_poly_basemul_montgomery(ref_ntt, row_ntt[0], vec_ntt[0]);
    for (std::size_t j = 1; j < kMlkemMatvecK; ++j) {
        mlkem_poly_basemul_montgomery(tmp_ntt, row_ntt[j], vec_ntt[j]);
        for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
            ref_ntt[i] = static_cast<std::int16_t>(ref_ntt[i] + tmp_ntt[i]);
        }
    }

    if (!coeffs_equal(got_ntt, ref_ntt, kMlkemMatvecN)) {
        return fail("direct row accumulation mismatch");
    }

    // Stronger external check:
    // invntt_tomont(dot_ntt) should equal the standard-domain negacyclic sum
    // of row_std[j] * vec_std[j].
    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        got_std[i] = got_ntt[i];
        expected_std[i] = 0;
    }

    mlkem_poly_invntt_tomont(got_std);

    for (std::size_t j = 0; j < kMlkemMatvecK; ++j) {
        naive_negacyclic_mul(tmp_std, row_std[j], vec_std[j]);
        add_poly_mod_q(expected_std, tmp_std);
    }

    for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
        const std::int16_t actual = mlkem_canonicalize_q(got_std[i]);
        if (actual != expected_std[i]) {
            return fail("full pipeline mismatch");
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

        for (std::uint8_t row = 0; row < kMlkemMatvecK; ++row) {
            if (!check_case(rho, row)) return 1;
        }
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        for (std::uint8_t row = 0; row < kMlkemMatvecK; ++row) {
            if (!check_case(rho, row)) return 1;
        }
    }

    std::cout
        << "[dna-pqcore-learn] matvec row ntt ok"
        << " k=" << kMlkemMatvecK
        << " n=" << kMlkemMatvecN
        << "\n";

    return 0;
}