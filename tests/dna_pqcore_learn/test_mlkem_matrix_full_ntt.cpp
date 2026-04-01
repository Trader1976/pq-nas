#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_matrix_gen.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] matrix full ntt test failed: " << msg << "\n";
    return false;
}

bool coeffs_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool coeffs_in_range(const std::int16_t* a, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] < 0 || a[i] >= kMlkemFieldQ) return false;
    }
    return true;
}

bool check_case(const std::array<std::uint8_t, kMlkemMatrixGenSeedBytes>& rho) {
    std::string err;

    std::int16_t a[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN]{};
    std::int16_t at[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN]{};
    std::int16_t a_again[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN]{};

    if (!mlkem_matrix_ntt(a, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_ntt failed");
    }

    if (!mlkem_matrix_ntt_transposed(at, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_ntt_transposed failed");
    }

    if (!mlkem_matrix_ntt(a_again, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_ntt repeat failed");
    }

    for (std::size_t row = 0; row < kMlkemMatrixGenK; ++row) {
        for (std::size_t col = 0; col < kMlkemMatrixGenK; ++col) {
            std::int16_t entry[kMlkemMatrixGenN]{};
            std::int16_t entry_t[kMlkemMatrixGenN]{};

            if (!mlkem_matrix_entry_ntt(entry, rho.data(),
                                        static_cast<std::uint8_t>(row),
                                        static_cast<std::uint8_t>(col),
                                        &err)) {
                std::cerr << err << "\n";
                return fail("mlkem_matrix_entry_ntt failed");
            }

            if (!mlkem_matrix_entry_ntt_transposed(entry_t, rho.data(),
                                                   static_cast<std::uint8_t>(row),
                                                   static_cast<std::uint8_t>(col),
                                                   &err)) {
                std::cerr << err << "\n";
                return fail("mlkem_matrix_entry_ntt_transposed failed");
            }

            if (!coeffs_equal(a[row][col], entry, kMlkemMatrixGenN)) {
                return fail("full matrix entry mismatch");
            }

            if (!coeffs_equal(at[row][col], entry_t, kMlkemMatrixGenN)) {
                return fail("full transposed matrix entry mismatch");
            }

            if (!coeffs_equal(a[row][col], at[col][row], kMlkemMatrixGenN)) {
                return fail("A[row][col] != A^T[col][row]");
            }

            if (!coeffs_equal(a[row][col], a_again[row][col], kMlkemMatrixGenN)) {
                return fail("full matrix determinism mismatch");
            }

            if (!coeffs_in_range(a[row][col], kMlkemMatrixGenN)) {
                return fail("full matrix range check failed");
            }

            if (!coeffs_in_range(at[row][col], kMlkemMatrixGenN)) {
                return fail("full transposed matrix range check failed");
            }
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemMatrixGenK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemMatrixGenN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Seed 1: 00 01 02 ... 1f
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
        }

        if (!check_case(rho)) return 1;
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        if (!check_case(rho)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] matrix full ntt ok"
        << " k=" << kMlkemMatrixGenK
        << " n=" << kMlkemMatrixGenN
        << "\n";

    return 0;
}