#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_sample_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] matrix entry ntt test failed: " << msg << "\n";
    return false;
}

template <std::size_t N>
bool arrays_equal(const std::array<std::int16_t, N>& a,
                  const std::array<std::int16_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool check_range(const std::array<std::int16_t, kMlkemMatrixGenN>& coeffs) {
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] < 0 || coeffs[i] >= kMlkemFieldQ) {
            return false;
        }
    }
    return true;
}

bool check_case(const std::array<std::uint8_t, kMlkemMatrixGenSeedBytes>& rho,
                std::uint8_t row,
                std::uint8_t col) {
    std::string err;

    std::array<std::int16_t, kMlkemMatrixGenN> normal{};
    std::array<std::int16_t, kMlkemMatrixGenN> normal_ref{};
    std::array<std::int16_t, kMlkemMatrixGenN> transposed{};
    std::array<std::int16_t, kMlkemMatrixGenN> transposed_ref{};
    std::array<std::int16_t, kMlkemMatrixGenN> transpose_relation{};

    if (!mlkem_matrix_entry_ntt(normal.data(), rho.data(), row, col, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_entry_ntt failed");
    }

    if (!mlkem_sample_ntt(normal_ref.data(), rho.data(), col, row, &err)) {
        std::cerr << err << "\n";
        return fail("direct SampleNTT(col,row) failed");
    }

    if (!arrays_equal(normal, normal_ref)) {
        return fail("normal wrapper mismatch");
    }

    if (!mlkem_matrix_entry_ntt_transposed(transposed.data(), rho.data(), row, col, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_matrix_entry_ntt_transposed failed");
    }

    if (!mlkem_sample_ntt(transposed_ref.data(), rho.data(), row, col, &err)) {
        std::cerr << err << "\n";
        return fail("direct SampleNTT(row,col) failed");
    }

    if (!arrays_equal(transposed, transposed_ref)) {
        return fail("transposed wrapper mismatch");
    }

    // A[row][col] must equal A^T[col][row].
    if (!mlkem_matrix_entry_ntt_transposed(transpose_relation.data(), rho.data(), col, row, &err)) {
        std::cerr << err << "\n";
        return fail("transpose relation generation failed");
    }

    if (!arrays_equal(normal, transpose_relation)) {
        return fail("A[row][col] != A^T[col][row]");
    }

    if (!check_range(normal)) return fail("normal range check failed");
    if (!check_range(transposed)) return fail("transposed range check failed");

    // Determinism.
    std::array<std::int16_t, kMlkemMatrixGenN> again{};
    if (!mlkem_matrix_entry_ntt(again.data(), rho.data(), row, col, &err)) {
        std::cerr << err << "\n";
        return fail("normal repeat failed");
    }

    if (!arrays_equal(normal, again)) {
        return fail("normal determinism mismatch");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemMatrixGenN == 256, "test assumes N = 256");
    static_assert(kMlkemMatrixGenSeedBytes == 32, "test assumes 32-byte rho");
    static_assert(kMlkemMatrixGenK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Seed 1: 00 01 02 ... 1f
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
        }

        for (std::uint8_t row = 0; row < kMlkemMatrixGenK; ++row) {
            for (std::uint8_t col = 0; col < kMlkemMatrixGenK; ++col) {
                if (!check_case(rho, row, col)) return 1;
            }
        }
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemMatrixGenSeedBytes> rho{};
        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        for (std::uint8_t row = 0; row < kMlkemMatrixGenK; ++row) {
            for (std::uint8_t col = 0; col < kMlkemMatrixGenK; ++col) {
                if (!check_case(rho, row, col)) return 1;
            }
        }
    }

    std::cout
        << "[dna-pqcore-learn] matrix entry ntt ok"
        << " k=" << kMlkemMatrixGenK
        << " n=" << kMlkemMatrixGenN
        << "\n";

    return 0;
}