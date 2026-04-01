#include "dna_mlkem_matrix_gen.h"

#include "dna_mlkem_sample_ntt.h"

namespace pqnas::dna_pqcore_learn {

bool mlkem_matrix_entry_ntt(std::int16_t coeffs[kMlkemMatrixGenN],
                            const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                            std::uint8_t row,
                            std::uint8_t col,
                            std::string* err) {
    if (coeffs == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    // A[row][col] = SampleNTT(rho, col, row)
    return mlkem_sample_ntt(coeffs, rho, col, row, err);
}

bool mlkem_matrix_entry_ntt_transposed(std::int16_t coeffs[kMlkemMatrixGenN],
                                       const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                                       std::uint8_t row,
                                       std::uint8_t col,
                                       std::string* err) {
    if (coeffs == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    // A^T[row][col] = SampleNTT(rho, row, col)
    return mlkem_sample_ntt(coeffs, rho, row, col, err);
}

bool mlkem_matrix_ntt(std::int16_t a[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN],
                      const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                      std::string* err) {
    if (a == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    for (std::uint8_t row = 0; row < static_cast<std::uint8_t>(kMlkemMatrixGenK); ++row) {
        for (std::uint8_t col = 0; col < static_cast<std::uint8_t>(kMlkemMatrixGenK); ++col) {
            if (!mlkem_matrix_entry_ntt(a[row][col], rho, row, col, err)) {
                return false;
            }
        }
    }

    return true;
}

bool mlkem_matrix_ntt_transposed(
    std::int16_t at[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN],
    const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
    std::string* err) {
    if (at == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    for (std::uint8_t row = 0; row < static_cast<std::uint8_t>(kMlkemMatrixGenK); ++row) {
        for (std::uint8_t col = 0; col < static_cast<std::uint8_t>(kMlkemMatrixGenK); ++col) {
            if (!mlkem_matrix_entry_ntt_transposed(at[row][col], rho, row, col, err)) {
                return false;
            }
        }
    }

    return true;
}

} // namespace pqnas::dna_pqcore_learn