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

} // namespace pqnas::dna_pqcore_learn