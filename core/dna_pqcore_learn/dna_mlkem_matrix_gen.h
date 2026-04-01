#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track matrix-entry generation layer.
    //
    // This is the thin wrapper around SampleNTT needed before building
    // the full k x k matrix generation step.
    //
    // For ML-KEM / Kyber matrix generation:
    //
    //   A[row][col] = SampleNTT(rho, col, row)
    //
    // and for the transposed view:
    //
    //   A^T[row][col] = SampleNTT(rho, row, col)

    constexpr std::size_t kMlkemMatrixGenN = 256;
    constexpr std::size_t kMlkemMatrixGenSeedBytes = 32;
    constexpr std::size_t kMlkemMatrixGenK = 3;

    // Generate one matrix entry in NTT representation:
    //
    //   A[row][col] = SampleNTT(rho, col, row)
    bool mlkem_matrix_entry_ntt(std::int16_t coeffs[kMlkemMatrixGenN],
                                const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                                std::uint8_t row,
                                std::uint8_t col,
                                std::string* err);

    // Generate one transposed matrix entry in NTT representation:
    //
    //   A^T[row][col] = SampleNTT(rho, row, col)
    bool mlkem_matrix_entry_ntt_transposed(std::int16_t coeffs[kMlkemMatrixGenN],
                                           const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                                           std::uint8_t row,
                                           std::uint8_t col,
                                           std::string* err);

} // namespace pqnas::dna_pqcore_learn