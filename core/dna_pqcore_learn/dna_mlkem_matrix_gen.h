#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

// Learning-track matrix generation layer.
//
// Current scope:
// - one matrix entry in NTT representation
// - one transposed matrix entry in NTT representation
// - full k x k matrix generation for ML-KEM-768 (k = 3)
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

// Generate the full k x k matrix A in NTT representation:
//
//   A[row][col] = SampleNTT(rho, col, row)
bool mlkem_matrix_ntt(std::int16_t a[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN],
                      const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
                      std::string* err);

// Generate the full transposed matrix A^T in NTT representation:
//
//   A^T[row][col] = SampleNTT(rho, row, col)
bool mlkem_matrix_ntt_transposed(
    std::int16_t at[kMlkemMatrixGenK][kMlkemMatrixGenK][kMlkemMatrixGenN],
    const std::uint8_t rho[kMlkemMatrixGenSeedBytes],
    std::string* err);

} // namespace pqnas::dna_pqcore_learn