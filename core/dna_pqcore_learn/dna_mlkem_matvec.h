#pragma once

#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track matrix-vector multiplication layer.
    //
    // Current scope:
    // - one row of a k=3 matrix in NTT representation times one k=3 vector
    // - full k=3 matrix times one k=3 vector, all in NTT representation
    //
    // This stays at the array level and mirrors the IND-CPA algebra shape
    // without yet introducing typed poly/polyvec wrappers.

    constexpr std::size_t kMlkemMatvecK = 3;
    constexpr std::size_t kMlkemMatvecN = 256;

    // Compute one NTT-domain row-vector dot product:
    //
    //   out_ntt = sum_{j=0..k-1} row_ntt[j] (*) vec_ntt[j]
    //
    // where (*) is the usual ML-KEM / Kyber NTT-domain polynomial multiply.
    void mlkem_matvec_mul_row_ntt(
        std::int16_t out_ntt[kMlkemMatvecN],
        const std::int16_t row_ntt[kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]);

    // Compute the full k=3 matrix-vector product in NTT representation:
    //
    //   out_vec_ntt[row] = sum_{col=0..k-1} matrix_ntt[row][col] (*) vec_ntt[col]
    //
    // Inputs:
    // - matrix_ntt[row][col]: one matrix entry in NTT representation
    // - vec_ntt[col]: one vector polynomial in NTT representation
    //
    // Output:
    // - out_vec_ntt[row]: one output vector polynomial in NTT representation
    void mlkem_matvec_mul_ntt(
        std::int16_t out_vec_ntt[kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t matrix_ntt[kMlkemMatvecK][kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]);

} // namespace pqnas::dna_pqcore_learn