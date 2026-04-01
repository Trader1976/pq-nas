#pragma once

#include <cstddef>
#include <cstdint>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track tomont helpers.
    //
    // These convert standard-domain coefficients into Montgomery domain,
    // coefficient-wise, matching the role of poly_tomont() in the clean
    // ML-KEM / Kyber algebra path.
    //
    // This is the missing bridge before the IND-CPA keygen algebra skeleton.

    constexpr std::size_t kMlkemTomontN = 256;
    constexpr std::size_t kMlkemTomontK = 3;

    // Convert one polynomial coefficient array into Montgomery domain in place.
    //
    // Output coefficients are the Montgomery-domain representatives of the input
    // coefficients mod q.
    void mlkem_poly_tomont(std::int16_t coeffs[kMlkemTomontN]);

    // Convert one k=3 vector of polynomials into Montgomery domain in place.
    void mlkem_vec_tomont(std::int16_t vec[kMlkemTomontK][kMlkemTomontN]);

} // namespace pqnas::dna_pqcore_learn