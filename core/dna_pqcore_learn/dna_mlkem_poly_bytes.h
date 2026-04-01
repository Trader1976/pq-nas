#pragma once

#include "dna_mlkem_poly.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pqlearn::mlkem768 {

    // ML-KEM polynomial byte encoding for a full polynomial in canonical form.
    //
    // For ML-KEM / Kyber, a polynomial with 256 coefficients is serialized into
    // 384 bytes by packing two 12-bit coefficients into 3 bytes:
    //
    //   c0 = a0[11:0]
    //   c1 = a1[11:0]
    //
    //   b0 = low 8 bits of c0
    //   b1 = high 4 bits of c0 | low 4 bits of c1 shifted left
    //   b2 = high 8 bits of c1
    //
    // This representation is used by public/secret key polynomial vectors.
    //
    // In this learning step we require coefficients to be canonical in [0, q).
    bool poly_to_bytes(const Poly& p, std::vector<std::uint8_t>* out, std::string* err);

    // Inverse of poly_to_bytes(). Decodes exactly 384 bytes into one polynomial.
    // Rejects decoded coefficients outside canonical [0, q) range.
    bool poly_from_bytes(const std::vector<std::uint8_t>& in, Poly* out, std::string* err);

} // namespace dnanexus::pqlearn::mlkem768