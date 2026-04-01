#pragma once

#include "dna_mlkem_poly.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pqlearn::mlkem768 {

    // Learning-step compression helpers for one polynomial with du = 10.
    //
    // Each coefficient is compressed to 10 bits.
    // Four coefficients (40 bits total) are packed into 5 bytes.
    // For 256 coefficients total size is 320 bytes.
    //
    // Compression is lossy.
    // The stable property we test is:
    //   recompress(decompress(compress(x))) == compress(x)

    std::uint16_t compress_coeff_du10(std::int32_t x);
    std::int16_t decompress_coeff_du10(std::uint16_t t);

    bool poly_compress_du10(const Poly& p, std::vector<std::uint8_t>* out, std::string* err);
    bool poly_decompress_du10(const std::vector<std::uint8_t>& in, Poly* out, std::string* err);

} // namespace dnanexus::pqlearn::mlkem768