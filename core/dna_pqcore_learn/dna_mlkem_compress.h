#pragma once

#include "dna_mlkem_poly.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pqlearn::mlkem768 {

    // Learning-step compression helpers for one polynomial.
    // This file starts with dv = 4 compression used for a single compressed poly
    // (128 bytes for 256 coefficients).
    //
    // Compression is lossy.
    // The expected stable property is:
    //   recompress(decompress(compress(x))) == compress(x)
    //
    // We require input coefficients to be canonical in [0, q).

    std::uint8_t compress_coeff_d4(std::int32_t x);
    std::int16_t decompress_coeff_d4(std::uint8_t t);

    // Compress one polynomial using 4 bits per coefficient.
    // Packs two 4-bit values into one byte -> 256 coeffs => 128 bytes.
    bool poly_compress_dv4(const Poly& p, std::vector<std::uint8_t>* out, std::string* err);

    // Inverse of poly_compress_dv4().
    // Decodes exactly 128 bytes into one polynomial in canonical coefficient range.
    bool poly_decompress_dv4(const std::vector<std::uint8_t>& in, Poly* out, std::string* err);

} // namespace dnanexus::pqlearn::mlkem768