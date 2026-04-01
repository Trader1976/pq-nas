#pragma once

#include "dna_mlkem_polyvec.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pqlearn::mlkem768 {

    // Compress one PolyVec using du = 10.
    //
    // For ML-KEM-768:
    // - one polynomial compressed with du=10 -> 320 bytes
    // - one polyvec contains k = 3 polynomials
    // - total encoded size is 3 * 320 = 960 bytes
    //
    // Compression is lossy.
    // The stable property we test is:
    //   recompress(decompress(compress(v))) == compress(v)
    bool polyvec_compress_du10(const PolyVec& v, std::vector<std::uint8_t>* out, std::string* err);

    // Inverse of polyvec_compress_du10().
    // Decodes exactly 960 bytes into one polyvec.
    bool polyvec_decompress_du10(const std::vector<std::uint8_t>& in, PolyVec* out, std::string* err);

} // namespace dnanexus::pqlearn::mlkem768