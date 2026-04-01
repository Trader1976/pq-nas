#pragma once

#include "dna_mlkem_polyvec.h"

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pqlearn::mlkem768 {

    // Byte encoding for a PolyVec in plain polynomial-byte form.
    //
    // For ML-KEM-768:
    // - one polynomial encodes to 384 bytes
    // - one polyvec contains k = 3 polynomials
    // - total encoded size is 3 * 384 = 1152 bytes
    //
    // This is the uncompressed polyvec byte form used by several internal ML-KEM
    // structures. At this stage we require all coefficients to be canonical.
    bool polyvec_to_bytes(const PolyVec& v, std::vector<std::uint8_t>* out, std::string* err);

    // Inverse of polyvec_to_bytes(). Decodes exactly kPolyVecBytes bytes.
    bool polyvec_from_bytes(const std::vector<std::uint8_t>& in, PolyVec* out, std::string* err);

} // namespace dnanexus::pqlearn::mlkem768