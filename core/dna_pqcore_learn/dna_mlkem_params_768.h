#pragma once

#include <cstddef>
#include <cstdint>

namespace dnanexus::pqlearn::mlkem768 {

    // This header is the starting point for the learning implementation.
    // It contains only fixed ML-KEM-768 parameters and small utility constants.
    // No vendored code is used here.

    constexpr std::size_t kN = 256;          // Polynomial degree
    constexpr std::int32_t kQ = 3329;        // Prime modulus

    // ML-KEM-768 parameter-set values.
    constexpr std::size_t kK = 3;
    constexpr std::size_t kEta1 = 2;
    constexpr std::size_t kEta2 = 2;
    constexpr std::size_t kDu = 10;
    constexpr std::size_t kDv = 4;

    // Byte sizes used by the standardized ML-KEM-768 format.
    // These are useful later when we compare our learning implementation
    // against the vendored backend and known-answer expectations.
    constexpr std::size_t kSymBytes = 32;
    constexpr std::size_t kSharedSecretBytes = 32;

    constexpr std::size_t kPublicKeyBytes = 1184;
    constexpr std::size_t kSecretKeyBytes = 2400;
    constexpr std::size_t kCiphertextBytes = 1088;

    // Internal packed sizes that become useful once we implement poly/polyvec
    // compression and IND-CPA structures.
    constexpr std::size_t kPolyBytes = 384;
    constexpr std::size_t kPolyVecBytes = kK * kPolyBytes;

    constexpr std::size_t kPolyCompressedBytesDu = 320;   // du = 10
    constexpr std::size_t kPolyCompressedBytesDv = 128;   // dv = 4
    constexpr std::size_t kPolyVecCompressedBytesDu = kK * kPolyCompressedBytesDu;

    // Small helpers used by later files.
    constexpr bool in_canonical_range(std::int32_t x) {
        return x >= 0 && x < kQ;
    }

    constexpr std::int32_t mod_q(std::int32_t x) {
        std::int32_t r = x % kQ;
        if (r < 0) r += kQ;
        return r;
    }

} // namespace dnanexus::pqlearn::mlkem768