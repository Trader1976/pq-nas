#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track SampleNTT layer.
    //
    // This is the direct bridge from:
    //   rho (32 bytes) + j (1 byte) + i (1 byte)
    //     -> SHAKE-128 XOF stream
    //     -> uniform rejection sampling
    //     -> 256 coefficients in [0, q)
    //
    // This corresponds to FIPS 203 Algorithm 7 at the array level.
    // We are NOT building the full matrix wrapper yet.

    constexpr std::size_t kMlkemSampleNttN = 256;
    constexpr std::size_t kMlkemSampleNttSeedBytes = 32;
    constexpr std::size_t kMlkemSampleNttInputBytes = 34;

    // Sample one NTT-domain polynomial from rho || j || i.
    //
    // Input:
    // - rho: 32-byte public seed
    // - j:   column index byte
    // - i:   row index byte
    //
    // Output:
    // - coeffs[0..255], each canonical in [0, q)
    //
    // Returns false on OpenSSL/XOF failure.
    bool mlkem_sample_ntt(std::int16_t coeffs[kMlkemSampleNttN],
                          const std::uint8_t rho[kMlkemSampleNttSeedBytes],
                          std::uint8_t j,
                          std::uint8_t i,
                          std::string* err);

} // namespace pqnas::dna_pqcore_learn