#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track PRF/XOF layer.
    //
    // This step is still deterministic and isolated:
    // - input: 32-byte seed + 1-byte nonce
    // - core: SHAKE-256(seed || nonce)
    // - output: first 64*eta bytes
    //
    // This is the exact bridge needed before wiring into the CBD samplers.

    constexpr std::size_t kMlkemSymBytes = 32;
    constexpr std::size_t kMlkemPrfEta2Bytes = 64 * 2; // 128
    constexpr std::size_t kMlkemPrfEta3Bytes = 64 * 3; // 192

    // Expand SHAKE-256(seed || nonce) to 64*eta bytes for eta = 2.
    bool mlkem_prf_eta2(std::uint8_t out[kMlkemPrfEta2Bytes],
                        const std::uint8_t seed[kMlkemSymBytes],
                        std::uint8_t nonce,
                        std::string* err);

    // Expand SHAKE-256(seed || nonce) to 64*eta bytes for eta = 3.
    bool mlkem_prf_eta3(std::uint8_t out[kMlkemPrfEta3Bytes],
                        const std::uint8_t seed[kMlkemSymBytes],
                        std::uint8_t nonce,
                        std::string* err);

} // namespace pqnas::dna_pqcore_learn