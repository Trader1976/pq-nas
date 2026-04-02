#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_kem.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track randomized ML-KEM-768 convenience API.
    //
    // This is a thin wrapper over the deterministic KEM layer:
    //
    //   keypair(): sample d,z randomly and call keypair_derand()
    //   encaps():  sample m randomly and call encaps_derand()
    //   decaps():  same as deterministic decapsulation
    //
    // This gives the learn track a practical top-level API without changing
    // the already-tested deterministic core.

    constexpr std::size_t kMlkemKemRandomPublicKeyBytes = kMlkemKemPublicKeyBytes;
    constexpr std::size_t kMlkemKemRandomSecretKeyBytes = kMlkemKemSecretKeyBytes;
    constexpr std::size_t kMlkemKemRandomCiphertextBytes = kMlkemKemCiphertextBytes;
    constexpr std::size_t kMlkemKemRandomSharedSecretBytes = kMlkemKemSharedSecretBytes;

    // Randomized ML-KEM-768 keypair generation.
    bool mlkem_kem_keypair(
        std::uint8_t pk[kMlkemKemRandomPublicKeyBytes],
        std::uint8_t sk[kMlkemKemRandomSecretKeyBytes],
        std::string* err);

    // Randomized ML-KEM-768 encapsulation.
    bool mlkem_kem_encaps(
        std::uint8_t ct[kMlkemKemRandomCiphertextBytes],
        std::uint8_t ss[kMlkemKemRandomSharedSecretBytes],
        const std::uint8_t pk[kMlkemKemRandomPublicKeyBytes],
        std::string* err);

    // ML-KEM-768 decapsulation.
    bool mlkem_kem_decaps_random_api(
        std::uint8_t ss[kMlkemKemRandomSharedSecretBytes],
        const std::uint8_t ct[kMlkemKemRandomCiphertextBytes],
        const std::uint8_t sk[kMlkemKemRandomSecretKeyBytes],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn