#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track CPA-PKE wrapper for ML-KEM-768.
    //
    // This wraps the packed deterministic IND-CPA flow into a cleaner API:
    // - keypair_derand: d -> (rho, sigma) -> packed keypair
    // - encrypt_derand: packed deterministic encryption
    // - decrypt: packed deterministic decryption
    //
    // This is still NOT the final KEM layer.

    constexpr std::size_t kMlkemCpapkeSeedBytes = 32;
    constexpr std::size_t kMlkemCpapkeMsgBytes = 32;

    constexpr std::size_t kMlkemCpapkeSecretKeyBytes = 1152;
    constexpr std::size_t kMlkemCpapkePublicKeyBytes = 1184;
    constexpr std::size_t kMlkemCpapkeCiphertextBytes = 1088;

    // Learning helper:
    // derive rho || sigma = SHA3-512(d || 0x03), split into two 32-byte halves.
    bool mlkem_cpapke_derive_rho_sigma(
        std::uint8_t rho[kMlkemCpapkeSeedBytes],
        std::uint8_t sigma[kMlkemCpapkeSeedBytes],
        const std::uint8_t d[kMlkemCpapkeSeedBytes],
        std::string* err);

    // Deterministic CPA-PKE keypair generation from a 32-byte seed d.
    bool mlkem_cpapke_keypair_derand(
        std::uint8_t pk[kMlkemCpapkePublicKeyBytes],
        std::uint8_t sk[kMlkemCpapkeSecretKeyBytes],
        const std::uint8_t d[kMlkemCpapkeSeedBytes],
        std::string* err);

    // Deterministic CPA-PKE encryption from explicit coins.
    bool mlkem_cpapke_encrypt_derand(
        std::uint8_t ct[kMlkemCpapkeCiphertextBytes],
        const std::uint8_t msg[kMlkemCpapkeMsgBytes],
        const std::uint8_t pk[kMlkemCpapkePublicKeyBytes],
        const std::uint8_t coins[kMlkemCpapkeSeedBytes],
        std::string* err);

    // Deterministic CPA-PKE decryption.
    bool mlkem_cpapke_decrypt(
        std::uint8_t msg[kMlkemCpapkeMsgBytes],
        const std::uint8_t ct[kMlkemCpapkeCiphertextBytes],
        const std::uint8_t sk[kMlkemCpapkeSecretKeyBytes],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn