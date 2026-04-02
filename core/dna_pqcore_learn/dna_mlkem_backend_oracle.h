#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pqnas::dna_pqcore_learn {

    // Thin adapter boundary between the learn track and the already-existing
    // backend/oracle wrapper in core/dna_pqcore.
    //
    // Goal:
    // - keep all backend naming uncertainty in one place
    // - let the actual comparison test stay clean
    //
    // Expected ML-KEM-768 sizes:
    constexpr std::size_t kMlkemOraclePublicKeyBytes = 1184;
    constexpr std::size_t kMlkemOracleSecretKeyBytes = 2400;
    constexpr std::size_t kMlkemOracleCiphertextBytes = 1088;
    constexpr std::size_t kMlkemOracleSharedSecretBytes = 32;
    constexpr std::size_t kMlkemOracleSeedBytes = 32;
    constexpr std::size_t kMlkemOracleMsgBytes = 32;

    // Deterministic backend keypair from explicit d and z.
    bool mlkem_oracle_keypair_derand(
        std::uint8_t pk[kMlkemOraclePublicKeyBytes],
        std::uint8_t sk[kMlkemOracleSecretKeyBytes],
        const std::uint8_t d[kMlkemOracleSeedBytes],
        const std::uint8_t z[kMlkemOracleSeedBytes],
        std::string* err);

    // Deterministic backend encaps from explicit 32-byte m.
    bool mlkem_oracle_encaps_derand(
        std::uint8_t ct[kMlkemOracleCiphertextBytes],
        std::uint8_t ss[kMlkemOracleSharedSecretBytes],
        const std::uint8_t pk[kMlkemOraclePublicKeyBytes],
        const std::uint8_t m[kMlkemOracleMsgBytes],
        std::string* err);

    // Backend decapsulation.
    bool mlkem_oracle_decaps(
        std::uint8_t ss[kMlkemOracleSharedSecretBytes],
        const std::uint8_t ct[kMlkemOracleCiphertextBytes],
        const std::uint8_t sk[kMlkemOracleSecretKeyBytes],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn