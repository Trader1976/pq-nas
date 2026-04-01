#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

// Learning-track packed IND-CPA flow.
//
// This step wires together:
// - deterministic keygen algebra skeleton
// - deterministic encrypt algebra skeleton
// - deterministic decrypt algebra skeleton
// - message encode/decode
// - exact public/secret-key packing
// - ciphertext compression packing
//
// It still does NOT do the full KEM layer.

constexpr std::size_t kMlkemIndcpaPackedK = 3;
constexpr std::size_t kMlkemIndcpaPackedN = 256;
constexpr std::size_t kMlkemIndcpaPackedSeedBytes = 32;
constexpr std::size_t kMlkemIndcpaPackedMsgBytes = 32;

constexpr std::size_t kMlkemIndcpaSecretKeyBytes = 1152;
constexpr std::size_t kMlkemIndcpaPublicKeyBytes = 1184;
constexpr std::size_t kMlkemIndcpaCiphertextBytes = 1088;

// Deterministic packed IND-CPA keypair generation from rho and sigma.
//
// Outputs:
// - sk = pack(s_hat)
// - pk = pack(t_hat) || rho
bool mlkem_indcpa_keypair_packed_deterministic(
    std::uint8_t pk[kMlkemIndcpaPublicKeyBytes],
    std::uint8_t sk[kMlkemIndcpaSecretKeyBytes],
    const std::uint8_t rho[kMlkemIndcpaPackedSeedBytes],
    const std::uint8_t sigma[kMlkemIndcpaPackedSeedBytes],
    std::string* err);

// Deterministic packed IND-CPA encryption.
//
// Inputs:
// - pk: packed public key
// - coins: deterministic encryption randomness
// - msg: 32 message bytes
//
// Output:
// - ct: packed ciphertext
bool mlkem_indcpa_encrypt_packed_deterministic(
    std::uint8_t ct[kMlkemIndcpaCiphertextBytes],
    const std::uint8_t pk[kMlkemIndcpaPublicKeyBytes],
    const std::uint8_t coins[kMlkemIndcpaPackedSeedBytes],
    const std::uint8_t msg[kMlkemIndcpaPackedMsgBytes],
    std::string* err);

// Deterministic packed IND-CPA decryption.
//
// Inputs:
// - sk: packed secret key
// - ct: packed ciphertext
//
// Output:
// - msg: recovered 32 message bytes
bool mlkem_indcpa_decrypt_packed_deterministic(
    std::uint8_t msg[kMlkemIndcpaPackedMsgBytes],
    const std::uint8_t sk[kMlkemIndcpaSecretKeyBytes],
    const std::uint8_t ct[kMlkemIndcpaCiphertextBytes],
    std::string* err);

} // namespace pqnas::dna_pqcore_learn