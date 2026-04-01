#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

// Learning-track ML-KEM-768 wrapper.
//
// This wraps the already-built CPA-PKE core into a deterministic KEM API.
//
// For learning clarity:
// - keypair_derand takes explicit d and z
// - encaps_derand takes explicit 32-byte m
//
// So this is still deterministic and easy to test.
//
// Secret-key layout used here matches the usual ML-KEM / Kyber layout:
//
//   sk = sk_cpapke || pk || H(pk) || z
//
// Sizes for ML-KEM-768:
//   pk = 1184
//   sk = 2400
//   ct = 1088
//   ss = 32

constexpr std::size_t kMlkemKemSeedBytes = 32;
constexpr std::size_t kMlkemKemMsgBytes = 32;
constexpr std::size_t kMlkemKemSharedSecretBytes = 32;

constexpr std::size_t kMlkemKemPublicKeyBytes = 1184;
constexpr std::size_t kMlkemKemSecretKeyBytes = 2400;
constexpr std::size_t kMlkemKemCiphertextBytes = 1088;

// Deterministic ML-KEM-768 keypair generation.
//
// Inputs:
// - d: seed for deriving rho || sigma
// - z: fallback secret for decapsulation failure path
bool mlkem_kem_keypair_derand(
    std::uint8_t pk[kMlkemKemPublicKeyBytes],
    std::uint8_t sk[kMlkemKemSecretKeyBytes],
    const std::uint8_t d[kMlkemKemSeedBytes],
    const std::uint8_t z[kMlkemKemSeedBytes],
    std::string* err);

// Deterministic ML-KEM-768 encapsulation.
//
// Input:
// - pk: public key
// - m: explicit 32-byte encapsulation input
//
// Outputs:
// - ct: ciphertext
// - ss: shared secret
bool mlkem_kem_encaps_derand(
    std::uint8_t ct[kMlkemKemCiphertextBytes],
    std::uint8_t ss[kMlkemKemSharedSecretBytes],
    const std::uint8_t pk[kMlkemKemPublicKeyBytes],
    const std::uint8_t m[kMlkemKemMsgBytes],
    std::string* err);

// ML-KEM-768 decapsulation.
//
// Inputs:
// - ct: ciphertext
// - sk: secret key
//
// Output:
// - ss: shared secret
bool mlkem_kem_decaps(
    std::uint8_t ss[kMlkemKemSharedSecretBytes],
    const std::uint8_t ct[kMlkemKemCiphertextBytes],
    const std::uint8_t sk[kMlkemKemSecretKeyBytes],
    std::string* err);

} // namespace pqnas::dna_pqcore_learn