#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

// Learning-track deterministic IND-CPA encryption algebra skeleton.
//
// This step intentionally starts from:
// - t_hat already given
// - rho already given
// - coins already given
// - message polynomial m already given
//
// It does NOT yet do:
// - message encode / decode
// - ciphertext compression / packing
// - full K-PKE / KEM wiring
//
// It only builds the algebra core for ML-KEM-768:
//
//   A_hat^T <- matrix_ntt_transposed(rho)
//   r,e1    <- noisevec_eta2(coins, nonce schedule)
//   e2      <- getnoise_eta2(coins, 6)
//   r_hat   <- NTT(r)
//   u       <- invntt_tomont(A_hat^T * r_hat) + e1
//   v       <- invntt_tomont(<t_hat, r_hat>) + e2 + m
//
// All objects remain array-level for clarity.

constexpr std::size_t kMlkemEncryptSkelK = 3;
constexpr std::size_t kMlkemEncryptSkelN = 256;
constexpr std::size_t kMlkemEncryptSkelSeedBytes = 32;

// Build the deterministic algebra core of IND-CPA encryption.
//
// Nonce schedule used here:
// - r  uses eta=2 with nonces 0,1,2
// - e1 uses eta=2 with nonces 3,4,5
// - e2 uses eta=2 with nonce  6
//
// Inputs:
// - t_hat: public-key polynomial vector in NTT representation
// - rho:   public matrix seed
// - coins: deterministic encryption randomness
// - m:     message polynomial in standard polynomial domain
//
// Outputs:
// - r_hat: NTT(r)
// - u:     standard-domain vector polynomial
// - v:     standard-domain polynomial
bool mlkem_indcpa_encrypt_algebra_skeleton(
    std::int16_t r_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    std::int16_t u[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    std::int16_t v[kMlkemEncryptSkelN],
    const std::int16_t t_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    const std::uint8_t rho[kMlkemEncryptSkelSeedBytes],
    const std::uint8_t coins[kMlkemEncryptSkelSeedBytes],
    const std::int16_t m[kMlkemEncryptSkelN],
    std::string* err);

} // namespace pqnas::dna_pqcore_learn