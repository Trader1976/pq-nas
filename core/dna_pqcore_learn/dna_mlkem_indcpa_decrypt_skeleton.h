#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "dna_mlkem_params_768.h"

namespace pqnas::dna_pqcore_learn {

    // Learning-track deterministic IND-CPA decryption algebra skeleton.
    //
    // This step intentionally starts from:
    // - s_hat already given
    // - u already given
    // - v already given
    //
    // It does NOT yet do:
    // - ciphertext unpack / decompress
    // - message decode
    // - full K-PKE / KEM wiring
    //
    // It only builds the algebra core for ML-KEM-768:
    //
    //   u_hat <- NTT(u)
    //   w     <- invntt_tomont(<s_hat, u_hat>)
    //   m'    <- v - w
    //
    // All objects remain array-level for clarity.

    constexpr std::size_t kMlkemDecryptSkelK = 3;
    constexpr std::size_t kMlkemDecryptSkelN = 256;

    // Build the deterministic algebra core of IND-CPA decryption.
    //
    // Inputs:
    // - s_hat: secret-key polynomial vector in NTT representation
    // - u:     ciphertext vector polynomial in standard polynomial domain
    // - v:     ciphertext polynomial in standard polynomial domain
    //
    // Outputs:
    // - u_hat: NTT(u)
    // - m_poly: pre-decode message polynomial in standard polynomial domain
    bool mlkem_indcpa_decrypt_algebra_skeleton(
        std::int16_t u_hat[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        std::int16_t m_poly[kMlkemDecryptSkelN],
        const std::int16_t s_hat[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        const std::int16_t u[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        const std::int16_t v[kMlkemDecryptSkelN],
        std::string* err);

} // namespace pqnas::dna_pqcore_learn