#include "dna_mlkem_backend_oracle.h"

#include <array>
#include <cstdint>

namespace {

// These are the real low-level ML-KEM-768 symbols used underneath the
// existing backend wrapper in core/dna_pqcore/dna_mlkem768_backend.cpp.
extern "C" {

int dnanexus_mlkem768_keypair_derand(std::uint8_t* pk,
                                     std::uint8_t* sk,
                                     const std::uint8_t* coins);

int dnanexus_mlkem768_enc_derand(std::uint8_t* ct,
                                 std::uint8_t* ss,
                                 const std::uint8_t* pk,
                                 const std::uint8_t* coins);

int dnanexus_mlkem768_dec(std::uint8_t* ss,
                          const std::uint8_t* ct,
                          const std::uint8_t* sk);

} // extern "C"

} // namespace

namespace pqnas::dna_pqcore_learn {

bool mlkem_oracle_keypair_derand(
    std::uint8_t pk[kMlkemOraclePublicKeyBytes],
    std::uint8_t sk[kMlkemOracleSecretKeyBytes],
    const std::uint8_t d[kMlkemOracleSeedBytes],
    const std::uint8_t z[kMlkemOracleSeedBytes],
    std::string* err) {
    if (pk == nullptr || sk == nullptr || d == nullptr || z == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    // The backend KEM keypair_derand consumes 64 bytes:
    //   coins = d || z
    std::array<std::uint8_t, 64> coins{};
    for (std::size_t i = 0; i < 32; ++i) {
        coins[i] = d[i];
        coins[32 + i] = z[i];
    }

    const int rc = dnanexus_mlkem768_keypair_derand(pk, sk, coins.data());
    if (rc != 0) {
        if (err) *err = "dnanexus_mlkem768_keypair_derand_failed";
        return false;
    }

    return true;
}

bool mlkem_oracle_encaps_derand(
    std::uint8_t ct[kMlkemOracleCiphertextBytes],
    std::uint8_t ss[kMlkemOracleSharedSecretBytes],
    const std::uint8_t pk[kMlkemOraclePublicKeyBytes],
    const std::uint8_t m[kMlkemOracleMsgBytes],
    std::string* err) {
    if (ct == nullptr || ss == nullptr || pk == nullptr || m == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    // The backend enc_derand consumes the explicit 32-byte encaps input.
    const int rc = dnanexus_mlkem768_enc_derand(ct, ss, pk, m);
    if (rc != 0) {
        if (err) *err = "dnanexus_mlkem768_enc_derand_failed";
        return false;
    }

    return true;
}

bool mlkem_oracle_decaps(
    std::uint8_t ss[kMlkemOracleSharedSecretBytes],
    const std::uint8_t ct[kMlkemOracleCiphertextBytes],
    const std::uint8_t sk[kMlkemOracleSecretKeyBytes],
    std::string* err) {
    if (ss == nullptr || ct == nullptr || sk == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    const int rc = dnanexus_mlkem768_dec(ss, ct, sk);
    if (rc != 0) {
        if (err) *err = "dnanexus_mlkem768_dec_failed";
        return false;
    }

    return true;
}

} // namespace pqnas::dna_pqcore_learn