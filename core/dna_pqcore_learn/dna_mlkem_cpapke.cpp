#include "dna_mlkem_cpapke.h"

#include <array>

#include <openssl/evp.h>

#include "dna_mlkem_indcpa_packed.h"

namespace pqnas::dna_pqcore_learn {
namespace {

constexpr std::size_t kSha3_512_Bytes = 64;

bool mlkem_sha3_512(std::uint8_t out[kSha3_512_Bytes],
                    const std::uint8_t in[kMlkemCpapkeSeedBytes],
                    std::string* err) {
    if (out == nullptr || in == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = true;
    unsigned int out_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex(EVP_sha3_512) failed";
        ok = false;
    } else if (EVP_DigestUpdate(ctx, in, kMlkemCpapkeSeedBytes) != 1) {
        if (err) *err = "EVP_DigestUpdate failed";
        ok = false;
    } else if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        ok = false;
    } else if (out_len != kSha3_512_Bytes) {
        if (err) *err = "unexpected SHA3-512 output length";
        ok = false;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace

bool mlkem_cpapke_derive_rho_sigma(
    std::uint8_t rho[kMlkemCpapkeSeedBytes],
    std::uint8_t sigma[kMlkemCpapkeSeedBytes],
    const std::uint8_t d[kMlkemCpapkeSeedBytes],
    std::string* err) {
    if (rho == nullptr || sigma == nullptr || d == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::array<std::uint8_t, kSha3_512_Bytes> buf{};
    if (!mlkem_sha3_512(buf.data(), d, err)) {
        return false;
    }

    for (std::size_t i = 0; i < kMlkemCpapkeSeedBytes; ++i) {
        rho[i] = buf[i];
        sigma[i] = buf[kMlkemCpapkeSeedBytes + i];
    }

    return true;
}

bool mlkem_cpapke_keypair_derand(
    std::uint8_t pk[kMlkemCpapkePublicKeyBytes],
    std::uint8_t sk[kMlkemCpapkeSecretKeyBytes],
    const std::uint8_t d[kMlkemCpapkeSeedBytes],
    std::string* err) {
    if (pk == nullptr || sk == nullptr || d == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::uint8_t rho[kMlkemCpapkeSeedBytes]{};
    std::uint8_t sigma[kMlkemCpapkeSeedBytes]{};

    if (!mlkem_cpapke_derive_rho_sigma(rho, sigma, d, err)) {
        return false;
    }

    return mlkem_indcpa_keypair_packed_deterministic(pk, sk, rho, sigma, err);
}

bool mlkem_cpapke_encrypt_derand(
    std::uint8_t ct[kMlkemCpapkeCiphertextBytes],
    const std::uint8_t msg[kMlkemCpapkeMsgBytes],
    const std::uint8_t pk[kMlkemCpapkePublicKeyBytes],
    const std::uint8_t coins[kMlkemCpapkeSeedBytes],
    std::string* err) {
    return mlkem_indcpa_encrypt_packed_deterministic(ct, pk, coins, msg, err);
}

bool mlkem_cpapke_decrypt(
    std::uint8_t msg[kMlkemCpapkeMsgBytes],
    const std::uint8_t ct[kMlkemCpapkeCiphertextBytes],
    const std::uint8_t sk[kMlkemCpapkeSecretKeyBytes],
    std::string* err) {
    return mlkem_indcpa_decrypt_packed_deterministic(msg, sk, ct, err);
}

} // namespace pqnas::dna_pqcore_learn