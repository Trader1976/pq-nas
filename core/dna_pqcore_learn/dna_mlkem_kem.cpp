#include "dna_mlkem_kem.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include <openssl/evp.h>

#include "dna_mlkem_cpapke.h"
#include "dna_mlkem_indcpa_packed.h"

namespace pqnas::dna_pqcore_learn {
namespace {

constexpr std::size_t kSha3_256_Bytes = 32;
constexpr std::size_t kSha3_512_Bytes = 64;
constexpr std::size_t kSkCpapkeBytes = 1152;
constexpr std::size_t kPkOffset = kSkCpapkeBytes;
constexpr std::size_t kHpkOffset = kSkCpapkeBytes + kMlkemKemPublicKeyBytes;
constexpr std::size_t kZOffset = kHpkOffset + kSha3_256_Bytes;

static_assert(kMlkemKemSecretKeyBytes == 2400, "unexpected ML-KEM-768 sk size");
static_assert(kZOffset + kMlkemKemSeedBytes == kMlkemKemSecretKeyBytes,
              "unexpected secret-key layout");

bool bytes_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool sha3_256_bytes(std::uint8_t out[kSha3_256_Bytes],
                    const std::uint8_t* in,
                    std::size_t in_len,
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

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex(EVP_sha3_256) failed";
        ok = false;
    } else if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
        if (err) *err = "EVP_DigestUpdate failed";
        ok = false;
    } else if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        ok = false;
    } else if (out_len != kSha3_256_Bytes) {
        if (err) *err = "unexpected SHA3-256 output length";
        ok = false;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool sha3_512_bytes(std::uint8_t out[kSha3_512_Bytes],
                    const std::uint8_t* in,
                    std::size_t in_len,
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
    } else if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
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

bool shake256_32(std::uint8_t out[kMlkemKemSharedSecretBytes],
                 const std::uint8_t* in,
                 std::size_t in_len,
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

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex(EVP_shake256) failed";
        ok = false;
    } else if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
        if (err) *err = "EVP_DigestUpdate failed";
        ok = false;
    } else if (EVP_DigestFinalXOF(ctx, out, kMlkemKemSharedSecretBytes) != 1) {
        if (err) *err = "EVP_DigestFinalXOF failed";
        ok = false;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool derive_shared_secret(std::uint8_t ss[kMlkemKemSharedSecretBytes],
                          const std::uint8_t key_part[kMlkemKemSeedBytes],
                          const std::uint8_t hct[kSha3_256_Bytes],
                          std::string* err) {
    std::array<std::uint8_t, 64> in{};
    for (std::size_t i = 0; i < 32; ++i) {
        in[i] = key_part[i];
        in[32 + i] = hct[i];
    }
    return shake256_32(ss, in.data(), in.size(), err);
}

} // namespace

bool mlkem_kem_keypair_derand(
    std::uint8_t pk[kMlkemKemPublicKeyBytes],
    std::uint8_t sk[kMlkemKemSecretKeyBytes],
    const std::uint8_t d[kMlkemKemSeedBytes],
    const std::uint8_t z[kMlkemKemSeedBytes],
    std::string* err) {
    if (pk == nullptr || sk == nullptr || d == nullptr || z == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::uint8_t rho[32]{};
    std::uint8_t sigma[32]{};
    std::uint8_t hpk[32]{};

    if (!mlkem_cpapke_derive_rho_sigma(rho, sigma, d, err)) {
        return false;
    }

    if (!mlkem_indcpa_keypair_packed_deterministic(pk, sk, rho, sigma, err)) {
        return false;
    }

    if (!sha3_256_bytes(hpk, pk, kMlkemKemPublicKeyBytes, err)) {
        return false;
    }

    // Extend secret key from:
    //   sk_cpapke
    // to:
    //   sk_cpapke || pk || H(pk) || z
    for (std::size_t i = 0; i < kMlkemKemPublicKeyBytes; ++i) {
        sk[kPkOffset + i] = pk[i];
    }
    for (std::size_t i = 0; i < 32; ++i) {
        sk[kHpkOffset + i] = hpk[i];
        sk[kZOffset + i] = z[i];
    }

    return true;
}

bool mlkem_kem_encaps_derand(
    std::uint8_t ct[kMlkemKemCiphertextBytes],
    std::uint8_t ss[kMlkemKemSharedSecretBytes],
    const std::uint8_t pk[kMlkemKemPublicKeyBytes],
    const std::uint8_t m[kMlkemKemMsgBytes],
    std::string* err) {
    if (ct == nullptr || ss == nullptr || pk == nullptr || m == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::uint8_t hpk[32]{};
    std::uint8_t hct[32]{};
    std::uint8_t kr[64]{};
    std::array<std::uint8_t, 64> g_in{};

    if (!sha3_256_bytes(hpk, pk, kMlkemKemPublicKeyBytes, err)) {
        return false;
    }

    for (std::size_t i = 0; i < 32; ++i) {
        g_in[i] = m[i];
        g_in[32 + i] = hpk[i];
    }

    if (!sha3_512_bytes(kr, g_in.data(), g_in.size(), err)) {
        return false;
    }

    const std::uint8_t* kbar = &kr[0];
    const std::uint8_t* coins = &kr[32];

    if (!mlkem_cpapke_encrypt_derand(ct, m, pk, coins, err)) {
        return false;
    }

    if (!sha3_256_bytes(hct, ct, kMlkemKemCiphertextBytes, err)) {
        return false;
    }

    return derive_shared_secret(ss, kbar, hct, err);
}

bool mlkem_kem_decaps(
    std::uint8_t ss[kMlkemKemSharedSecretBytes],
    const std::uint8_t ct[kMlkemKemCiphertextBytes],
    const std::uint8_t sk[kMlkemKemSecretKeyBytes],
    std::string* err) {
    if (ss == nullptr || ct == nullptr || sk == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    const std::uint8_t* sk_cpapke = &sk[0];
    const std::uint8_t* pk = &sk[kPkOffset];
    const std::uint8_t* hpk = &sk[kHpkOffset];
    const std::uint8_t* z = &sk[kZOffset];

    std::uint8_t m_prime[32]{};
    std::uint8_t ct_cmp[kMlkemKemCiphertextBytes]{};
    std::uint8_t hct[32]{};
    std::uint8_t kr[64]{};
    std::array<std::uint8_t, 64> g_in{};

    if (!mlkem_cpapke_decrypt(m_prime, ct, sk_cpapke, err)) {
        return false;
    }

    for (std::size_t i = 0; i < 32; ++i) {
        g_in[i] = m_prime[i];
        g_in[32 + i] = hpk[i];
    }

    if (!sha3_512_bytes(kr, g_in.data(), g_in.size(), err)) {
        return false;
    }

    const std::uint8_t* kbar_prime = &kr[0];
    const std::uint8_t* coins_prime = &kr[32];

    if (!mlkem_cpapke_encrypt_derand(ct_cmp, m_prime, pk, coins_prime, err)) {
        return false;
    }

    if (!sha3_256_bytes(hct, ct, kMlkemKemCiphertextBytes, err)) {
        return false;
    }

    const std::uint8_t* key_part = bytes_equal(ct, ct_cmp, kMlkemKemCiphertextBytes)
        ? kbar_prime
        : z;

    return derive_shared_secret(ss, key_part, hct, err);
}

} // namespace pqnas::dna_pqcore_learn