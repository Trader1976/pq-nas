#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include <openssl/evp.h>

#include "dna_mlkem_cpapke.h"
#include "dna_mlkem_indcpa_packed.h"
#include "dna_mlkem_kem.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

constexpr std::size_t kSha3_256_Bytes = 32;
constexpr std::size_t kSha3_512_Bytes = 64;
constexpr std::size_t kSkCpapkeBytes = 1152;
constexpr std::size_t kPkOffset = kSkCpapkeBytes;
constexpr std::size_t kHpkOffset = kSkCpapkeBytes + kMlkemKemPublicKeyBytes;
constexpr std::size_t kZOffset = kHpkOffset + 32;

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] kem test failed: " << msg << "\n";
    return false;
}

template <std::size_t N>
bool bytes_equal(const std::array<std::uint8_t, N>& a,
                 const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

template <std::size_t N>
bool any_diff(const std::array<std::uint8_t, N>& a,
              const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return true;
    }
    return false;
}

bool ref_sha3_256(std::uint8_t out[kSha3_256_Bytes],
                  const std::uint8_t* in,
                  std::size_t in_len,
                  std::string* err) {
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

bool ref_sha3_512(std::uint8_t out[kSha3_512_Bytes],
                  const std::uint8_t* in,
                  std::size_t in_len,
                  std::string* err) {
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

bool ref_shake256_32(std::uint8_t out[kMlkemKemSharedSecretBytes],
                     const std::uint8_t* in,
                     std::size_t in_len,
                     std::string* err) {
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

bool ref_kem_encaps(std::uint8_t ct[kMlkemKemCiphertextBytes],
                    std::uint8_t ss[kMlkemKemSharedSecretBytes],
                    const std::uint8_t pk[kMlkemKemPublicKeyBytes],
                    const std::uint8_t m[kMlkemKemMsgBytes],
                    std::string* err) {
    std::uint8_t hpk[32]{};
    std::uint8_t hct[32]{};
    std::uint8_t kr[64]{};
    std::array<std::uint8_t, 64> g_in{};
    std::array<std::uint8_t, 64> kdf_in{};

    if (!ref_sha3_256(hpk, pk, kMlkemKemPublicKeyBytes, err)) return false;

    for (std::size_t i = 0; i < 32; ++i) {
        g_in[i] = m[i];
        g_in[32 + i] = hpk[i];
    }

    if (!ref_sha3_512(kr, g_in.data(), g_in.size(), err)) return false;

    const std::uint8_t* kbar = &kr[0];
    const std::uint8_t* coins = &kr[32];

    if (!mlkem_cpapke_encrypt_derand(ct, m, pk, coins, err)) return false;
    if (!ref_sha3_256(hct, ct, kMlkemKemCiphertextBytes, err)) return false;

    for (std::size_t i = 0; i < 32; ++i) {
        kdf_in[i] = kbar[i];
        kdf_in[32 + i] = hct[i];
    }

    return ref_shake256_32(ss, kdf_in.data(), kdf_in.size(), err);
}

bool ref_kem_decaps(std::uint8_t ss[kMlkemKemSharedSecretBytes],
                    const std::uint8_t ct[kMlkemKemCiphertextBytes],
                    const std::uint8_t sk[kMlkemKemSecretKeyBytes],
                    std::string* err) {
    const std::uint8_t* sk_cpapke = &sk[0];
    const std::uint8_t* pk = &sk[kPkOffset];
    const std::uint8_t* hpk = &sk[kHpkOffset];
    const std::uint8_t* z = &sk[kZOffset];

    std::uint8_t m_prime[32]{};
    std::uint8_t ct_cmp[kMlkemKemCiphertextBytes]{};
    std::uint8_t hct[32]{};
    std::uint8_t kr[64]{};
    std::array<std::uint8_t, 64> g_in{};
    std::array<std::uint8_t, 64> kdf_in{};

    if (!mlkem_cpapke_decrypt(m_prime, ct, sk_cpapke, err)) return false;

    for (std::size_t i = 0; i < 32; ++i) {
        g_in[i] = m_prime[i];
        g_in[32 + i] = hpk[i];
    }

    if (!ref_sha3_512(kr, g_in.data(), g_in.size(), err)) return false;

    const std::uint8_t* kbar_prime = &kr[0];
    const std::uint8_t* coins_prime = &kr[32];

    if (!mlkem_cpapke_encrypt_derand(ct_cmp, m_prime, pk, coins_prime, err)) return false;
    if (!ref_sha3_256(hct, ct, kMlkemKemCiphertextBytes, err)) return false;

    const std::uint8_t* chosen = z;
    bool same = true;
    for (std::size_t i = 0; i < kMlkemKemCiphertextBytes; ++i) {
        if (ct[i] != ct_cmp[i]) {
            same = false;
            break;
        }
    }
    if (same) chosen = kbar_prime;

    for (std::size_t i = 0; i < 32; ++i) {
        kdf_in[i] = chosen[i];
        kdf_in[32 + i] = hct[i];
    }

    return ref_shake256_32(ss, kdf_in.data(), kdf_in.size(), err);
}

bool check_case(const std::array<std::uint8_t, kMlkemKemSeedBytes>& d,
                const std::array<std::uint8_t, kMlkemKemSeedBytes>& z,
                const std::array<std::uint8_t, kMlkemKemMsgBytes>& m,
                const std::array<std::uint8_t, kMlkemKemMsgBytes>& m2) {
    std::string err;

    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk{};
    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_again{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_again{};

    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_ref{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_ref{};

    std::array<std::uint8_t, kMlkemKemSeedBytes> rho{};
    std::array<std::uint8_t, kMlkemKemSeedBytes> sigma{};
    std::array<std::uint8_t, 32> hpk{};

    if (!mlkem_kem_keypair_derand(pk.data(), sk.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem keypair failed");
    }

    if (!mlkem_kem_keypair_derand(pk_again.data(), sk_again.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem keypair repeat failed");
    }

    if (!bytes_equal(pk, pk_again)) return fail("pk determinism mismatch");
    if (!bytes_equal(sk, sk_again)) return fail("sk determinism mismatch");

    if (!mlkem_cpapke_derive_rho_sigma(rho.data(), sigma.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("derive rho sigma failed");
    }

    if (!mlkem_indcpa_keypair_packed_deterministic(
            pk_ref.data(), sk_ref.data(), rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference cpapke keypair failed");
    }

    if (!bytes_equal(pk, pk_ref)) return fail("pk reference mismatch");

    for (std::size_t i = 0; i < kSkCpapkeBytes; ++i) {
        if (sk[i] != sk_ref[i]) return fail("sk_cpapke prefix mismatch");
    }

    for (std::size_t i = 0; i < kMlkemKemPublicKeyBytes; ++i) {
        if (sk[kPkOffset + i] != pk[i]) return fail("sk pk copy mismatch");
    }

    if (!ref_sha3_256(hpk.data(), pk.data(), kMlkemKemPublicKeyBytes, &err)) {
        std::cerr << err << "\n";
        return fail("reference H(pk) failed");
    }

    for (std::size_t i = 0; i < 32; ++i) {
        if (sk[kHpkOffset + i] != hpk[i]) return fail("sk H(pk) mismatch");
        if (sk[kZOffset + i] != z[i]) return fail("sk z mismatch");
    }

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_again{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_again{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct2{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss2{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_ref{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_ref{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_ref{};

    if (!mlkem_kem_encaps_derand(ct.data(), ss.data(), pk.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem encaps failed");
    }

    if (!mlkem_kem_encaps_derand(ct_again.data(), ss_again.data(), pk.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem encaps repeat failed");
    }

    if (!bytes_equal(ct, ct_again)) return fail("ct determinism mismatch");
    if (!bytes_equal(ss, ss_again)) return fail("ss determinism mismatch");

    if (!ref_kem_encaps(ct_ref.data(), ss_ref.data(), pk.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference kem encaps failed");
    }

    if (!bytes_equal(ct, ct_ref)) return fail("ct reference mismatch");
    if (!bytes_equal(ss, ss_ref)) return fail("ss reference mismatch");

    if (!mlkem_kem_encaps_derand(ct2.data(), ss2.data(), pk.data(), m2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem encaps second message failed");
    }

    if (!any_diff(ct, ct2)) return fail("different m did not affect ciphertext");
    if (!any_diff(ss, ss2)) return fail("different m did not affect shared secret");

    if (!mlkem_kem_decaps(ss_dec.data(), ct.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem decaps failed");
    }

    if (!bytes_equal(ss, ss_dec)) return fail("decaps roundtrip mismatch");

    if (!mlkem_kem_decaps(ss_dec_ref.data(), ct2.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem decaps second ct failed");
    }

    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_ref2{};
    if (!ref_kem_decaps(ss_dec_ref2.data(), ct2.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference kem decaps failed");
    }

    if (!bytes_equal(ss_dec_ref, ss_dec_ref2)) return fail("decaps reference mismatch");

    // Tamper ciphertext and verify decapsulation follows the reference fallback path.
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_tampered = ct;
    ct_tampered[0] ^= 0x01u;

    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_ref{};

    if (!mlkem_kem_decaps(ss_tampered.data(), ct_tampered.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("kem decaps tampered ct failed");
    }

    if (!ref_kem_decaps(ss_tampered_ref.data(), ct_tampered.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference tampered decaps failed");
    }

    if (!bytes_equal(ss_tampered, ss_tampered_ref)) {
        return fail("tampered decaps reference mismatch");
    }

    if (!any_diff(ss, ss_tampered)) {
        return fail("tampered ciphertext did not affect shared secret");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemKemSeedBytes == 32, "test assumes 32-byte seeds");
    static_assert(kMlkemKemMsgBytes == 32, "test assumes 32-byte encaps input");
    static_assert(kMlkemKemPublicKeyBytes == 1184, "test assumes pk bytes = 1184");
    static_assert(kMlkemKemSecretKeyBytes == 2400, "test assumes sk bytes = 2400");
    static_assert(kMlkemKemCiphertextBytes == 1088, "test assumes ct bytes = 1088");
    static_assert(kMlkemKemSharedSecretBytes == 32, "test assumes ss bytes = 32");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemKemSeedBytes> d{};
        std::array<std::uint8_t, kMlkemKemSeedBytes> z{};
        std::array<std::uint8_t, kMlkemKemMsgBytes> m{};
        std::array<std::uint8_t, kMlkemKemMsgBytes> m2{};

        for (std::size_t i = 0; i < d.size(); ++i) {
            d[i] = static_cast<std::uint8_t>(i);
            z[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
            m[i] = static_cast<std::uint8_t>((53u * i + 7u) & 0xFFu);
            m2[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }

        if (!check_case(d, z, m, m2)) return 1;
    }

    // Case 2
    {
        std::array<std::uint8_t, kMlkemKemSeedBytes> d{};
        std::array<std::uint8_t, kMlkemKemSeedBytes> z{};
        std::array<std::uint8_t, kMlkemKemMsgBytes> m{};
        std::array<std::uint8_t, kMlkemKemMsgBytes> m2{};

        for (std::size_t i = 0; i < d.size(); ++i) {
            d[i] = static_cast<std::uint8_t>((71u * i + 9u) & 0xFFu);
            z[i] = static_cast<std::uint8_t>((11u * i + 149u) & 0xFFu);
            m[i] = static_cast<std::uint8_t>((97u * i + 5u) & 0xFFu);
            m2[i] = static_cast<std::uint8_t>((19u * i + 201u) & 0xFFu);
        }

        if (!check_case(d, z, m, m2)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] kem ok"
        << " pk=" << kMlkemKemPublicKeyBytes
        << " sk=" << kMlkemKemSecretKeyBytes
        << " ct=" << kMlkemKemCiphertextBytes
        << " ss=" << kMlkemKemSharedSecretBytes
        << "\n";

    return 0;
}