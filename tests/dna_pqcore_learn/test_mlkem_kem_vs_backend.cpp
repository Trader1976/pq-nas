#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_backend_oracle.h"
#include "dna_mlkem_cpapke.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"
#include "dna_mlkem_kem.h"
#include "dna_mlkem_field.h"
#include <openssl/evp.h>

#include "dna_mlkem_field.h"

using namespace pqnas::dna_pqcore_learn;

namespace {
    constexpr std::size_t kSha3_256_Bytes = 32;
    constexpr std::size_t kSha3_512_Bytes = 64;

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
constexpr std::size_t kPolyBytes = 384;
constexpr std::size_t kPolyVecBytes = 1152;
constexpr std::size_t kSkCpapkeBytes = 1152;
constexpr std::size_t kPkRhoOffset = 1152;

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] kem-vs-backend test failed: " << msg << "\n";
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

    bool poly_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (mlkem_canonicalize_q(a[i]) != mlkem_canonicalize_q(b[i])) {
            return false;
        }
    }
    return true;
}

void unpack_poly12(std::int16_t coeffs[kMlkemKemCiphertextBytes / 4],
                   const std::uint8_t in[kPolyBytes]) {
    for (std::size_t i = 0; i < 128; ++i) {
        const std::uint16_t t0 =
            static_cast<std::uint16_t>(in[3 * i + 0]) |
            (static_cast<std::uint16_t>(in[3 * i + 1] & 0x0Fu) << 8);

        const std::uint16_t t1 =
            (static_cast<std::uint16_t>(in[3 * i + 1]) >> 4) |
            (static_cast<std::uint16_t>(in[3 * i + 2]) << 4);

        coeffs[2 * i + 0] = static_cast<std::int16_t>(t0);
        coeffs[2 * i + 1] = static_cast<std::int16_t>(t1);
    }
}

void unpack_polyvec12(std::int16_t vec[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
                      const std::uint8_t in[kPolyVecBytes]) {
    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        unpack_poly12(vec[j], &in[j * kPolyBytes]);
    }
}

bool compare_polyvec(const std::int16_t a[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
                     const std::int16_t b[kMlkemKeygenSkelK][kMlkemKeygenSkelN]) {
    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        if (!poly_equal(a[j], b[j], kMlkemKeygenSkelN)) return false;
    }
    return true;
}

bool check_case(const std::array<std::uint8_t, kMlkemKemSeedBytes>& d,
                const std::array<std::uint8_t, kMlkemKemSeedBytes>& z,
                const std::array<std::uint8_t, kMlkemKemMsgBytes>& m,
                const std::array<std::uint8_t, kMlkemKemMsgBytes>& m2) {
    std::string err;

    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_learn{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_learn{};
    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_oracle{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_oracle{};

    if (!mlkem_kem_keypair_derand(pk_learn.data(), sk_learn.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn keypair_derand failed");
    }

    if (!mlkem_oracle_keypair_derand(pk_oracle.data(), sk_oracle.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail("oracle keypair_derand failed");
    }

    // First isolate seed derivation by checking the rho tail in the backend pk.
    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> rho{};
    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> sigma{};

    if (!mlkem_cpapke_derive_rho_sigma(rho.data(), sigma.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("derive_rho_sigma failed");
    }

    for (std::size_t i = 0; i < kMlkemCpapkeSeedBytes; ++i) {
        if (pk_oracle[kPkRhoOffset + i] != rho[i]) {
            return fail("rho tail mismatch (seed derivation mismatch)");
        }
    }

    // Decode packed CPA-PKE parts from both learn and backend keys.
    std::int16_t s_hat_learn_dec[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat_learn_dec[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t s_hat_oracle_dec[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat_oracle_dec[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    unpack_polyvec12(s_hat_learn_dec, sk_learn.data());
    unpack_polyvec12(t_hat_learn_dec, pk_learn.data());
    unpack_polyvec12(s_hat_oracle_dec, sk_oracle.data());
    unpack_polyvec12(t_hat_oracle_dec, pk_oracle.data());

    // Compute the direct learn skeleton outputs from derived rho,sigma.
    std::int16_t s_hat_ref[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat_dummy[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat_ref[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat_ref, e_hat_dummy, t_hat_ref, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn keygen skeleton failed");
    }

    if (!compare_polyvec(s_hat_learn_dec, s_hat_ref)) {
        return fail("learn packed sk does not match learn keygen skeleton");
    }

    if (!compare_polyvec(t_hat_learn_dec, t_hat_ref)) {
        return fail("learn packed pk does not match learn keygen skeleton");
    }

    if (!compare_polyvec(s_hat_oracle_dec, s_hat_ref)) {
        return fail("s_hat mismatch (noise/NTT path differs from backend)");
    }

    if (!compare_polyvec(t_hat_oracle_dec, t_hat_ref)) {
        return fail("t_hat mismatch (matrix/matvec/tomont path differs from backend)");
    }

    // If decoded core objects match, then raw packed bytes should match too.
    if (!bytes_equal(pk_learn, pk_oracle)) return fail("public key byte mismatch after decoded match");
    if (!bytes_equal(sk_learn, sk_oracle)) return fail("secret key byte mismatch after decoded match");

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_learn{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_oracle{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_oracle{};

    if (!mlkem_kem_encaps_derand(ct_learn.data(), ss_learn.data(), pk_learn.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn encaps_derand failed");
    }

    if (!mlkem_oracle_encaps_derand(ct_oracle.data(), ss_oracle.data(), pk_oracle.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("oracle encaps_derand failed");
    }

    if (!bytes_equal(ct_learn, ct_oracle)) return fail("ciphertext mismatch");

    std::array<std::uint8_t, kSha3_256_Bytes> hpk{};
    std::array<std::uint8_t, kSha3_512_Bytes> kr{};
    std::array<std::uint8_t, 64> g_in{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_expected{};

    if (!ref_sha3_256(hpk.data(), pk_learn.data(), kMlkemKemPublicKeyBytes, &err)) {
        std::cerr << err << "\n";
        return fail("reference H(pk) failed");
    }

    for (std::size_t i = 0; i < 32; ++i) {
        g_in[i] = m[i];
        g_in[32 + i] = hpk[i];
    }

    if (!ref_sha3_512(kr.data(), g_in.data(), g_in.size(), &err)) {
        std::cerr << err << "\n";
        return fail("reference G(m||H(pk)) failed");
    }

    for (std::size_t i = 0; i < 32; ++i) {
        ss_expected[i] = kr[i];
    }

    if (!bytes_equal(ss_learn, ss_expected)) {
        return fail("learn encaps ss != direct kr[0..31]");
    }

    if (!bytes_equal(ss_oracle, ss_expected)) {
        return fail("oracle encaps ss != direct kr[0..31]");
    }

    if (!bytes_equal(ss_learn, ss_oracle)) return fail("shared secret mismatch");

    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_oracle{};

    if (!mlkem_kem_decaps(ss_dec_learn.data(), ct_learn.data(), sk_learn.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn decaps failed");
    }

    if (!mlkem_oracle_decaps(ss_dec_oracle.data(), ct_oracle.data(), sk_oracle.data(), &err)) {
        std::cerr << err << "\n";
        return fail("oracle decaps failed");
    }

    if (!bytes_equal(ss_dec_learn, ss_learn)) return fail("learn decaps roundtrip mismatch");
    if (!bytes_equal(ss_dec_oracle, ss_oracle)) return fail("oracle decaps roundtrip mismatch");
    if (!bytes_equal(ss_dec_learn, ss_dec_oracle)) return fail("decaps shared secret mismatch");

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct2_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss2_learn{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct2_oracle{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss2_oracle{};

    if (!mlkem_kem_encaps_derand(ct2_learn.data(), ss2_learn.data(), pk_learn.data(), m2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn second encaps_derand failed");
    }

    if (!mlkem_oracle_encaps_derand(ct2_oracle.data(), ss2_oracle.data(), pk_oracle.data(), m2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("oracle second encaps_derand failed");
    }

    if (!bytes_equal(ct2_learn, ct2_oracle)) return fail("second ciphertext mismatch");
    if (!bytes_equal(ss2_learn, ss2_oracle)) return fail("second shared secret mismatch");

    if (!any_diff(ct_learn, ct2_learn)) return fail("two deterministic encaps inputs gave same ciphertext");
    if (!any_diff(ss_learn, ss2_learn)) return fail("two deterministic encaps inputs gave same shared secret");

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_tampered{};
    ct_tampered = ct_learn;
    ct_tampered[0] ^= 0x01u;

    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_oracle{};

    if (!mlkem_kem_decaps(ss_tampered_learn.data(), ct_tampered.data(), sk_learn.data(), &err)) {
        std::cerr << err << "\n";
        return fail("learn tampered decaps failed");
    }

    if (!mlkem_oracle_decaps(ss_tampered_oracle.data(), ct_tampered.data(), sk_oracle.data(), &err)) {
        std::cerr << err << "\n";
        return fail("oracle tampered decaps failed");
    }

    if (!bytes_equal(ss_tampered_learn, ss_tampered_oracle)) {
        return fail("tampered decaps mismatch");
    }

    if (!any_diff(ss_learn, ss_tampered_learn)) {
        return fail("tampered ciphertext did not affect shared secret");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemKemPublicKeyBytes == kMlkemOraclePublicKeyBytes,
                  "learn/backend pk size mismatch");
    static_assert(kMlkemKemSecretKeyBytes == kMlkemOracleSecretKeyBytes,
                  "learn/backend sk size mismatch");
    static_assert(kMlkemKemCiphertextBytes == kMlkemOracleCiphertextBytes,
                  "learn/backend ct size mismatch");
    static_assert(kMlkemKemSharedSecretBytes == kMlkemOracleSharedSecretBytes,
                  "learn/backend ss size mismatch");

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
        << "[dna-pqcore-learn] kem vs backend ok"
        << " pk=" << kMlkemKemPublicKeyBytes
        << " sk=" << kMlkemKemSecretKeyBytes
        << " ct=" << kMlkemKemCiphertextBytes
        << " ss=" << kMlkemKemSharedSecretBytes
        << "\n";

    return 0;
}