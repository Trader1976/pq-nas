#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include <openssl/evp.h>

#include "dna_mlkem_cpapke.h"
#include "dna_mlkem_indcpa_packed.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

constexpr std::size_t kSha3_512_Bytes = 64;

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] cpapke test failed: " << msg << "\n";
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

bool check_case(const std::array<std::uint8_t, kMlkemCpapkeSeedBytes>& d,
                const std::array<std::uint8_t, kMlkemCpapkeSeedBytes>& coins,
                const std::array<std::uint8_t, kMlkemCpapkeSeedBytes>& coins2,
                const std::array<std::uint8_t, kMlkemCpapkeMsgBytes>& msg) {
    std::string err;

    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> rho{};
    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> sigma{};
    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> rho_again{};
    std::array<std::uint8_t, kMlkemCpapkeSeedBytes> sigma_again{};

    std::array<std::uint8_t, kSha3_512_Bytes> ref_hash{};

    if (!mlkem_cpapke_derive_rho_sigma(rho.data(), sigma.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("derive_rho_sigma failed");
    }

    if (!mlkem_cpapke_derive_rho_sigma(rho_again.data(), sigma_again.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("derive_rho_sigma repeat failed");
    }

    if (!bytes_equal(rho, rho_again)) return fail("rho determinism mismatch");
    if (!bytes_equal(sigma, sigma_again)) return fail("sigma determinism mismatch");

    std::array<std::uint8_t, kMlkemCpapkeSeedBytes + 1> g_in{};
    for (std::size_t i = 0; i < kMlkemCpapkeSeedBytes; ++i) {
        g_in[i] = d[i];
    }
    g_in[kMlkemCpapkeSeedBytes] = 3;

    if (!ref_sha3_512(ref_hash.data(), g_in.data(), g_in.size(), &err)) {
        std::cerr << err << "\n";
        return fail("reference sha3_512 failed");
    }
    for (std::size_t i = 0; i < kMlkemCpapkeSeedBytes; ++i) {
        if (rho[i] != ref_hash[i]) return fail("rho split mismatch");
        if (sigma[i] != ref_hash[kMlkemCpapkeSeedBytes + i]) return fail("sigma split mismatch");
    }

    std::array<std::uint8_t, kMlkemCpapkePublicKeyBytes> pk{};
    std::array<std::uint8_t, kMlkemCpapkeSecretKeyBytes> sk{};
    std::array<std::uint8_t, kMlkemCpapkePublicKeyBytes> pk_again{};
    std::array<std::uint8_t, kMlkemCpapkeSecretKeyBytes> sk_again{};

    std::array<std::uint8_t, kMlkemCpapkePublicKeyBytes> pk_ref{};
    std::array<std::uint8_t, kMlkemCpapkeSecretKeyBytes> sk_ref{};

    if (!mlkem_cpapke_keypair_derand(pk.data(), sk.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke keypair failed");
    }

    if (!mlkem_cpapke_keypair_derand(pk_again.data(), sk_again.data(), d.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke keypair repeat failed");
    }

    if (!bytes_equal(pk, pk_again)) return fail("pk determinism mismatch");
    if (!bytes_equal(sk, sk_again)) return fail("sk determinism mismatch");

    if (!mlkem_indcpa_keypair_packed_deterministic(
            pk_ref.data(), sk_ref.data(), rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference packed keypair failed");
    }

    if (!bytes_equal(pk, pk_ref)) return fail("pk reference mismatch");
    if (!bytes_equal(sk, sk_ref)) return fail("sk reference mismatch");

    std::array<std::uint8_t, kMlkemCpapkeCiphertextBytes> ct{};
    std::array<std::uint8_t, kMlkemCpapkeCiphertextBytes> ct_again{};
    std::array<std::uint8_t, kMlkemCpapkeCiphertextBytes> ct2{};
    std::array<std::uint8_t, kMlkemCpapkeCiphertextBytes> ct_ref{};

    if (!mlkem_cpapke_encrypt_derand(ct.data(), msg.data(), pk.data(), coins.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke encrypt failed");
    }

    if (!mlkem_cpapke_encrypt_derand(ct_again.data(), msg.data(), pk.data(), coins.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke encrypt repeat failed");
    }

    if (!bytes_equal(ct, ct_again)) return fail("ciphertext determinism mismatch");

    if (!mlkem_indcpa_encrypt_packed_deterministic(
            ct_ref.data(), pk.data(), coins.data(), msg.data(), &err)) {
        std::cerr << err << "\n";
        return fail("reference packed encrypt failed");
    }

    if (!bytes_equal(ct, ct_ref)) return fail("ciphertext reference mismatch");

    if (!mlkem_cpapke_encrypt_derand(ct2.data(), msg.data(), pk.data(), coins2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke encrypt second-coins failed");
    }

    if (!any_diff(ct, ct2)) return fail("different coins did not affect ciphertext");

    std::array<std::uint8_t, kMlkemCpapkeMsgBytes> out{};
    std::array<std::uint8_t, kMlkemCpapkeMsgBytes> out2{};

    if (!mlkem_cpapke_decrypt(out.data(), ct.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke decrypt failed");
    }

    if (!mlkem_cpapke_decrypt(out2.data(), ct2.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("cpapke decrypt second ciphertext failed");
    }

    if (!bytes_equal(msg, out)) return fail("decrypt roundtrip mismatch");
    if (!bytes_equal(msg, out2)) return fail("decrypt second ciphertext mismatch");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemCpapkeSeedBytes == 32, "test assumes 32-byte seed");
    static_assert(kMlkemCpapkeMsgBytes == 32, "test assumes 32-byte message");
    static_assert(kMlkemCpapkePublicKeyBytes == 1184, "test assumes pk bytes = 1184");
    static_assert(kMlkemCpapkeSecretKeyBytes == 1152, "test assumes sk bytes = 1152");
    static_assert(kMlkemCpapkeCiphertextBytes == 1088, "test assumes ct bytes = 1088");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> d{};
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> coins{};
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> coins2{};
        std::array<std::uint8_t, kMlkemCpapkeMsgBytes> msg{};

        for (std::size_t i = 0; i < d.size(); ++i) {
            d[i] = static_cast<std::uint8_t>(i);
            coins[i] = static_cast<std::uint8_t>((53u * i + 7u) & 0xFFu);
            coins2[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }

        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((17u * i + 3u) & 0xFFu);
        }

        if (!check_case(d, coins, coins2, msg)) return 1;
    }

    // Case 2
    {
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> d{};
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> coins{};
        std::array<std::uint8_t, kMlkemCpapkeSeedBytes> coins2{};
        std::array<std::uint8_t, kMlkemCpapkeMsgBytes> msg{};

        for (std::size_t i = 0; i < d.size(); ++i) {
            d[i] = static_cast<std::uint8_t>((71u * i + 9u) & 0xFFu);
            coins[i] = static_cast<std::uint8_t>((11u * i + 149u) & 0xFFu);
            coins2[i] = static_cast<std::uint8_t>((97u * i + 5u) & 0xFFu);
        }

        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((i & 1u) ? 0xAAu : 0x55u);
        }

        if (!check_case(d, coins, coins2, msg)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] cpapke ok"
        << " pk=" << kMlkemCpapkePublicKeyBytes
        << " sk=" << kMlkemCpapkeSecretKeyBytes
        << " ct=" << kMlkemCpapkeCiphertextBytes
        << "\n";

    return 0;
}