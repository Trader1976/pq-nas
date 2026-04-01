#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_indcpa_packed.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] indcpa packed test failed: " << msg << "\n";
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

bool check_case(const std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes>& rho,
                const std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes>& sigma,
                const std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes>& coins,
                const std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes>& coins2,
                const std::array<std::uint8_t, kMlkemIndcpaPackedMsgBytes>& msg) {
    std::string err;

    std::array<std::uint8_t, kMlkemIndcpaPublicKeyBytes> pk{};
    std::array<std::uint8_t, kMlkemIndcpaSecretKeyBytes> sk{};

    std::array<std::uint8_t, kMlkemIndcpaPublicKeyBytes> pk_again{};
    std::array<std::uint8_t, kMlkemIndcpaSecretKeyBytes> sk_again{};

    std::array<std::uint8_t, kMlkemIndcpaCiphertextBytes> ct{};
    std::array<std::uint8_t, kMlkemIndcpaCiphertextBytes> ct_again{};
    std::array<std::uint8_t, kMlkemIndcpaCiphertextBytes> ct2{};

    std::array<std::uint8_t, kMlkemIndcpaPackedMsgBytes> out{};
    std::array<std::uint8_t, kMlkemIndcpaPackedMsgBytes> out2{};

    if (!mlkem_indcpa_keypair_packed_deterministic(
            pk.data(), sk.data(), rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("keypair packed failed");
    }

    if (!mlkem_indcpa_keypair_packed_deterministic(
            pk_again.data(), sk_again.data(), rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("keypair packed repeat failed");
    }

    if (!bytes_equal(pk, pk_again)) return fail("pk determinism mismatch");
    if (!bytes_equal(sk, sk_again)) return fail("sk determinism mismatch");

    // Public key tail must equal rho exactly.
    for (std::size_t i = 0; i < kMlkemIndcpaPackedSeedBytes; ++i) {
        if (pk[kMlkemIndcpaPublicKeyBytes - kMlkemIndcpaPackedSeedBytes + i] != rho[i]) {
            return fail("pk rho tail mismatch");
        }
    }

    if (!mlkem_indcpa_encrypt_packed_deterministic(
            ct.data(), pk.data(), coins.data(), msg.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt packed failed");
    }

    if (!mlkem_indcpa_encrypt_packed_deterministic(
            ct_again.data(), pk.data(), coins.data(), msg.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt packed repeat failed");
    }

    if (!bytes_equal(ct, ct_again)) return fail("ct determinism mismatch");

    if (!mlkem_indcpa_encrypt_packed_deterministic(
            ct2.data(), pk.data(), coins2.data(), msg.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt packed second-coins failed");
    }

    if (!any_diff(ct, ct2)) return fail("different coins did not affect ciphertext");

    if (!mlkem_indcpa_decrypt_packed_deterministic(
            out.data(), sk.data(), ct.data(), &err)) {
        std::cerr << err << "\n";
        return fail("decrypt packed failed");
    }

    if (!mlkem_indcpa_decrypt_packed_deterministic(
            out2.data(), sk.data(), ct2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("decrypt packed second ciphertext failed");
    }

    if (!bytes_equal(msg, out)) return fail("decrypt roundtrip mismatch");
    if (!bytes_equal(msg, out2)) return fail("decrypt second ciphertext mismatch");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemIndcpaPublicKeyBytes == 1184, "test assumes pk bytes = 1184");
    static_assert(kMlkemIndcpaSecretKeyBytes == 1152, "test assumes sk bytes = 1152");
    static_assert(kMlkemIndcpaCiphertextBytes == 1088, "test assumes ct bytes = 1088");
    static_assert(kMlkemIndcpaPackedMsgBytes == 32, "test assumes msg bytes = 32");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> coins{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> coins2{};
        std::array<std::uint8_t, kMlkemIndcpaPackedMsgBytes> msg{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
            sigma[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
            coins[i] = static_cast<std::uint8_t>((53u * i + 7u) & 0xFFu);
            coins2[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }

        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((17u * i + 3u) & 0xFFu);
        }

        if (!check_case(rho, sigma, coins, coins2, msg)) return 1;
    }

    // Case 2
    {
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> coins{};
        std::array<std::uint8_t, kMlkemIndcpaPackedSeedBytes> coins2{};
        std::array<std::uint8_t, kMlkemIndcpaPackedMsgBytes> msg{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((19u * i + 201u) & 0xFFu);
            sigma[i] = static_cast<std::uint8_t>((71u * i + 9u) & 0xFFu);
            coins[i] = static_cast<std::uint8_t>((11u * i + 149u) & 0xFFu);
            coins2[i] = static_cast<std::uint8_t>((97u * i + 5u) & 0xFFu);
        }

        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((i & 1u) ? 0xAAu : 0x55u);
        }

        if (!check_case(rho, sigma, coins, coins2, msg)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] indcpa packed ok"
        << " pk=" << kMlkemIndcpaPublicKeyBytes
        << " sk=" << kMlkemIndcpaSecretKeyBytes
        << " ct=" << kMlkemIndcpaCiphertextBytes
        << "\n";

    return 0;
}