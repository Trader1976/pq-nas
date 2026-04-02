#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_kem.h"
#include "dna_mlkem_kem_random.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] kem random test failed: " << msg << "\n";
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

bool check_keypair_roundtrip() {
    std::string err;

    std::array<std::uint8_t, kMlkemKemRandomPublicKeyBytes> pk1{};
    std::array<std::uint8_t, kMlkemKemRandomSecretKeyBytes> sk1{};
    std::array<std::uint8_t, kMlkemKemRandomPublicKeyBytes> pk2{};
    std::array<std::uint8_t, kMlkemKemRandomSecretKeyBytes> sk2{};

    if (!mlkem_kem_keypair(pk1.data(), sk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random keypair 1 failed");
    }

    if (!mlkem_kem_keypair(pk2.data(), sk2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random keypair 2 failed");
    }

    // Practical sanity check: two independently random keypairs should differ.
    if (!any_diff(pk1, pk2)) {
        return fail("two random public keys were identical");
    }

    if (!any_diff(sk1, sk2)) {
        return fail("two random secret keys were identical");
    }

    std::array<std::uint8_t, kMlkemKemRandomCiphertextBytes> ct1{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss1{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss1_dec{};

    if (!mlkem_kem_encaps(ct1.data(), ss1.data(), pk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random encaps 1 failed");
    }

    if (!mlkem_kem_decaps_random_api(ss1_dec.data(), ct1.data(), sk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random decaps 1 failed");
    }

    if (!bytes_equal(ss1, ss1_dec)) {
        return fail("roundtrip mismatch for keypair 1");
    }

    std::array<std::uint8_t, kMlkemKemRandomCiphertextBytes> ct2{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss2{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss2_dec{};

    if (!mlkem_kem_encaps(ct2.data(), ss2.data(), pk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random encaps 2 failed");
    }

    if (!mlkem_kem_decaps_random_api(ss2_dec.data(), ct2.data(), sk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random decaps 2 failed");
    }

    if (!bytes_equal(ss2, ss2_dec)) {
        return fail("roundtrip mismatch for second encaps");
    }

    // Practical sanity check: two independently random encapsulations to the
    // same public key should differ.
    if (!any_diff(ct1, ct2)) {
        return fail("two random ciphertexts were identical");
    }

    if (!any_diff(ss1, ss2)) {
        return fail("two random shared secrets were identical");
    }

    // Second keypair should also work.
    std::array<std::uint8_t, kMlkemKemRandomCiphertextBytes> ct3{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss3{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss3_dec{};

    if (!mlkem_kem_encaps(ct3.data(), ss3.data(), pk2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random encaps 3 failed");
    }

    if (!mlkem_kem_decaps_random_api(ss3_dec.data(), ct3.data(), sk2.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random decaps 3 failed");
    }

    if (!bytes_equal(ss3, ss3_dec)) {
        return fail("roundtrip mismatch for keypair 2");
    }

    // Tamper path should produce a different shared secret with overwhelming probability.
    std::array<std::uint8_t, kMlkemKemRandomCiphertextBytes> ct_tampered = ct1;
    ct_tampered[0] ^= 0x01u;

    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss_tampered{};

    if (!mlkem_kem_decaps_random_api(ss_tampered.data(), ct_tampered.data(), sk1.data(), &err)) {
        std::cerr << err << "\n";
        return fail("random decaps tampered failed");
    }

    if (!any_diff(ss1, ss_tampered)) {
        return fail("tampered ciphertext did not affect shared secret");
    }

    return true;
}

bool check_interop_with_deterministic_decaps() {
    std::string err;

    std::array<std::uint8_t, kMlkemKemRandomPublicKeyBytes> pk{};
    std::array<std::uint8_t, kMlkemKemRandomSecretKeyBytes> sk{};
    std::array<std::uint8_t, kMlkemKemRandomCiphertextBytes> ct{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss_random{};
    std::array<std::uint8_t, kMlkemKemRandomSharedSecretBytes> ss_det{};

    if (!mlkem_kem_keypair(pk.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("interop keypair failed");
    }

    if (!mlkem_kem_encaps(ct.data(), ss_random.data(), pk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("interop encaps failed");
    }

    if (!mlkem_kem_decaps(ss_det.data(), ct.data(), sk.data(), &err)) {
        std::cerr << err << "\n";
        return fail("interop deterministic decaps failed");
    }

    if (!bytes_equal(ss_random, ss_det)) {
        return fail("random encaps and deterministic decaps did not agree");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemKemRandomPublicKeyBytes == 1184, "test assumes pk bytes = 1184");
    static_assert(kMlkemKemRandomSecretKeyBytes == 2400, "test assumes sk bytes = 2400");
    static_assert(kMlkemKemRandomCiphertextBytes == 1088, "test assumes ct bytes = 1088");
    static_assert(kMlkemKemRandomSharedSecretBytes == 32, "test assumes ss bytes = 32");

    if (!check_keypair_roundtrip()) return 1;
    if (!check_interop_with_deterministic_decaps()) return 1;

    std::cout
        << "[dna-pqcore-learn] kem random ok"
        << " pk=" << kMlkemKemRandomPublicKeyBytes
        << " sk=" << kMlkemKemRandomSecretKeyBytes
        << " ct=" << kMlkemKemRandomCiphertextBytes
        << " ss=" << kMlkemKemRandomSharedSecretBytes
        << "\n";

    return 0;
}