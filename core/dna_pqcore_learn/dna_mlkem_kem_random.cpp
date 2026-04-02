#include "dna_mlkem_kem_random.h"

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>

#include <openssl/rand.h>

namespace pqnas::dna_pqcore_learn {
namespace {

bool mlkem_random_bytes(std::uint8_t* out, std::size_t len, std::string* err) {
    if (out == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    if (len > static_cast<std::size_t>(INT_MAX)) {
        if (err) *err = "requested random length too large";
        return false;
    }

    if (RAND_bytes(out, static_cast<int>(len)) != 1) {
        if (err) *err = "RAND_bytes failed";
        return false;
    }

    return true;
}

} // namespace

bool mlkem_kem_keypair(
    std::uint8_t pk[kMlkemKemRandomPublicKeyBytes],
    std::uint8_t sk[kMlkemKemRandomSecretKeyBytes],
    std::string* err) {
    if (pk == nullptr || sk == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::array<std::uint8_t, kMlkemKemSeedBytes> d{};
    std::array<std::uint8_t, kMlkemKemSeedBytes> z{};

    if (!mlkem_random_bytes(d.data(), d.size(), err)) {
        return false;
    }

    if (!mlkem_random_bytes(z.data(), z.size(), err)) {
        return false;
    }

    return mlkem_kem_keypair_derand(pk, sk, d.data(), z.data(), err);
}

bool mlkem_kem_encaps(
    std::uint8_t ct[kMlkemKemRandomCiphertextBytes],
    std::uint8_t ss[kMlkemKemRandomSharedSecretBytes],
    const std::uint8_t pk[kMlkemKemRandomPublicKeyBytes],
    std::string* err) {
    if (ct == nullptr || ss == nullptr || pk == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::array<std::uint8_t, kMlkemKemMsgBytes> m{};

    if (!mlkem_random_bytes(m.data(), m.size(), err)) {
        return false;
    }

    return mlkem_kem_encaps_derand(ct, ss, pk, m.data(), err);
}

bool mlkem_kem_decaps_random_api(
    std::uint8_t ss[kMlkemKemRandomSharedSecretBytes],
    const std::uint8_t ct[kMlkemKemRandomCiphertextBytes],
    const std::uint8_t sk[kMlkemKemRandomSecretKeyBytes],
    std::string* err) {
    return mlkem_kem_decaps(ss, ct, sk, err);
}

} // namespace pqnas::dna_pqcore_learn