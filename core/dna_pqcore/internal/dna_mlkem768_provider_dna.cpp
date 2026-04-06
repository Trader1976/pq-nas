#include "internal/dna_mlkem768_provider.h"

#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dna_mlkem_kem.h"

extern "C" {

// Native backend helper used only for provider-local contract validation.
//
// enc_derand performs the FIPS 203 modulus/public-key check and returns non-zero
// on invalid public keys.
//
// dec performs the secret-key hash check and returns non-zero on invalid secret
// keys, while still returning success for correctly-sized tampered ciphertexts.
int dnanexus_mlkem768_enc_derand(std::uint8_t* ct,
                                 std::uint8_t* ss,
                                 const std::uint8_t* pk,
                                 const std::uint8_t* coins);

int dnanexus_mlkem768_dec(std::uint8_t* ss,
                          const std::uint8_t* ct,
                          const std::uint8_t* sk);

} // extern "C"

namespace dnanexus::pq::internal {
namespace {

static bool random_bytes_local(std::size_t n, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->assign(n, 0);
    if (n == 0) return true;
    return RAND_bytes(reinterpret_cast<unsigned char*>(out->data()),
                      static_cast<int>(out->size())) == 1;
}

static bool dna_public_key_passes_modulus_check(
    const std::vector<std::uint8_t>& public_key) {
    if (public_key.size() != kMlKem768PublicKeyBytes) {
        return false;
    }

    std::array<std::uint8_t, kMlKem768CiphertextBytes> ct{};
    std::array<std::uint8_t, kMlKem768SharedSecretBytes> ss{};
    std::array<std::uint8_t, kMlKem768SharedSecretBytes> m{};

    return dnanexus_mlkem768_enc_derand(
               ct.data(),
               ss.data(),
               public_key.data(),
               m.data()) == 0;
}

static bool dna_secret_key_passes_hash_check(
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext) {
    if (secret_key.size() != kMlKem768SecretKeyBytes) {
        return false;
    }
    if (ciphertext.size() != kMlKem768CiphertextBytes) {
        return false;
    }

    std::array<std::uint8_t, kMlKem768SharedSecretBytes> ss{};

    return dnanexus_mlkem768_dec(
               ss.data(),
               ciphertext.data(),
               secret_key.data()) == 0;
}

} // namespace

bool mlkem768_dna_provider_available() {
    return true;
}

std::string mlkem768_dna_provider_name() {
    return "dna-internal-wip";
}

MlKem768Status mlkem768_dna_provider_keygen(MlKem768Keypair* out) {
    if (!out) {
        return MlKem768Status::output_null;
    }

    mlkem768_wipe_keypair(out);

    std::vector<std::uint8_t> coins(2 * kMlKem768SharedSecretBytes, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        mlkem768_wipe_shared_secret(&coins);
        return MlKem768Status::random_failed;
    }

    out->public_key.assign(kMlKem768PublicKeyBytes, 0);
    out->secret_key.assign(kMlKem768SecretKeyBytes, 0);

    std::string learn_err;
    const bool ok = pqnas::dna_pqcore_learn::mlkem_kem_keypair_derand(
        reinterpret_cast<std::uint8_t*>(out->public_key.data()),
        reinterpret_cast<std::uint8_t*>(out->secret_key.data()),
        reinterpret_cast<const std::uint8_t*>(coins.data()),
        reinterpret_cast<const std::uint8_t*>(coins.data() + kMlKem768SharedSecretBytes),
        &learn_err);

    mlkem768_wipe_shared_secret(&coins);

    if (!ok) {
        mlkem768_wipe_keypair(out);
        return MlKem768Status::provider_failed;
    }

    if (out->public_key.size() != kMlKem768PublicKeyBytes ||
        out->secret_key.size() != kMlKem768SecretKeyBytes) {
        mlkem768_wipe_keypair(out);
        return MlKem768Status::provider_failed;
    }

    return MlKem768Status::ok;
}

MlKem768Status mlkem768_dna_provider_encapsulate(
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out) {
    if (!out) {
        return MlKem768Status::output_null;
    }

    mlkem768_wipe_encap_result(out);

    if (public_key.size() != kMlKem768PublicKeyBytes) {
        return MlKem768Status::bad_public_key_len;
    }

    if (!dna_public_key_passes_modulus_check(public_key)) {
        return MlKem768Status::invalid_public_key;
    }

    std::vector<std::uint8_t> m(kMlKem768SharedSecretBytes, 0);
    if (!random_bytes_local(m.size(), &m)) {
        mlkem768_wipe_shared_secret(&m);
        return MlKem768Status::random_failed;
    }

    out->ciphertext.assign(kMlKem768CiphertextBytes, 0);
    out->shared_secret.assign(kMlKem768SharedSecretBytes, 0);

    std::string learn_err;
    const bool ok = pqnas::dna_pqcore_learn::mlkem_kem_encaps_derand(
        reinterpret_cast<std::uint8_t*>(out->ciphertext.data()),
        reinterpret_cast<std::uint8_t*>(out->shared_secret.data()),
        reinterpret_cast<const std::uint8_t*>(public_key.data()),
        reinterpret_cast<const std::uint8_t*>(m.data()),
        &learn_err);

    mlkem768_wipe_shared_secret(&m);

    if (!ok) {
        mlkem768_wipe_encap_result(out);
        return MlKem768Status::provider_failed;
    }

    if (out->ciphertext.size() != kMlKem768CiphertextBytes ||
        out->shared_secret.size() != kMlKem768SharedSecretBytes) {
        mlkem768_wipe_encap_result(out);
        return MlKem768Status::provider_failed;
    }

    return MlKem768Status::ok;
}

MlKem768Status mlkem768_dna_provider_decapsulate(
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>* out_shared_secret) {
    if (!out_shared_secret) {
        return MlKem768Status::output_null;
    }

    mlkem768_wipe_shared_secret(out_shared_secret);

    if (secret_key.size() != kMlKem768SecretKeyBytes) {
        return MlKem768Status::bad_secret_key_len;
    }

    if (ciphertext.size() != kMlKem768CiphertextBytes) {
        return MlKem768Status::bad_ciphertext_len;
    }

    if (!dna_secret_key_passes_hash_check(secret_key, ciphertext)) {
        return MlKem768Status::invalid_secret_key;
    }

    out_shared_secret->assign(kMlKem768SharedSecretBytes, 0);

    std::string learn_err;
    const bool ok = pqnas::dna_pqcore_learn::mlkem_kem_decaps(
        reinterpret_cast<std::uint8_t*>(out_shared_secret->data()),
        reinterpret_cast<const std::uint8_t*>(ciphertext.data()),
        reinterpret_cast<const std::uint8_t*>(secret_key.data()),
        &learn_err);

    if (!ok) {
        mlkem768_wipe_shared_secret(out_shared_secret);
        return MlKem768Status::provider_failed;
    }

    if (out_shared_secret->size() != kMlKem768SharedSecretBytes) {
        mlkem768_wipe_shared_secret(out_shared_secret);
        return MlKem768Status::provider_failed;
    }

    return MlKem768Status::ok;
}

} // namespace dnanexus::pq::internal