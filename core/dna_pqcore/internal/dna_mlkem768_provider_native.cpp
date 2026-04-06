#include "dna_mlkem_native_config_768.h"
#include "internal/dna_mlkem768_provider.h"

#include <openssl/rand.h>

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_API_NAMESPACE_PREFIX MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_API_NO_SUPERCOP
#include "mlkem/mlkem_native.h"
#undef MLK_CONFIG_API_NO_SUPERCOP
#undef MLK_CONFIG_API_NAMESPACE_PREFIX
#undef MLK_CONFIG_API_PARAMETER_SET
}

namespace dnanexus::pq::internal {
namespace {

static bool random_bytes_local(std::size_t n, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->assign(n, 0);
    if (n == 0) return true;
    return RAND_bytes(reinterpret_cast<unsigned char*>(out->data()),
                      static_cast<int>(out->size())) == 1;
}

} // namespace

    MlKem768ProviderId mlkem768_active_provider_id() {
    return MlKem768ProviderId::dna;
}

bool mlkem768_provider_available() {
    return true;
}

    std::string mlkem768_provider_name() {
    return "mlkem-native-c";
}

MlKem768Status mlkem768_provider_keygen(MlKem768Keypair* out) {
    if (!out) {
        return MlKem768Status::output_null;
    }

    mlkem768_wipe_keypair(out);

    std::vector<std::uint8_t> coins(2 * MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        mlkem768_wipe_shared_secret(&coins);
        return MlKem768Status::random_failed;
    }

    out->public_key.assign(kMlKem768PublicKeyBytes, 0);
    out->secret_key.assign(kMlKem768SecretKeyBytes, 0);

    const int rc = dnanexus_mlkem768_keypair_derand(
        reinterpret_cast<uint8_t*>(out->public_key.data()),
        reinterpret_cast<uint8_t*>(out->secret_key.data()),
        reinterpret_cast<const uint8_t*>(coins.data()));

    mlkem768_wipe_shared_secret(&coins);

    if (rc != 0) {
        mlkem768_wipe_keypair(out);
        return MlKem768Status::provider_failed;
    }

    return MlKem768Status::ok;
}

MlKem768Status mlkem768_provider_encapsulate(
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out) {
    if (!out) {
        return MlKem768Status::output_null;
    }

    mlkem768_wipe_encap_result(out);

    if (public_key.size() != kMlKem768PublicKeyBytes) {
        return MlKem768Status::bad_public_key_len;
    }

    std::vector<std::uint8_t> coins(MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        mlkem768_wipe_shared_secret(&coins);
        return MlKem768Status::random_failed;
    }

    out->ciphertext.assign(kMlKem768CiphertextBytes, 0);
    out->shared_secret.assign(kMlKem768SharedSecretBytes, 0);

    const int rc = dnanexus_mlkem768_enc_derand(
        reinterpret_cast<uint8_t*>(out->ciphertext.data()),
        reinterpret_cast<uint8_t*>(out->shared_secret.data()),
        reinterpret_cast<const uint8_t*>(public_key.data()),
        reinterpret_cast<const uint8_t*>(coins.data()));

    mlkem768_wipe_shared_secret(&coins);

    if (rc != 0) {
        mlkem768_wipe_encap_result(out);
        return MlKem768Status::invalid_public_key;
    }

    return MlKem768Status::ok;
}

MlKem768Status mlkem768_provider_decapsulate(
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

    out_shared_secret->assign(kMlKem768SharedSecretBytes, 0);

    const int rc = dnanexus_mlkem768_dec(
        reinterpret_cast<uint8_t*>(out_shared_secret->data()),
        reinterpret_cast<const uint8_t*>(ciphertext.data()),
        reinterpret_cast<const uint8_t*>(secret_key.data()));

    if (rc != 0) {
        mlkem768_wipe_shared_secret(out_shared_secret);
        return MlKem768Status::invalid_secret_key;
    }

    return MlKem768Status::ok;
}

} // namespace dnanexus::pq::internal