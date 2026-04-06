#include "internal/dna_mlkem768_provider.h"

#include <openssl/rand.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dna_mlkem_kem.h"

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

bool mlkem768_dna_provider_available() {
    // Keep false until encapsulate and decapsulate are also implemented.
    return false;
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
    const std::vector<std::uint8_t>&,
    MlKem768EncapResult* out) {
    mlkem768_wipe_encap_result(out);
    return out ? MlKem768Status::provider_failed : MlKem768Status::output_null;
}

MlKem768Status mlkem768_dna_provider_decapsulate(
    const std::vector<std::uint8_t>&,
    const std::vector<std::uint8_t>&,
    std::vector<std::uint8_t>* out_shared_secret) {
    mlkem768_wipe_shared_secret(out_shared_secret);
    return out_shared_secret ? MlKem768Status::provider_failed
                             : MlKem768Status::output_null;
}

} // namespace dnanexus::pq::internal