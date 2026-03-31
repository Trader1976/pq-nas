#include "share_pq_mlkem_v1.h"

#include <openssl/rand.h>

#include <algorithm>
#include <vector>

extern "C" {
#define MLK_CONFIG_API_PARAMETER_SET 768
#define MLK_CONFIG_API_NAMESPACE_PREFIX pqnas_mlkem768
#define MLK_CONFIG_API_NO_SUPERCOP
#include "mlkem/mlkem_native.h"
}

namespace pqnas {
namespace {

static void wipe_bytes(std::vector<std::uint8_t>* v) {
    if (!v) return;
    std::fill(v->begin(), v->end(), 0);
    v->clear();
    v->shrink_to_fit();
}

static bool random_bytes_local(std::size_t n, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->assign(n, 0);
    if (n == 0) return true;
    return RAND_bytes(reinterpret_cast<unsigned char*>(out->data()),
                      static_cast<int>(out->size())) == 1;
}

} // namespace

bool mlkem768_available_v1() {
    return true;
}

std::string mlkem768_backend_name_v1() {
    return "mlkem-native-c";
}

bool mlkem768_keygen_v1(MlKem768KeypairV1* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    wipe_bytes(&out->public_key);
    wipe_bytes(&out->secret_key);

    std::vector<std::uint8_t> coins(2 * MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        if (err) *err = "random_coins_failed";
        return false;
    }

    out->public_key.assign(MLKEM768_PUBLICKEYBYTES, 0);
    out->secret_key.assign(MLKEM768_SECRETKEYBYTES, 0);

    const int rc = pqnas_mlkem768_keypair_derand(
        reinterpret_cast<uint8_t*>(out->public_key.data()),
        reinterpret_cast<uint8_t*>(out->secret_key.data()),
        reinterpret_cast<const uint8_t*>(coins.data()));

    wipe_bytes(&coins);

    if (rc != 0) {
        wipe_bytes(&out->public_key);
        wipe_bytes(&out->secret_key);
        if (err) *err = "mlkem768_keypair_derand_failed";
        return false;
    }

    return true;
}

bool mlkem768_encapsulate_v1(const std::vector<std::uint8_t>& public_key,
                             MlKem768EncapResultV1* out,
                             std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    wipe_bytes(&out->ciphertext);
    wipe_bytes(&out->shared_secret);

    if (public_key.size() != MLKEM768_PUBLICKEYBYTES) {
        if (err) *err = "mlkem768_bad_public_key_len";
        return false;
    }

    std::vector<std::uint8_t> coins(MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        if (err) *err = "random_coins_failed";
        return false;
    }

    out->ciphertext.assign(MLKEM768_CIPHERTEXTBYTES, 0);
    out->shared_secret.assign(MLKEM_BYTES, 0);

    const int rc = pqnas_mlkem768_enc_derand(
        reinterpret_cast<uint8_t*>(out->ciphertext.data()),
        reinterpret_cast<uint8_t*>(out->shared_secret.data()),
        reinterpret_cast<const uint8_t*>(public_key.data()),
        reinterpret_cast<const uint8_t*>(coins.data()));

    wipe_bytes(&coins);

    if (rc != 0) {
        wipe_bytes(&out->ciphertext);
        wipe_bytes(&out->shared_secret);
        if (err) *err = "mlkem768_enc_derand_failed";
        return false;
    }

    return true;
}

bool mlkem768_decapsulate_v1(const std::vector<std::uint8_t>& secret_key,
                             const std::vector<std::uint8_t>& ciphertext,
                             std::vector<std::uint8_t>* out_shared_secret,
                             std::string* err) {
    if (err) err->clear();
    if (!out_shared_secret) {
        if (err) *err = "output_null";
        return false;
    }

    wipe_bytes(out_shared_secret);

    if (secret_key.size() != MLKEM768_SECRETKEYBYTES) {
        if (err) *err = "mlkem768_bad_secret_key_len";
        return false;
    }

    if (ciphertext.size() != MLKEM768_CIPHERTEXTBYTES) {
        if (err) *err = "mlkem768_bad_ciphertext_len";
        return false;
    }

    out_shared_secret->assign(MLKEM_BYTES, 0);

    const int rc = pqnas_mlkem768_dec(
        reinterpret_cast<uint8_t*>(out_shared_secret->data()),
        reinterpret_cast<const uint8_t*>(ciphertext.data()),
        reinterpret_cast<const uint8_t*>(secret_key.data()));

    if (rc != 0) {
        wipe_bytes(out_shared_secret);
        if (err) *err = "mlkem768_dec_failed";
        return false;
    }

    return true;
}

    bool mlkem768_selftest_v1(std::string* err) {
    if (err) err->clear();

    MlKem768KeypairV1 kp;
    std::string step_err;
    if (!mlkem768_keygen_v1(&kp, &step_err)) {
        if (err) *err = "selftest:keygen:" + step_err;
        return false;
    }

    MlKem768EncapResultV1 enc;
    if (!mlkem768_encapsulate_v1(kp.public_key, &enc, &step_err)) {
        if (err) *err = "selftest:encapsulate:" + step_err;
        return false;
    }

    std::vector<std::uint8_t> dec_ss;
    if (!mlkem768_decapsulate_v1(kp.secret_key, enc.ciphertext, &dec_ss, &step_err)) {
        if (err) *err = "selftest:decapsulate:" + step_err;
        return false;
    }

    if (enc.shared_secret.size() != dec_ss.size() || enc.shared_secret != dec_ss) {
        if (err) *err = "selftest:shared_secret_mismatch";
        return false;
    }

    return true;
}

} // namespace pqnas