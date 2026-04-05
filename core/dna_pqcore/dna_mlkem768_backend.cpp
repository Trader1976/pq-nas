#include "dna_mlkem768_backend.h"
#include "dna_mlkem_native_config_768.h"

#include <openssl/crypto.h>
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

namespace dnanexus::pq {
namespace {

// Securely wipe a raw byte buffer.
static void secure_wipe_bytes(void* ptr, std::size_t len) {
    if (!ptr || len == 0) return;
    OPENSSL_cleanse(ptr, len);
}

// Securely wipe and clear a vector holding sensitive bytes.
// We wipe the currently used storage and then clear the vector.
// We intentionally do not treat capacity reduction as a security primitive.
static void wipe_bytes(std::vector<std::uint8_t>* v) {
    if (!v) return;
    if (!v->empty()) {
        secure_wipe_bytes(v->data(), v->size());
    }
    v->clear();
}

// Fill `out` with `n` cryptographically random bytes.
static bool random_bytes_local(std::size_t n, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->assign(n, 0);
    if (n == 0) return true;
    return RAND_bytes(reinterpret_cast<unsigned char*>(out->data()),
                      static_cast<int>(out->size())) == 1;
}

} // namespace

// Native ML-KEM provider is compiled in for this target, so availability is constant.
bool mlkem768_available() {
    return true;
}

// Human-readable provider label for diagnostics/logs.
std::string mlkem768_backend_name() {
    return "mlkem-native-c";
}

// Generate an ML-KEM-768 keypair using wrapper-owned randomness and the
// provider's derandomized entry point.
bool mlkem768_keygen(MlKem768Keypair* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    wipe_bytes(&out->public_key);
    wipe_bytes(&out->secret_key);

    // ML-KEM key generation consumes 2 * MLKEM_SYMBYTES of randomness.
    std::vector<std::uint8_t> coins(2 * MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        wipe_bytes(&coins);
        if (err) *err = "random_coins_failed";
        return false;
    }

    out->public_key.assign(MLKEM768_PUBLICKEYBYTES, 0);
    out->secret_key.assign(MLKEM768_SECRETKEYBYTES, 0);

    const int rc = dnanexus_mlkem768_keypair_derand(
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

// Encapsulate to a recipient ML-KEM-768 public key using wrapper-owned
// randomness and the provider's derandomized entry point.
bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                          MlKem768EncapResult* out,
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

    // ML-KEM encapsulation consumes MLKEM_SYMBYTES of randomness.
    std::vector<std::uint8_t> coins(MLKEM_SYMBYTES, 0);
    if (!random_bytes_local(coins.size(), &coins)) {
        wipe_bytes(&coins);
        if (err) *err = "random_coins_failed";
        return false;
    }

    out->ciphertext.assign(MLKEM768_CIPHERTEXTBYTES, 0);
    out->shared_secret.assign(MLKEM_BYTES, 0);

    const int rc = dnanexus_mlkem768_enc_derand(
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

// Decapsulate an ML-KEM-768 ciphertext with recipient secret key.
//
// Important boundary rule:
// - The provider owns the implicit-rejection logic for correctly sized
//   ciphertexts, including compare/reject/shared-secret selection.
// - The wrapper must remain thin here and must not recreate those internals.
// - A nonzero provider return is treated as provider failure or secret-key
//   integrity failure, not as ordinary invalid-ciphertext rejection.
bool mlkem768_decapsulate(const std::vector<std::uint8_t>& secret_key,
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

    const int rc = dnanexus_mlkem768_dec(
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

// Diagnostic end-to-end ML-KEM self-test:
// keygen -> encapsulate -> decapsulate -> shared-secret equality check.
bool mlkem768_selftest(std::string* err) {
    if (err) err->clear();

    MlKem768Keypair kp;
    MlKem768EncapResult enc;
    std::vector<std::uint8_t> dec_ss;
    std::string step_err;

    const auto cleanup = [&]() {
        wipe_bytes(&kp.secret_key);
        wipe_bytes(&enc.shared_secret);
        wipe_bytes(&dec_ss);

        // These are public, but clear them too for tidy diagnostic cleanup.
        wipe_bytes(&kp.public_key);
        wipe_bytes(&enc.ciphertext);
    };

    if (!mlkem768_keygen(&kp, &step_err)) {
        cleanup();
        if (err) *err = "selftest:keygen:" + step_err;
        return false;
    }

    if (!mlkem768_encapsulate(kp.public_key, &enc, &step_err)) {
        cleanup();
        if (err) *err = "selftest:encapsulate:" + step_err;
        return false;
    }

    if (!mlkem768_decapsulate(kp.secret_key, enc.ciphertext, &dec_ss, &step_err)) {
        cleanup();
        if (err) *err = "selftest:decapsulate:" + step_err;
        return false;
    }

    if (enc.shared_secret.size() != dec_ss.size() || enc.shared_secret != dec_ss) {
        cleanup();
        if (err) *err = "selftest:shared_secret_mismatch";
        return false;
    }

    cleanup();
    return true;
}

} // namespace dnanexus::pq