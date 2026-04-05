#include "dna_mlkem768_backend.h"
#include "internal/dna_mlkem768_backend_diag.h"
#include "internal/dna_mlkem768_provider.h"
#include "internal/dna_mlkem768_provider_select.h"

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <vector>

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

static const char* status_string(MlKem768Status st) {
    switch (st) {
        case MlKem768Status::ok:
            return "ok";
        case MlKem768Status::output_null:
            return "output_null";
        case MlKem768Status::bad_public_key_len:
            return "bad_public_key_len";
        case MlKem768Status::bad_secret_key_len:
            return "bad_secret_key_len";
        case MlKem768Status::bad_ciphertext_len:
            return "bad_ciphertext_len";
        case MlKem768Status::invalid_public_key:
            return "invalid_public_key";
        case MlKem768Status::invalid_secret_key:
            return "invalid_secret_key";
        case MlKem768Status::random_failed:
            return "random_failed";
        case MlKem768Status::provider_failed:
            return "provider_failed";
    }
    return "provider_failed";
}

} // namespace

void mlkem768_wipe_keypair(MlKem768Keypair* kp) {
    if (!kp) return;
    wipe_bytes(&kp->secret_key);
    wipe_bytes(&kp->public_key);
}

void mlkem768_wipe_encap_result(MlKem768EncapResult* enc) {
    if (!enc) return;
    wipe_bytes(&enc->shared_secret);
    wipe_bytes(&enc->ciphertext);
}

void mlkem768_wipe_shared_secret(std::vector<std::uint8_t>* ss) {
    wipe_bytes(ss);
}

// Public diagnostic helpers delegate to the selected internal provider.
bool mlkem768_available() {
    return internal::mlkem768_selected_provider_available();
}

std::string mlkem768_backend_name() {
    return internal::mlkem768_selected_provider_name();
}

// Public status API delegates to the selected internal provider.
MlKem768Status mlkem768_keygen_status(MlKem768Keypair* out) {
    return internal::mlkem768_selected_provider_keygen(out);
}

MlKem768Status mlkem768_encapsulate_status(
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out) {
    return internal::mlkem768_selected_provider_encapsulate(public_key, out);
}

MlKem768Status mlkem768_decapsulate_status(
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>* out_shared_secret) {
    return internal::mlkem768_selected_provider_decapsulate(
        secret_key, ciphertext, out_shared_secret);
}

// Compatibility wrapper around mlkem768_keygen_status().
bool mlkem768_keygen(MlKem768Keypair* out, std::string* err) {
    if (err) err->clear();
    const MlKem768Status st = mlkem768_keygen_status(out);
    if (st != MlKem768Status::ok) {
        if (err) *err = status_string(st);
        return false;
    }
    return true;
}

// Compatibility wrapper around mlkem768_encapsulate_status().
bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                          MlKem768EncapResult* out,
                          std::string* err) {
    if (err) err->clear();
    const MlKem768Status st = mlkem768_encapsulate_status(public_key, out);
    if (st != MlKem768Status::ok) {
        if (err) *err = status_string(st);
        return false;
    }
    return true;
}

// Compatibility wrapper around mlkem768_decapsulate_status().
bool mlkem768_decapsulate(const std::vector<std::uint8_t>& secret_key,
                          const std::vector<std::uint8_t>& ciphertext,
                          std::vector<std::uint8_t>* out_shared_secret,
                          std::string* err) {
    if (err) err->clear();
    const MlKem768Status st =
        mlkem768_decapsulate_status(secret_key, ciphertext, out_shared_secret);
    if (st != MlKem768Status::ok) {
        if (err) *err = status_string(st);
        return false;
    }
    return true;
}

// Diagnostic end-to-end ML-KEM self-test:
// keygen -> encapsulate -> decapsulate -> shared-secret equality check.
//
// This deliberately exercises the public DNA boundary rather than calling the
// internal provider functions directly.
bool mlkem768_selftest(std::string* err) {
    if (err) err->clear();

    MlKem768Keypair kp;
    MlKem768EncapResult enc;
    std::vector<std::uint8_t> dec_ss;

    const auto cleanup = [&]() {
        mlkem768_wipe_keypair(&kp);
        mlkem768_wipe_encap_result(&enc);
        mlkem768_wipe_shared_secret(&dec_ss);
    };

    const MlKem768Status st_keygen = mlkem768_keygen_status(&kp);
    if (st_keygen != MlKem768Status::ok) {
        cleanup();
        if (err) *err = "selftest:keygen:" + std::string(status_string(st_keygen));
        return false;
    }

    const MlKem768Status st_enc = mlkem768_encapsulate_status(kp.public_key, &enc);
    if (st_enc != MlKem768Status::ok) {
        cleanup();
        if (err) *err = "selftest:encapsulate:" + std::string(status_string(st_enc));
        return false;
    }

    const MlKem768Status st_dec =
        mlkem768_decapsulate_status(kp.secret_key, enc.ciphertext, &dec_ss);
    if (st_dec != MlKem768Status::ok) {
        cleanup();
        if (err) *err = "selftest:decapsulate:" + std::string(status_string(st_dec));
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