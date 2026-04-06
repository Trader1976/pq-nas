#include "share_pq_mlkem_v1.h"

#include "dna_mlkem768_backend.h"
#include "internal/dna_mlkem768_backend_diag.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace pqnas {
namespace {

namespace dna = dnanexus::pq;

// Best-effort wipe helper for temporary sensitive byte buffers.
// Used for V1 adapter-owned std::vector material.
static void wipe_bytes(std::vector<std::uint8_t>* v) {
    if (!v) return;
    std::fill(v->begin(), v->end(), 0);
    v->clear();
    v->shrink_to_fit();
}

static std::string status_to_err_string(dna::MlKem768Status st, const char* op) {
    switch (st) {
        case dna::MlKem768Status::ok:
            return "";
        case dna::MlKem768Status::output_null:
            return "output_null";
        case dna::MlKem768Status::bad_public_key_len:
            return "mlkem768_bad_public_key_len";
        case dna::MlKem768Status::bad_secret_key_len:
            return "mlkem768_bad_secret_key_len";
        case dna::MlKem768Status::bad_ciphertext_len:
            return "mlkem768_bad_ciphertext_len";
        case dna::MlKem768Status::invalid_public_key:
            return "mlkem768_invalid_public_key";
        case dna::MlKem768Status::invalid_secret_key:
            return "mlkem768_invalid_secret_key";
        case dna::MlKem768Status::random_failed:
            return "random_coins_failed";
        case dna::MlKem768Status::provider_failed:
            return std::string("mlkem768_") + op + "_failed";
    }
    return std::string("mlkem768_") + op + "_failed";
}

} // namespace

bool mlkem768_available_v1() {
    return dna::mlkem768_available();
}

std::string mlkem768_backend_name_v1() {
    return dna::mlkem768_backend_name();
}

bool mlkem768_keygen_v1(MlKem768KeypairV1* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    wipe_bytes(&out->public_key);
    wipe_bytes(&out->secret_key);

    dna::MlKem768Keypair kp;
    const dna::MlKem768Status st = dna::mlkem768_keygen_status(&kp);
    if (st != dna::MlKem768Status::ok) {
        dna::mlkem768_wipe_keypair(&kp);
        if (err) *err = status_to_err_string(st, "keygen");
        return false;
    }

    out->public_key = std::move(kp.public_key);
    out->secret_key = std::move(kp.secret_key);
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

    dna::MlKem768EncapResult enc;
    const dna::MlKem768Status st = dna::mlkem768_encapsulate_status(public_key, &enc);
    if (st != dna::MlKem768Status::ok) {
        dna::mlkem768_wipe_encap_result(&enc);
        if (err) *err = status_to_err_string(st, "encapsulate");
        return false;
    }

    out->ciphertext = std::move(enc.ciphertext);
    out->shared_secret = std::move(enc.shared_secret);
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

    std::vector<std::uint8_t> shared_secret;
    const dna::MlKem768Status st =
        dna::mlkem768_decapsulate_status(secret_key, ciphertext, &shared_secret);

    if (st != dna::MlKem768Status::ok) {
        dna::mlkem768_wipe_shared_secret(&shared_secret);
        if (err) *err = status_to_err_string(st, "decapsulate");
        return false;
    }

    *out_shared_secret = std::move(shared_secret);
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