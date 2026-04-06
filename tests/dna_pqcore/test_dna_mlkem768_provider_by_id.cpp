#include "internal/dna_mlkem768_provider.h"
#include "internal/dna_mlkem768_provider_select.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace dnanexus::pq;

namespace {

const char* status_name(MlKem768Status st) {
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
    return "unknown";
}

bool expect_true(const char* label, bool cond) {
    if (!cond) {
        std::cerr << "[dna-pqcore] " << label << " failed\n";
        return false;
    }
    return true;
}

bool expect_status(const char* label, MlKem768Status got, MlKem768Status want) {
    if (got != want) {
        std::cerr << "[dna-pqcore] " << label
                  << " expected=" << status_name(want)
                  << " got=" << status_name(got) << "\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    using internal::MlKem768ProviderId;

    // Native provider by-id: happy path.
    if (!expect_true("native available",
                     internal::mlkem768_provider_available_by_id(MlKem768ProviderId::native))) {
        return 1;
    }

    if (!expect_true("native name",
                     internal::mlkem768_provider_name_by_id(MlKem768ProviderId::native) ==
                         "mlkem-native-c")) {
        return 1;
    }

    MlKem768Keypair kp;
    {
        const MlKem768Status st =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::native, &kp);
        if (!expect_status("native keygen", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("native keygen pk size",
                         kp.public_key.size() == kMlKem768PublicKeyBytes)) {
            return 1;
        }
        if (!expect_true("native keygen sk size",
                         kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
            return 1;
        }
    }

    MlKem768EncapResult enc;
    {
        const MlKem768Status st = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::native, kp.public_key, &enc);
        if (!expect_status("native encapsulate", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("native encaps ct size",
                         enc.ciphertext.size() == kMlKem768CiphertextBytes)) {
            return 1;
        }
        if (!expect_true("native encaps ss size",
                         enc.shared_secret.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
    }

    std::vector<std::uint8_t> dec_ss;
    {
        const MlKem768Status st = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::native, kp.secret_key, enc.ciphertext, &dec_ss);
        if (!expect_status("native decapsulate", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("native decaps ss size",
                         dec_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("native enc/dec match", dec_ss == enc.shared_secret)) {
            return 1;
        }
    }

    // Stub provider by-id: unavailable and failing, with output wipe discipline.
    if (!expect_true("stub unavailable",
                     !internal::mlkem768_provider_available_by_id(MlKem768ProviderId::stub))) {
        return 1;
    }

    if (!expect_true("stub name",
                     internal::mlkem768_provider_name_by_id(MlKem768ProviderId::stub) ==
                         "stub-unavailable")) {
        return 1;
    }

    {
        MlKem768Keypair stub_kp;
        stub_kp.public_key.assign(7, 0xAA);
        stub_kp.secret_key.assign(7, 0xBB);

        const MlKem768Status st =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::stub, &stub_kp);
        if (!expect_status("stub keygen", st, MlKem768Status::provider_failed)) {
            return 1;
        }
        if (!expect_true("stub keygen clears pk", stub_kp.public_key.empty())) {
            return 1;
        }
        if (!expect_true("stub keygen clears sk", stub_kp.secret_key.empty())) {
            return 1;
        }
    }

    {
        MlKem768EncapResult stub_enc;
        stub_enc.ciphertext.assign(7, 0xCC);
        stub_enc.shared_secret.assign(7, 0xDD);

        const MlKem768Status st = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::stub, kp.public_key, &stub_enc);
        if (!expect_status("stub encapsulate", st, MlKem768Status::provider_failed)) {
            return 1;
        }
        if (!expect_true("stub encaps clears ct", stub_enc.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("stub encaps clears ss", stub_enc.shared_secret.empty())) {
            return 1;
        }
    }

    {
        std::vector<std::uint8_t> stub_ss(9, 0xEE);

        const MlKem768Status st = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::stub, kp.secret_key, enc.ciphertext, &stub_ss);
        if (!expect_status("stub decapsulate", st, MlKem768Status::provider_failed)) {
            return 1;
        }
        if (!expect_true("stub decaps clears ss", stub_ss.empty())) {
            return 1;
        }
    }

    // DNA provider by-id: keygen-only slice.
    if (!expect_true("dna unavailable until full provider exists",
                     !internal::mlkem768_provider_available_by_id(MlKem768ProviderId::dna))) {
        return 1;
    }

    if (!expect_true("dna name",
                     internal::mlkem768_provider_name_by_id(MlKem768ProviderId::dna) ==
                         "dna-internal-wip")) {
        return 1;
    }

    {
        MlKem768Keypair dna_kp;

        const MlKem768Status st =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::dna, &dna_kp);
        if (!expect_status("dna keygen", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("dna keygen pk size",
                         dna_kp.public_key.size() == kMlKem768PublicKeyBytes)) {
            return 1;
        }
        if (!expect_true("dna keygen sk size",
                         dna_kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
            return 1;
        }
    }

    {
        MlKem768EncapResult dna_enc;
        dna_enc.ciphertext.assign(7, 0xC3);
        dna_enc.shared_secret.assign(7, 0xD4);

        const MlKem768Status st = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::dna, kp.public_key, &dna_enc);
        if (!expect_status("dna encapsulate", st, MlKem768Status::provider_failed)) {
            return 1;
        }
        if (!expect_true("dna encaps clears ct", dna_enc.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("dna encaps clears ss", dna_enc.shared_secret.empty())) {
            return 1;
        }
    }

    {
        std::vector<std::uint8_t> dna_ss(9, 0xF5);

        const MlKem768Status st = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::dna, kp.secret_key, enc.ciphertext, &dna_ss);
        if (!expect_status("dna decapsulate", st, MlKem768Status::provider_failed)) {
            return 1;
        }
        if (!expect_true("dna decaps clears ss", dna_ss.empty())) {
            return 1;
        }
    }

    // Null-output consistency checks on stub path.
    {
        const MlKem768Status st =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::stub, nullptr);
        if (!expect_status("stub keygen nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        const MlKem768Status st = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::stub, kp.public_key, nullptr);
        if (!expect_status("stub encapsulate nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        const MlKem768Status st = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::stub, kp.secret_key, enc.ciphertext, nullptr);
        if (!expect_status("stub decapsulate nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }

    // Null-output consistency checks on dna path.
    {
        const MlKem768Status st =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::dna, nullptr);
        if (!expect_status("dna keygen nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        const MlKem768Status st = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::dna, kp.public_key, nullptr);
        if (!expect_status("dna encapsulate nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        const MlKem768Status st = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::dna, kp.secret_key, enc.ciphertext, nullptr);
        if (!expect_status("dna decapsulate nullptr", st, MlKem768Status::output_null)) {
            return 1;
        }
    }

    std::cout << "[dna-pqcore] provider by-id ok"
              << " native=mlkem-native-c"
              << " stub=stub-unavailable"
              << " dna=dna-internal-wip"
              << "\n";

    return 0;
}