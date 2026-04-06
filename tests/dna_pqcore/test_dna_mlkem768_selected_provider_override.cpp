#include "dna_mlkem768_backend.h"
#include "internal/dna_mlkem768_backend_diag.h"
#include "internal/dna_mlkem768_provider_select.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace dnanexus::pq;

namespace {

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
                  << " expected=" << static_cast<int>(want)
                  << " got=" << static_cast<int>(got) << "\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    using dnanexus::pq::internal::MlKem768ProviderId;

    // Section A: default state is now DNA.
    if (!expect_true("default no override",
                     !dnanexus::pq::internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("default selected provider dna",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::dna)) {
        return 1;
    }

    if (!expect_true("default backend name dna",
                     mlkem768_backend_name() == "dna-internal-wip")) {
        return 1;
    }

    // Section B: reject unsupported override.
    if (!expect_true("reject stub override",
                     !dnanexus::pq::internal::mlkem768_set_selected_provider_override(
                         MlKem768ProviderId::stub))) {
        return 1;
    }

    if (!expect_true("still no override after rejecting stub",
                     !dnanexus::pq::internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("still selected dna after rejecting stub",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::dna)) {
        return 1;
    }

    // Section C: force native and exercise the public selected-provider path.
    if (!expect_true("set native override",
                     dnanexus::pq::internal::mlkem768_set_selected_provider_override(
                         MlKem768ProviderId::native))) {
        return 1;
    }

    if (!expect_true("override present",
                     dnanexus::pq::internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("selected provider now native",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::native)) {
        return 1;
    }

    if (!expect_true("selected provider name native",
                     dnanexus::pq::internal::mlkem768_selected_provider_name() ==
                         "mlkem-native-c")) {
        return 1;
    }

    if (!expect_true("public backend name reflects native override",
                     mlkem768_backend_name() == "mlkem-native-c")) {
        return 1;
    }

    MlKem768Keypair kp;
    const MlKem768Status st_keygen = mlkem768_keygen_status(&kp);
    if (!expect_status("public keygen via selected native", st_keygen, MlKem768Status::ok)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native keygen pk size",
                     kp.public_key.size() == kMlKem768PublicKeyBytes)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native keygen sk size",
                     kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    MlKem768EncapResult enc;
    const MlKem768Status st_enc = mlkem768_encapsulate_status(kp.public_key, &enc);
    if (!expect_status("public encaps via selected native", st_enc, MlKem768Status::ok)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native encaps ct size",
                     enc.ciphertext.size() == kMlKem768CiphertextBytes)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native encaps ss size",
                     enc.shared_secret.size() == kMlKem768SharedSecretBytes)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    std::vector<std::uint8_t> dec_ss;
    const MlKem768Status st_dec = mlkem768_decapsulate_status(
        kp.secret_key, enc.ciphertext, &dec_ss);
    if (!expect_status("public decaps via selected native", st_dec, MlKem768Status::ok)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native decaps ss size",
                     dec_ss.size() == kMlKem768SharedSecretBytes)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    if (!expect_true("public native enc/dec match", dec_ss == enc.shared_secret)) {
        dnanexus::pq::internal::mlkem768_clear_selected_provider_override();
        return 1;
    }

    // Section D: clear override.
    dnanexus::pq::internal::mlkem768_clear_selected_provider_override();

    if (!expect_true("override cleared",
                     !dnanexus::pq::internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("selected provider returned to dna",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::dna)) {
        return 1;
    }

    if (!expect_true("public backend name returned to dna",
                     mlkem768_backend_name() == "dna-internal-wip")) {
        return 1;
    }

    std::cout << "[dna-pqcore] selected provider override ok"
              << " default=dna"
              << " override=native"
              << " restored=dna"
              << "\n";

    return 0;
}