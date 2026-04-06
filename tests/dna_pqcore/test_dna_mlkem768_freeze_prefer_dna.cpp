#include "dna_mlkem768_backend.h"
#include "internal/dna_mlkem768_backend_diag.h"
#include "internal/dna_mlkem768_provider_select.h"

#include <cstdint>
#include <iostream>
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

    // Under the DNA-selected freeze lane, selection should come from env.
    if (!expect_true("no in-process override required",
                     !dnanexus::pq::internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("selected provider is dna via env",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::dna)) {
        return 1;
    }

    if (!expect_true("backend name reflects dna selection",
                     mlkem768_backend_name() == "dna-internal-wip")) {
        return 1;
    }

    MlKem768Keypair kp;
    const MlKem768Status st_keygen = mlkem768_keygen_status(&kp);
    if (!expect_status("public keygen via dna-selected lane",
                       st_keygen, MlKem768Status::ok)) {
        return 1;
    }

    if (!expect_true("public keygen pk size",
                     kp.public_key.size() == kMlKem768PublicKeyBytes)) {
        return 1;
    }

    if (!expect_true("public keygen sk size",
                     kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
        return 1;
    }

    MlKem768EncapResult enc;
    const MlKem768Status st_enc = mlkem768_encapsulate_status(kp.public_key, &enc);
    if (!expect_status("public encaps via dna-selected lane",
                       st_enc, MlKem768Status::ok)) {
        return 1;
    }

    if (!expect_true("public encaps ct size",
                     enc.ciphertext.size() == kMlKem768CiphertextBytes)) {
        return 1;
    }

    if (!expect_true("public encaps ss size",
                     enc.shared_secret.size() == kMlKem768SharedSecretBytes)) {
        return 1;
    }

    std::vector<std::uint8_t> dec_ss;
    const MlKem768Status st_dec =
        mlkem768_decapsulate_status(kp.secret_key, enc.ciphertext, &dec_ss);
    if (!expect_status("public decaps via dna-selected lane",
                       st_dec, MlKem768Status::ok)) {
        return 1;
    }

    if (!expect_true("public decaps ss size",
                     dec_ss.size() == kMlKem768SharedSecretBytes)) {
        return 1;
    }

    if (!expect_true("public roundtrip match",
                     dec_ss == enc.shared_secret)) {
        return 1;
    }

    std::cout << "[dna-pqcore] freeze prefer dna ok"
              << " provider=" << mlkem768_backend_name()
              << " pk=" << kMlKem768PublicKeyBytes
              << " sk=" << kMlKem768SecretKeyBytes
              << " ct=" << kMlKem768CiphertextBytes
              << " ss=" << kMlKem768SharedSecretBytes
              << "\n";

    return 0;
}