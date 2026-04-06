#include "internal/dna_mlkem768_provider.h"
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
    using internal::MlKem768ProviderId;

    if (!expect_true("selected provider remains native",
                     internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::native)) {
        return 1;
    }

    constexpr int kIters = 8;
    for (int i = 0; i < kIters; ++i) {
        MlKem768Keypair kp;
        const MlKem768Status st_keygen =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::dna, &kp);
        if (!expect_status("dna keygen", st_keygen, MlKem768Status::ok)) {
            return 1;
        }

        if (!expect_true("dna keygen pk size",
                         kp.public_key.size() == kMlKem768PublicKeyBytes)) {
            return 1;
        }
        if (!expect_true("dna keygen sk size",
                         kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
            return 1;
        }

        MlKem768EncapResult enc;
        const MlKem768Status st_enc = internal::mlkem768_provider_encapsulate_by_id(
            MlKem768ProviderId::native, kp.public_key, &enc);
        if (!expect_status("native encapsulate from dna pk", st_enc, MlKem768Status::ok)) {
            return 1;
        }

        std::vector<std::uint8_t> dec_ss;
        const MlKem768Status st_dec = internal::mlkem768_provider_decapsulate_by_id(
            MlKem768ProviderId::native, kp.secret_key, enc.ciphertext, &dec_ss);
        if (!expect_status("native decapsulate from dna sk", st_dec, MlKem768Status::ok)) {
            return 1;
        }

        if (!expect_true("interop shared secret size",
                         dec_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("interop shared secret match", dec_ss == enc.shared_secret)) {
            return 1;
        }
    }

    std::cout << "[dna-pqcore] dna keygen interop ok"
              << " iters=" << kIters
              << " pk=" << kMlKem768PublicKeyBytes
              << " sk=" << kMlKem768SecretKeyBytes
              << "\n";

    return 0;
}