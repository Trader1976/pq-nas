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

    if (!expect_true("selected provider defaults to dna",
                     internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::dna)) {
        return 1;
                         }

    constexpr int kIters = 8;

    // Case A: DNA full roundtrip.
    for (int i = 0; i < kIters; ++i) {
        MlKem768Keypair kp;
        MlKem768EncapResult enc;
        std::vector<std::uint8_t> dec_ss;

        const MlKem768Status st_keygen =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::dna, &kp);
        if (!expect_status("dna keygen", st_keygen, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_enc =
            internal::mlkem768_provider_encapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.public_key,
                                                          &enc);
        if (!expect_status("dna encapsulate", st_enc, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_dec =
            internal::mlkem768_provider_decapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.secret_key,
                                                          enc.ciphertext,
                                                          &dec_ss);
        if (!expect_status("dna decapsulate", st_dec, MlKem768Status::ok)) {
            return 1;
        }

        if (!expect_true("dna roundtrip ss size",
                         dec_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("dna roundtrip ss match", dec_ss == enc.shared_secret)) {
            return 1;
        }
    }

    // Case B: native -> DNA interop.
    for (int i = 0; i < kIters; ++i) {
        MlKem768Keypair kp;
        MlKem768EncapResult enc;
        std::vector<std::uint8_t> dec_ss;

        const MlKem768Status st_keygen =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::native, &kp);
        if (!expect_status("native keygen", st_keygen, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_enc =
            internal::mlkem768_provider_encapsulate_by_id(MlKem768ProviderId::native,
                                                          kp.public_key,
                                                          &enc);
        if (!expect_status("native encapsulate", st_enc, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_dec =
            internal::mlkem768_provider_decapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.secret_key,
                                                          enc.ciphertext,
                                                          &dec_ss);
        if (!expect_status("dna decapsulate native ct", st_dec, MlKem768Status::ok)) {
            return 1;
        }

        if (!expect_true("native->dna ss size",
                         dec_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("native->dna ss match", dec_ss == enc.shared_secret)) {
            return 1;
        }
    }

    // Case C: tampered ciphertext still returns ok with a different shared secret.
    {
        MlKem768Keypair kp;
        MlKem768EncapResult enc;
        std::vector<std::uint8_t> good_ss;
        std::vector<std::uint8_t> bad_ss;

        const MlKem768Status st_keygen =
            internal::mlkem768_provider_keygen_by_id(MlKem768ProviderId::dna, &kp);
        if (!expect_status("tamper keygen", st_keygen, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_enc =
            internal::mlkem768_provider_encapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.public_key,
                                                          &enc);
        if (!expect_status("tamper encapsulate", st_enc, MlKem768Status::ok)) {
            return 1;
        }

        const MlKem768Status st_good_dec =
            internal::mlkem768_provider_decapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.secret_key,
                                                          enc.ciphertext,
                                                          &good_ss);
        if (!expect_status("tamper good decap", st_good_dec, MlKem768Status::ok)) {
            return 1;
        }

        std::vector<std::uint8_t> tampered_ct = enc.ciphertext;
        tampered_ct[0] ^= 0x01;

        const MlKem768Status st_bad_dec =
            internal::mlkem768_provider_decapsulate_by_id(MlKem768ProviderId::dna,
                                                          kp.secret_key,
                                                          tampered_ct,
                                                          &bad_ss);
        if (!expect_status("tamper dna decap still ok", st_bad_dec, MlKem768Status::ok)) {
            return 1;
        }

        if (!expect_true("tamper bad ss size",
                         bad_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("tamper ss differs", bad_ss != good_ss)) {
            return 1;
        }
    }

    std::cout << "[dna-pqcore] dna decaps interop ok"
              << " iters=" << kIters
              << " ss=" << kMlKem768SharedSecretBytes
              << "\n";

    return 0;
}