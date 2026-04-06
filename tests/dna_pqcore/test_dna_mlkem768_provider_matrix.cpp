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

bool expect_true(const std::string& label, bool cond) {
    if (!cond) {
        std::cerr << "[dna-pqcore] " << label << " failed\n";
        return false;
    }
    return true;
}

bool expect_status(const std::string& label, MlKem768Status got, MlKem768Status want) {
    if (got != want) {
        std::cerr << "[dna-pqcore] " << label
                  << " expected=" << status_name(want)
                  << " got=" << status_name(got) << "\n";
        return false;
    }
    return true;
}

struct ProviderDesc {
    dnanexus::pq::internal::MlKem768ProviderId id;
    const char* name;
};

std::string combo_label(const ProviderDesc& kg,
                        const ProviderDesc& enc,
                        const ProviderDesc& dec,
                        int iter) {
    return std::string(kg.name) + "-kg/" +
           enc.name + "-enc/" +
           dec.name + "-dec" +
           "/iter=" + std::to_string(iter);
}

} // namespace

int main() {
    using dnanexus::pq::internal::MlKem768ProviderId;

    if (!expect_true("selected provider remains native",
                     dnanexus::pq::internal::mlkem768_selected_provider_id() ==
                         MlKem768ProviderId::native)) {
        return 1;
    }

    const ProviderDesc providers[] = {
        {MlKem768ProviderId::native, "native"},
        {MlKem768ProviderId::dna, "dna"},
    };

    constexpr int kIters = 8;
    int valid_case_count = 0;
    int tamper_case_count = 0;

    // -------------------------------------------------------------------------
    // Case group A: valid interoperability matrix
    // -------------------------------------------------------------------------
    for (const auto& kgp : providers) {
        for (const auto& encp : providers) {
            for (const auto& decp : providers) {
                for (int iter = 0; iter < kIters; ++iter) {
                    const std::string base = combo_label(kgp, encp, decp, iter);

                    MlKem768Keypair kp;
                    const MlKem768Status st_keygen =
                        dnanexus::pq::internal::mlkem768_provider_keygen_by_id(kgp.id, &kp);
                    if (!expect_status(base + ":keygen", st_keygen, MlKem768Status::ok)) {
                        return 1;
                    }
                    if (!expect_true(base + ":pk_size",
                                     kp.public_key.size() == kMlKem768PublicKeyBytes)) {
                        return 1;
                    }
                    if (!expect_true(base + ":sk_size",
                                     kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
                        return 1;
                    }

                    MlKem768EncapResult enc;
                    const MlKem768Status st_enc =
                        dnanexus::pq::internal::mlkem768_provider_encapsulate_by_id(
                            encp.id, kp.public_key, &enc);
                    if (!expect_status(base + ":encaps", st_enc, MlKem768Status::ok)) {
                        return 1;
                    }
                    if (!expect_true(base + ":ct_size",
                                     enc.ciphertext.size() == kMlKem768CiphertextBytes)) {
                        return 1;
                    }
                    if (!expect_true(base + ":ss_size",
                                     enc.shared_secret.size() == kMlKem768SharedSecretBytes)) {
                        return 1;
                    }

                    std::vector<std::uint8_t> dec_ss;
                    const MlKem768Status st_dec =
                        dnanexus::pq::internal::mlkem768_provider_decapsulate_by_id(
                            decp.id, kp.secret_key, enc.ciphertext, &dec_ss);
                    if (!expect_status(base + ":decaps", st_dec, MlKem768Status::ok)) {
                        return 1;
                    }
                    if (!expect_true(base + ":dec_ss_size",
                                     dec_ss.size() == kMlKem768SharedSecretBytes)) {
                        return 1;
                    }
                    if (!expect_true(base + ":ss_match", dec_ss == enc.shared_secret)) {
                        return 1;
                    }

                    ++valid_case_count;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Case group B: tampered ciphertext behavior matrix
    // -------------------------------------------------------------------------
    for (const auto& kgp : providers) {
        for (const auto& encp : providers) {
            for (const auto& decp : providers) {
                for (int iter = 0; iter < kIters; ++iter) {
                    const std::string base =
                        combo_label(kgp, encp, decp, iter) + ":tamper";

                    MlKem768Keypair kp;
                    const MlKem768Status st_keygen =
                        dnanexus::pq::internal::mlkem768_provider_keygen_by_id(kgp.id, &kp);
                    if (!expect_status(base + ":keygen", st_keygen, MlKem768Status::ok)) {
                        return 1;
                    }

                    MlKem768EncapResult enc;
                    const MlKem768Status st_enc =
                        dnanexus::pq::internal::mlkem768_provider_encapsulate_by_id(
                            encp.id, kp.public_key, &enc);
                    if (!expect_status(base + ":encaps", st_enc, MlKem768Status::ok)) {
                        return 1;
                    }

                    std::vector<std::uint8_t> good_ss;
                    const MlKem768Status st_good =
                        dnanexus::pq::internal::mlkem768_provider_decapsulate_by_id(
                            decp.id, kp.secret_key, enc.ciphertext, &good_ss);
                    if (!expect_status(base + ":good_decaps", st_good, MlKem768Status::ok)) {
                        return 1;
                    }
                    if (!expect_true(base + ":good_ss_size",
                                     good_ss.size() == kMlKem768SharedSecretBytes)) {
                        return 1;
                    }
                    if (!expect_true(base + ":good_ss_match", good_ss == enc.shared_secret)) {
                        return 1;
                    }

                    std::vector<std::uint8_t> bad_ct = enc.ciphertext;
                    bad_ct[0] ^= 0x01;

                    std::vector<std::uint8_t> bad_ss;
                    const MlKem768Status st_bad =
                        dnanexus::pq::internal::mlkem768_provider_decapsulate_by_id(
                            decp.id, kp.secret_key, bad_ct, &bad_ss);
                    if (!expect_status(base + ":bad_decaps_still_ok",
                                       st_bad, MlKem768Status::ok)) {
                        return 1;
                    }
                    if (!expect_true(base + ":bad_ss_size",
                                     bad_ss.size() == kMlKem768SharedSecretBytes)) {
                        return 1;
                    }
                    if (!expect_true(base + ":bad_ss_differs", bad_ss != good_ss)) {
                        return 1;
                    }

                    ++tamper_case_count;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Case group C: bad-length contract checks for decapsulation providers
    // -------------------------------------------------------------------------
    {
        MlKem768Keypair kp;
        MlKem768EncapResult enc;
        if (!expect_status("prep native keygen",
                           dnanexus::pq::internal::mlkem768_provider_keygen_by_id(
                               MlKem768ProviderId::native, &kp),
                           MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_status("prep native encaps",
                           dnanexus::pq::internal::mlkem768_provider_encapsulate_by_id(
                               MlKem768ProviderId::native, kp.public_key, &enc),
                           MlKem768Status::ok)) {
            return 1;
        }

        for (const auto& decp : providers) {
            {
                std::vector<std::uint8_t> short_sk = kp.secret_key;
                short_sk.pop_back();
                std::vector<std::uint8_t> out_ss(5, 0xAA);

                const MlKem768Status st =
                    dnanexus::pq::internal::mlkem768_provider_decapsulate_by_id(
                        decp.id, short_sk, enc.ciphertext, &out_ss);

                if (!expect_status(std::string(decp.name) + ":bad_secret_key_len",
                                   st, MlKem768Status::bad_secret_key_len)) {
                    return 1;
                }
                if (!expect_true(std::string(decp.name) + ":bad_secret_key_clears_output",
                                 out_ss.empty())) {
                    return 1;
                }
            }

            {
                std::vector<std::uint8_t> short_ct = enc.ciphertext;
                short_ct.pop_back();
                std::vector<std::uint8_t> out_ss(5, 0xBB);

                const MlKem768Status st =
                    dnanexus::pq::internal::mlkem768_provider_decapsulate_by_id(
                        decp.id, kp.secret_key, short_ct, &out_ss);

                if (!expect_status(std::string(decp.name) + ":bad_ciphertext_len",
                                   st, MlKem768Status::bad_ciphertext_len)) {
                    return 1;
                }
                if (!expect_true(std::string(decp.name) + ":bad_ciphertext_clears_output",
                                 out_ss.empty())) {
                    return 1;
                }
            }
        }
    }

    std::cout << "[dna-pqcore] provider matrix ok"
              << " valid_cases=" << valid_case_count
              << " tamper_cases=" << tamper_case_count
              << " providers=native,dna"
              << "\n";

    return 0;
}