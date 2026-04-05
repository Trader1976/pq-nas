#include "dna_mlkem768_backend.h"

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

bool expect_false(const char* label, bool cond) {
    if (cond) {
        std::cerr << "[dna-pqcore] " << label << " unexpectedly succeeded\n";
        return false;
    }
    return true;
}

bool expect_err(const char* label, const std::string& got, const char* want) {
    if (got != want) {
        std::cerr << "[dna-pqcore] " << label
                  << " expected_err=" << want
                  << " got_err=" << got << "\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    std::string err;

    // 1) Happy path through compatibility wrappers.
    MlKem768Keypair kp;
    if (!expect_true("keygen", mlkem768_keygen(&kp, &err))) {
        return 1;
    }
    if (!expect_true("keygen err empty", err.empty())) {
        return 1;
    }

    MlKem768EncapResult enc;
    if (!expect_true("encapsulate", mlkem768_encapsulate(kp.public_key, &enc, &err))) {
        return 1;
    }
    if (!expect_true("encapsulate err empty", err.empty())) {
        return 1;
    }

    std::vector<std::uint8_t> dec_ss;
    if (!expect_true("decapsulate", mlkem768_decapsulate(kp.secret_key, enc.ciphertext, &dec_ss, &err))) {
        return 1;
    }
    if (!expect_true("decapsulate err empty", err.empty())) {
        return 1;
    }
    if (!expect_true("shared secret size", dec_ss.size() == kMlKem768SharedSecretBytes)) {
        return 1;
    }
    if (!expect_true("shared secret match", dec_ss == enc.shared_secret)) {
        return 1;
    }

    // 2) Null output handling.
    err = "stale";
    if (!expect_false("keygen nullptr", mlkem768_keygen(nullptr, &err))) {
        return 1;
    }
    if (!expect_err("keygen nullptr err", err, "output_null")) {
        return 1;
    }

    err = "stale";
    if (!expect_false("encapsulate nullptr", mlkem768_encapsulate(kp.public_key, nullptr, &err))) {
        return 1;
    }
    if (!expect_err("encapsulate nullptr err", err, "output_null")) {
        return 1;
    }

    err = "stale";
    if (!expect_false("decapsulate nullptr",
                      mlkem768_decapsulate(kp.secret_key, enc.ciphertext, nullptr, &err))) {
        return 1;
    }
    if (!expect_err("decapsulate nullptr err", err, "output_null")) {
        return 1;
    }

    // 3) Bad public-key length.
    {
        std::vector<std::uint8_t> bad_pk = kp.public_key;
        bad_pk.pop_back();

        MlKem768EncapResult out;
        out.ciphertext.assign(7, 0xAA);
        out.shared_secret.assign(7, 0xBB);

        err = "stale";
        if (!expect_false("bad pk len", mlkem768_encapsulate(bad_pk, &out, &err))) {
            return 1;
        }
        if (!expect_err("bad pk len err", err, "bad_public_key_len")) {
            return 1;
        }
        if (!expect_true("bad pk clears ciphertext", out.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("bad pk clears shared secret", out.shared_secret.empty())) {
            return 1;
        }
    }

    // 4) Invalid public key with correct length.
    {
        std::vector<std::uint8_t> bad_pk = kp.public_key;

        // Force first packed 12-bit coefficient to 0xFFF (> q-1).
        bad_pk[0] = 0xFF;
        bad_pk[1] = static_cast<std::uint8_t>((bad_pk[1] & 0xF0) | 0x0F);

        MlKem768EncapResult out;
        out.ciphertext.assign(7, 0xAB);
        out.shared_secret.assign(7, 0xBC);

        err = "stale";
        if (!expect_false("invalid pk", mlkem768_encapsulate(bad_pk, &out, &err))) {
            return 1;
        }
        if (!expect_err("invalid pk err", err, "invalid_public_key")) {
            return 1;
        }
        if (!expect_true("invalid pk clears ciphertext", out.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("invalid pk clears shared secret", out.shared_secret.empty())) {
            return 1;
        }
    }

    // 5) Bad secret-key length.
    {
        std::vector<std::uint8_t> bad_sk = kp.secret_key;
        bad_sk.pop_back();

        std::vector<std::uint8_t> out_ss(9, 0xCC);

        err = "stale";
        if (!expect_false("bad sk len",
                          mlkem768_decapsulate(bad_sk, enc.ciphertext, &out_ss, &err))) {
            return 1;
        }
        if (!expect_err("bad sk len err", err, "bad_secret_key_len")) {
            return 1;
        }
        if (!expect_true("bad sk clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    // 6) Bad ciphertext length.
    {
        std::vector<std::uint8_t> bad_ct = enc.ciphertext;
        bad_ct.pop_back();

        std::vector<std::uint8_t> out_ss(9, 0xDD);

        err = "stale";
        if (!expect_false("bad ct len",
                          mlkem768_decapsulate(kp.secret_key, bad_ct, &out_ss, &err))) {
            return 1;
        }
        if (!expect_err("bad ct len err", err, "bad_ciphertext_len")) {
            return 1;
        }
        if (!expect_true("bad ct clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    // 7) Correct-length tampered ciphertext is still success.
    {
        std::vector<std::uint8_t> tampered_ct = enc.ciphertext;
        tampered_ct[0] ^= 0x01;

        std::vector<std::uint8_t> out_ss;
        err = "stale";
        if (!expect_true("tampered ct success",
                         mlkem768_decapsulate(kp.secret_key, tampered_ct, &out_ss, &err))) {
            return 1;
        }
        if (!expect_true("tampered ct err empty", err.empty())) {
            return 1;
        }
        if (!expect_true("tampered ct shared secret size",
                         out_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("tampered ct secret differs", out_ss != enc.shared_secret)) {
            return 1;
        }
    }

    // 8) Invalid secret key with correct length.
    {
        constexpr std::size_t kSymBytes = kMlKem768SharedSecretBytes;

        std::vector<std::uint8_t> bad_sk = kp.secret_key;
        bad_sk[bad_sk.size() - 2 * kSymBytes] ^= 0x01;

        std::vector<std::uint8_t> out_ss(9, 0xEE);

        err = "stale";
        if (!expect_false("invalid sk",
                          mlkem768_decapsulate(bad_sk, enc.ciphertext, &out_ss, &err))) {
            return 1;
        }
        if (!expect_err("invalid sk err", err, "invalid_secret_key")) {
            return 1;
        }
        if (!expect_true("invalid sk clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    std::cout << "[dna-pqcore] compat ok"
              << " pk=" << kp.public_key.size()
              << " sk=" << kp.secret_key.size()
              << " ct=" << enc.ciphertext.size()
              << " ss=" << enc.shared_secret.size()
              << "\n";

    return 0;
}