#include "dna_mlkem768_backend.h"

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

bool expect_status(const char* label, MlKem768Status got, MlKem768Status want) {
    if (got != want) {
        std::cerr << "[dna-pqcore] " << label
                  << " expected=" << status_name(want)
                  << " got=" << status_name(got) << "\n";
        return false;
    }
    return true;
}

bool expect_true(const char* label, bool cond) {
    if (!cond) {
        std::cerr << "[dna-pqcore] " << label << " failed\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    // 1) Null output handling on the stable status API.
    {
        const MlKem768Status st = mlkem768_keygen_status(nullptr);
        if (!expect_status("keygen_status(nullptr)", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        std::vector<std::uint8_t> pk(kMlKem768PublicKeyBytes, 0);
        const MlKem768Status st = mlkem768_encapsulate_status(pk, nullptr);
        if (!expect_status("encapsulate_status(nullptr)", st, MlKem768Status::output_null)) {
            return 1;
        }
    }
    {
        std::vector<std::uint8_t> sk(kMlKem768SecretKeyBytes, 0);
        std::vector<std::uint8_t> ct(kMlKem768CiphertextBytes, 0);
        const MlKem768Status st = mlkem768_decapsulate_status(sk, ct, nullptr);
        if (!expect_status("decapsulate_status(nullptr)", st, MlKem768Status::output_null)) {
            return 1;
        }
    }

    // 2) Happy path on the stable status API.
    MlKem768Keypair kp;
    {
        const MlKem768Status st = mlkem768_keygen_status(&kp);
        if (!expect_status("keygen_status", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("public key size matches constant",
                         kp.public_key.size() == kMlKem768PublicKeyBytes)) {
            return 1;
        }
        if (!expect_true("secret key size matches constant",
                         kp.secret_key.size() == kMlKem768SecretKeyBytes)) {
            return 1;
        }
    }

    MlKem768EncapResult enc;
    {
        const MlKem768Status st = mlkem768_encapsulate_status(kp.public_key, &enc);
        if (!expect_status("encapsulate_status", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("ciphertext size matches constant",
                         enc.ciphertext.size() == kMlKem768CiphertextBytes)) {
            return 1;
        }
        if (!expect_true("shared secret size matches constant",
                         enc.shared_secret.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
    }

    std::vector<std::uint8_t> dec_ss;
    {
        const MlKem768Status st =
            mlkem768_decapsulate_status(kp.secret_key, enc.ciphertext, &dec_ss);
        if (!expect_status("decapsulate_status(valid)", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("dec shared secret size matches constant",
                         dec_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("enc/dec shared secret match", dec_ss == enc.shared_secret)) {
            return 1;
        }
    }

    // 3) Bad public-key length should fail and clear outputs.
    {
        std::vector<std::uint8_t> bad_pk = kp.public_key;
        bad_pk.pop_back();

        MlKem768EncapResult out;
        out.ciphertext.assign(7, 0xAA);
        out.shared_secret.assign(7, 0xBB);

        const MlKem768Status st = mlkem768_encapsulate_status(bad_pk, &out);
        if (!expect_status("encapsulate_status(bad pk len)", st, MlKem768Status::bad_public_key_len)) {
            return 1;
        }
        if (!expect_true("bad pk len clears ciphertext", out.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("bad pk len clears shared secret", out.shared_secret.empty())) {
            return 1;
        }
    }

    // 4) Correct-length malformed public key should fail as invalid_public_key.
    // Force the first packed 12-bit coefficient to 0xFFF, which is > q-1 and
    // therefore non-canonical under the provider modulus check.
    {
        std::vector<std::uint8_t> bad_pk = kp.public_key;

        // Packed 12-bit layout for the first two coefficients:
        //   t0 = pk[0] | ((pk[1] & 0x0F) << 8)
        //   t1 = (pk[1] >> 4) | (pk[2] << 4)
        //
        // Set t0 = 0xFFF unconditionally.
        bad_pk[0] = 0xFF;
        bad_pk[1] = static_cast<std::uint8_t>((bad_pk[1] & 0xF0) | 0x0F);

        MlKem768EncapResult out;
        out.ciphertext.assign(7, 0xAB);
        out.shared_secret.assign(7, 0xBC);

        const MlKem768Status st = mlkem768_encapsulate_status(bad_pk, &out);
        if (!expect_status("encapsulate_status(invalid pk)", st, MlKem768Status::invalid_public_key)) {
            return 1;
        }
        if (!expect_true("invalid pk clears ciphertext", out.ciphertext.empty())) {
            return 1;
        }
        if (!expect_true("invalid pk clears shared secret", out.shared_secret.empty())) {
            return 1;
        }
    }

    // 5) Bad secret-key length should fail and clear output.
    {
        std::vector<std::uint8_t> bad_sk = kp.secret_key;
        bad_sk.pop_back();

        std::vector<std::uint8_t> out_ss(9, 0xCC);

        const MlKem768Status st =
            mlkem768_decapsulate_status(bad_sk, enc.ciphertext, &out_ss);
        if (!expect_status("decapsulate_status(bad sk len)", st, MlKem768Status::bad_secret_key_len)) {
            return 1;
        }
        if (!expect_true("bad sk len clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    // 6) Bad ciphertext length should fail and clear output.
    {
        std::vector<std::uint8_t> bad_ct = enc.ciphertext;
        bad_ct.pop_back();

        std::vector<std::uint8_t> out_ss(9, 0xDD);

        const MlKem768Status st =
            mlkem768_decapsulate_status(kp.secret_key, bad_ct, &out_ss);
        if (!expect_status("decapsulate_status(bad ct len)", st, MlKem768Status::bad_ciphertext_len)) {
            return 1;
        }
        if (!expect_true("bad ct len clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    // 7) Correct-length tampered ciphertext is NOT an API failure.
    //    Provider implicit rejection should still return ok with a different secret.
    {
        std::vector<std::uint8_t> tampered_ct = enc.ciphertext;
        tampered_ct[0] ^= 0x01;

        std::vector<std::uint8_t> out_ss;
        const MlKem768Status st =
            mlkem768_decapsulate_status(kp.secret_key, tampered_ct, &out_ss);

        if (!expect_status("decapsulate_status(tampered ct)", st, MlKem768Status::ok)) {
            return 1;
        }
        if (!expect_true("tampered ct returns shared-secret-size secret",
                         out_ss.size() == kMlKem768SharedSecretBytes)) {
            return 1;
        }
        if (!expect_true("tampered ct secret differs from valid secret", out_ss != enc.shared_secret)) {
            return 1;
        }
    }

    // 8) Corrupt the stored H(pk) field inside the correctly sized secret key.
    //    This should trigger provider secret-key integrity failure.
    {
        constexpr std::size_t kSymBytes = kMlKem768SharedSecretBytes;

        std::vector<std::uint8_t> bad_sk = kp.secret_key;
        if (!expect_true("secret key large enough for integrity-field test",
                         bad_sk.size() >= 2 * kSymBytes)) {
            return 1;
        }

        // Current ML-KEM CCA secret-key layout stores H(pk) in the 32 bytes
        // immediately before the final 32-byte rejection secret z.
        bad_sk[bad_sk.size() - 2 * kSymBytes] ^= 0x01;

        std::vector<std::uint8_t> out_ss(9, 0xEE);
        const MlKem768Status st =
            mlkem768_decapsulate_status(bad_sk, enc.ciphertext, &out_ss);

        if (!expect_status("decapsulate_status(corrupted sk integrity field)",
                           st, MlKem768Status::invalid_secret_key)) {
            return 1;
        }
        if (!expect_true("corrupted sk clears shared secret", out_ss.empty())) {
            return 1;
        }
    }

    std::cout << "[dna-pqcore] boundary ok"
              << " pk=" << kp.public_key.size()
              << " sk=" << kp.secret_key.size()
              << " ct=" << enc.ciphertext.size()
              << " ss=" << enc.shared_secret.size()
              << "\n";

    return 0;
}