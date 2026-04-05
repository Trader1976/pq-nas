#include "dna_mlkem768_backend.h"

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

} // namespace

int main() {
    // Null-safe repeated calls should not crash.
    mlkem768_wipe_keypair(nullptr);
    mlkem768_wipe_encap_result(nullptr);
    mlkem768_wipe_shared_secret(nullptr);

    // Wipe keypair.
    MlKem768Keypair kp;
    kp.public_key.assign(kMlKem768PublicKeyBytes, 0x11);
    kp.secret_key.assign(kMlKem768SecretKeyBytes, 0x22);

    mlkem768_wipe_keypair(&kp);

    if (!expect_true("wipe keypair clears public_key", kp.public_key.empty())) {
        return 1;
    }
    if (!expect_true("wipe keypair clears secret_key", kp.secret_key.empty())) {
        return 1;
    }

    // Repeated wipe should remain safe.
    mlkem768_wipe_keypair(&kp);

    if (!expect_true("repeated wipe keypair keeps public_key empty", kp.public_key.empty())) {
        return 1;
    }
    if (!expect_true("repeated wipe keypair keeps secret_key empty", kp.secret_key.empty())) {
        return 1;
    }

    // Wipe encapsulation result.
    MlKem768EncapResult enc;
    enc.ciphertext.assign(kMlKem768CiphertextBytes, 0x33);
    enc.shared_secret.assign(kMlKem768SharedSecretBytes, 0x44);

    mlkem768_wipe_encap_result(&enc);

    if (!expect_true("wipe encap_result clears ciphertext", enc.ciphertext.empty())) {
        return 1;
    }
    if (!expect_true("wipe encap_result clears shared_secret", enc.shared_secret.empty())) {
        return 1;
    }

    // Repeated wipe should remain safe.
    mlkem768_wipe_encap_result(&enc);

    if (!expect_true("repeated wipe encap_result keeps ciphertext empty", enc.ciphertext.empty())) {
        return 1;
    }
    if (!expect_true("repeated wipe encap_result keeps shared_secret empty", enc.shared_secret.empty())) {
        return 1;
    }

    // Wipe standalone shared secret.
    std::vector<std::uint8_t> ss(kMlKem768SharedSecretBytes, 0x55);
    mlkem768_wipe_shared_secret(&ss);

    if (!expect_true("wipe shared_secret clears vector", ss.empty())) {
        return 1;
    }

    // Repeated wipe should remain safe.
    mlkem768_wipe_shared_secret(&ss);

    if (!expect_true("repeated wipe shared_secret keeps vector empty", ss.empty())) {
        return 1;
    }

    std::cout << "[dna-pqcore] secret lifecycle ok\n";
    return 0;
}