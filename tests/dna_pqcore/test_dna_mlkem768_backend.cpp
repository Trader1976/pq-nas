#include "dna_mlkem768_backend.h"
#include "internal/dna_mlkem768_backend_diag.h"

#include <iostream>
#include <string>
#include <vector>

using namespace dnanexus::pq;

int main() {
    std::string err;

    std::cout << "[dna-pqcore] backend=" << mlkem768_backend_name()
              << " available=" << (mlkem768_available() ? "yes" : "no")
              << "\n";

    if (!mlkem768_selftest(&err)) {
        std::cerr << "[dna-pqcore] selftest failed: " << err << "\n";
        return 1;
    }

    MlKem768Keypair kp;
    if (!mlkem768_keygen(&kp, &err)) {
        std::cerr << "[dna-pqcore] keygen failed: " << err << "\n";
        return 1;
    }

    MlKem768EncapResult enc;
    if (!mlkem768_encapsulate(kp.public_key, &enc, &err)) {
        std::cerr << "[dna-pqcore] encapsulate failed: " << err << "\n";
        return 1;
    }

    std::vector<std::uint8_t> dec_ss;
    if (!mlkem768_decapsulate(kp.secret_key, enc.ciphertext, &dec_ss, &err)) {
        std::cerr << "[dna-pqcore] decapsulate failed: " << err << "\n";
        return 1;
    }

    if (enc.shared_secret != dec_ss) {
        std::cerr << "[dna-pqcore] shared secret mismatch\n";
        return 1;
    }

    std::cout << "[dna-pqcore] ok"
              << " pk=" << kp.public_key.size()
              << " sk=" << kp.secret_key.size()
              << " ct=" << enc.ciphertext.size()
              << " ss=" << enc.shared_secret.size()
              << "\n";

    if (kp.public_key.size() != kMlKem768PublicKeyBytes ||
        kp.secret_key.size() != kMlKem768SecretKeyBytes ||
        enc.ciphertext.size() != kMlKem768CiphertextBytes ||
        enc.shared_secret.size() != kMlKem768SharedSecretBytes) {
        std::cerr << "[dna-pqcore] size constant mismatch\n";
        return 1;
        }

    return 0;
}