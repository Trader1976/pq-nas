#include "dna_mlkem768_backend.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pq;

    std::cout << "[dna-pqcore] backend=" << mlkem768_backend_name()
              << " available=" << (mlkem768_available() ? "yes" : "no")
              << std::endl;

    std::string err;
    if (!mlkem768_selftest(&err)) {
        std::cerr << "[dna-pqcore] selftest failed";
        if (!err.empty()) std::cerr << " detail=" << err;
        std::cerr << std::endl;
        return 1;
    }

    MlKem768Keypair kp;
    if (!mlkem768_keygen(&kp, &err)) {
        std::cerr << "[dna-pqcore] keygen failed: " << err << std::endl;
        return 1;
    }

    MlKem768EncapResult enc;
    if (!mlkem768_encapsulate(kp.public_key, &enc, &err)) {
        std::cerr << "[dna-pqcore] encapsulate failed: " << err << std::endl;
        return 1;
    }

    std::vector<std::uint8_t> dec_ss;
    if (!mlkem768_decapsulate(kp.secret_key, enc.ciphertext, &dec_ss, &err)) {
        std::cerr << "[dna-pqcore] decapsulate failed: " << err << std::endl;
        return 1;
    }

    if (enc.shared_secret != dec_ss) {
        std::cerr << "[dna-pqcore] shared secret mismatch" << std::endl;
        return 1;
    }

    std::cout << "[dna-pqcore] ok"
              << " pk=" << kp.public_key.size()
              << " sk=" << kp.secret_key.size()
              << " ct=" << enc.ciphertext.size()
              << " ss=" << enc.shared_secret.size()
              << std::endl;

    return 0;
}