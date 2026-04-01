#include "dna_mlkem_params_768.h"

#include <iostream>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    if (kN != 256) return 1;
    if (kQ != 3329) return 1;
    if (kK != 3) return 1;

    if (kPublicKeyBytes != 1184) return 1;
    if (kSecretKeyBytes != 2400) return 1;
    if (kCiphertextBytes != 1088) return 1;

    if (!in_canonical_range(0)) return 1;
    if (!in_canonical_range(kQ - 1)) return 1;
    if (in_canonical_range(kQ)) return 1;

    if (mod_q(0) != 0) return 1;
    if (mod_q(kQ) != 0) return 1;
    if (mod_q(-1) != kQ - 1) return 1;
    if (mod_q(kQ + 5) != 5) return 1;

    std::cout << "[dna-pqcore-learn] params ok"
              << " n=" << kN
              << " q=" << kQ
              << " k=" << kK
              << " pk=" << kPublicKeyBytes
              << " sk=" << kSecretKeyBytes
              << " ct=" << kCiphertextBytes
              << std::endl;

    return 0;
}