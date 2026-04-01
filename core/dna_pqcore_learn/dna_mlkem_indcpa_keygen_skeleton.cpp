#include "dna_mlkem_indcpa_keygen_skeleton.h"

#include <array>

#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_noisevec.h"
#include "dna_mlkem_ntt.h"
#include "dna_mlkem_tomont.h"

namespace pqnas::dna_pqcore_learn {

bool mlkem_indcpa_keygen_algebra_skeleton(
    std::int16_t s_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
    std::int16_t e_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
    std::int16_t t_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN],
    const std::uint8_t rho[kMlkemKeygenSkelSeedBytes],
    const std::uint8_t sigma[kMlkemKeygenSkelSeedBytes],
    std::string* err) {
    if (s_hat == nullptr || e_hat == nullptr || t_hat == nullptr ||
        rho == nullptr || sigma == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::int16_t a_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t s_std[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_std[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    if (!mlkem_matrix_ntt(a_hat, rho, err)) {
        return false;
    }

    // ML-KEM-768 uses eta1 = 2 in key generation for both s and e.
    if (!mlkem_noisevec_eta2(s_std, sigma, 0, err)) {
        return false;
    }

    if (!mlkem_noisevec_eta2(e_std, sigma, 3, err)) {
        return false;
    }

    // Copy to the output buffers, then move them into the NTT domain.
    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        for (std::size_t i = 0; i < kMlkemKeygenSkelN; ++i) {
            s_hat[j][i] = s_std[j][i];
            e_hat[j][i] = e_std[j][i];
        }

        mlkem_poly_ntt_forward(s_hat[j]);
        mlkem_poly_ntt_forward(e_hat[j]);
    }

    // t_hat = tomont(A_hat * s_hat) + e_hat
    mlkem_matvec_mul_ntt(t_hat, a_hat, s_hat);
    mlkem_vec_tomont(t_hat);

    for (std::size_t row = 0; row < kMlkemKeygenSkelK; ++row) {
        for (std::size_t i = 0; i < kMlkemKeygenSkelN; ++i) {
            t_hat[row][i] = static_cast<std::int16_t>(t_hat[row][i] + e_hat[row][i]);
        }
    }

    return true;
}

} // namespace pqnas::dna_pqcore_learn