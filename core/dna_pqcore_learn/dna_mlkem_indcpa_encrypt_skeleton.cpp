#include "dna_mlkem_indcpa_encrypt_skeleton.h"

#include <array>

#include "dna_mlkem_getnoise.h"
#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_noisevec.h"
#include "dna_mlkem_ntt.h"

namespace pqnas::dna_pqcore_learn {

bool mlkem_indcpa_encrypt_algebra_skeleton(
    std::int16_t r_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    std::int16_t u[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    std::int16_t v[kMlkemEncryptSkelN],
    const std::int16_t t_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelN],
    const std::uint8_t rho[kMlkemEncryptSkelSeedBytes],
    const std::uint8_t coins[kMlkemEncryptSkelSeedBytes],
    const std::int16_t m[kMlkemEncryptSkelN],
    std::string* err) {
    if (r_hat == nullptr || u == nullptr || v == nullptr ||
        t_hat == nullptr || rho == nullptr || coins == nullptr || m == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::int16_t at_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t r_std[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t e1[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t e2[kMlkemEncryptSkelN]{};

    std::int16_t u_ntt[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v_ntt[kMlkemEncryptSkelN]{};

    if (!mlkem_matrix_ntt_transposed(at_hat, rho, err)) {
        return false;
    }

    // ML-KEM-768 uses eta1 = 2 and eta2 = 2, so all three noise objects here
    // are generated with eta=2.
    if (!mlkem_noisevec_eta2(r_std, coins, 0, err)) {
        return false;
    }

    if (!mlkem_noisevec_eta2(e1, coins, 3, err)) {
        return false;
    }

    if (!mlkem_getnoise_eta2(e2, coins, 6, err)) {
        return false;
    }

    // r_hat = NTT(r)
    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            r_hat[j][i] = r_std[j][i];
        }
        mlkem_poly_ntt_forward(r_hat[j]);
    }

    // u_ntt = A_hat^T * r_hat
    mlkem_matvec_mul_ntt(u_ntt, at_hat, r_hat);

    // u = invntt_tomont(u_ntt) + e1
    for (std::size_t row = 0; row < kMlkemEncryptSkelK; ++row) {
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            u[row][i] = u_ntt[row][i];
        }

        mlkem_poly_invntt_tomont(u[row]);

        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            u[row][i] = static_cast<std::int16_t>(u[row][i] + e1[row][i]);
        }
    }

    // v_ntt = <t_hat, r_hat>
    mlkem_matvec_mul_row_ntt(v_ntt, t_hat, r_hat);

    // v = invntt_tomont(v_ntt) + e2 + m
    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        v[i] = v_ntt[i];
    }

    mlkem_poly_invntt_tomont(v);

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        v[i] = static_cast<std::int16_t>(v[i] + e2[i] + m[i]);
    }

    return true;
}

} // namespace pqnas::dna_pqcore_learn