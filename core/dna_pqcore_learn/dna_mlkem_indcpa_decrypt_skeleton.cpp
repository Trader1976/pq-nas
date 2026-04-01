#include "dna_mlkem_indcpa_decrypt_skeleton.h"

#include <array>

#include "dna_mlkem_matvec.h"
#include "dna_mlkem_ntt.h"

namespace pqnas::dna_pqcore_learn {

    bool mlkem_indcpa_decrypt_algebra_skeleton(
        std::int16_t u_hat[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        std::int16_t m_poly[kMlkemDecryptSkelN],
        const std::int16_t s_hat[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        const std::int16_t u[kMlkemDecryptSkelK][kMlkemDecryptSkelN],
        const std::int16_t v[kMlkemDecryptSkelN],
        std::string* err) {
        if (u_hat == nullptr || m_poly == nullptr ||
            s_hat == nullptr || u == nullptr || v == nullptr) {
            if (err) *err = "null pointer input";
            return false;
            }

        std::int16_t w_ntt[kMlkemDecryptSkelN]{};
        std::int16_t w[kMlkemDecryptSkelN]{};

        // u_hat = NTT(u)
        for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
            for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
                u_hat[j][i] = u[j][i];
            }
            mlkem_poly_ntt_forward(u_hat[j]);
        }

        // w_ntt = <s_hat, u_hat>
        mlkem_matvec_mul_row_ntt(w_ntt, s_hat, u_hat);

        // w = invntt_tomont(w_ntt)
        for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
            w[i] = w_ntt[i];
        }
        mlkem_poly_invntt_tomont(w);

        // m' = v - w
        for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
            m_poly[i] = static_cast<std::int16_t>(v[i] - w[i]);
        }

        return true;
    }

} // namespace pqnas::dna_pqcore_learn