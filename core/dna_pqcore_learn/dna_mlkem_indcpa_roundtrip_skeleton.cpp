#include "dna_mlkem_indcpa_roundtrip_skeleton.h"

#include "dna_mlkem_indcpa_decrypt_skeleton.h"
#include "dna_mlkem_indcpa_encrypt_skeleton.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"

namespace pqnas::dna_pqcore_learn {

    bool mlkem_indcpa_roundtrip_algebra_skeleton(
        std::int16_t t_hat[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN],
        std::int16_t u[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN],
        std::int16_t v[kMlkemRoundtripSkelN],
        std::int16_t m_poly_dec[kMlkemRoundtripSkelN],
        const std::uint8_t rho[kMlkemRoundtripSkelSeedBytes],
        const std::uint8_t sigma[kMlkemRoundtripSkelSeedBytes],
        const std::uint8_t coins[kMlkemRoundtripSkelSeedBytes],
        const std::int16_t m[kMlkemRoundtripSkelN],
        std::string* err) {
        if (t_hat == nullptr || u == nullptr || v == nullptr || m_poly_dec == nullptr ||
            rho == nullptr || sigma == nullptr || coins == nullptr || m == nullptr) {
            if (err) *err = "null pointer input";
            return false;
            }

        std::int16_t s_hat[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
        std::int16_t e_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};

        std::int16_t r_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
        std::int16_t u_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};

        if (!mlkem_indcpa_keygen_algebra_skeleton(
                s_hat, e_hat_dummy, t_hat, rho, sigma, err)) {
            return false;
                }

        if (!mlkem_indcpa_encrypt_algebra_skeleton(
                r_hat_dummy, u, v, t_hat, rho, coins, m, err)) {
            return false;
                }

        if (!mlkem_indcpa_decrypt_algebra_skeleton(
                u_hat_dummy, m_poly_dec, s_hat, u, v, err)) {
            return false;
                }

        return true;
    }

} // namespace pqnas::dna_pqcore_learn