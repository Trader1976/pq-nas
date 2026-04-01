#include "dna_mlkem_matvec.h"

#include <array>
#include <climits>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

namespace pqnas::dna_pqcore_learn {
    namespace {

        static_assert(kMlkemMatvecK == 3, "dna_mlkem_matvec assumes ML-KEM-768 k = 3");
        static_assert(kMlkemMatvecN == 256, "dna_mlkem_matvec assumes N = 256");
        static_assert(6 * kMlkemFieldQ < INT16_MAX,
                      "expected row accumulation bound to fit in int16_t");

    } // namespace

    void mlkem_matvec_mul_row_ntt(
        std::int16_t out_ntt[kMlkemMatvecN],
        const std::int16_t row_ntt[kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]) {
        std::array<std::int16_t, kMlkemMatvecN> tmp{};

        mlkem_poly_basemul_montgomery(out_ntt, row_ntt[0], vec_ntt[0]);

        for (std::size_t j = 1; j < kMlkemMatvecK; ++j) {
            mlkem_poly_basemul_montgomery(tmp.data(), row_ntt[j], vec_ntt[j]);

            for (std::size_t i = 0; i < kMlkemMatvecN; ++i) {
                out_ntt[i] = static_cast<std::int16_t>(out_ntt[i] + tmp[i]);
            }
        }
    }

    void mlkem_matvec_mul_ntt(
        std::int16_t out_vec_ntt[kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t matrix_ntt[kMlkemMatvecK][kMlkemMatvecK][kMlkemMatvecN],
        const std::int16_t vec_ntt[kMlkemMatvecK][kMlkemMatvecN]) {
        for (std::size_t row = 0; row < kMlkemMatvecK; ++row) {
            mlkem_matvec_mul_row_ntt(out_vec_ntt[row], matrix_ntt[row], vec_ntt);
        }
    }

} // namespace pqnas::dna_pqcore_learn