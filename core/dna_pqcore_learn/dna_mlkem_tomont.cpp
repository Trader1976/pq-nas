#include "dna_mlkem_tomont.h"

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

namespace pqnas::dna_pqcore_learn {

    void mlkem_poly_tomont(std::int16_t coeffs[kMlkemTomontN]) {
        // Mirrors the clean ML-KEM / Kyber idea:
        //
        //   fqmul(a, R^2 mod q) = a * R mod q
        //
        // because fqmul() is Montgomery multiplication.
        for (std::size_t i = 0; i < kMlkemTomontN; ++i) {
            coeffs[i] = mlkem_fqmul_signed(coeffs[i],
                                           static_cast<std::int16_t>(kMlkemMontgomeryR2ModQ));
        }
    }

    void mlkem_vec_tomont(std::int16_t vec[kMlkemTomontK][kMlkemTomontN]) {
        for (std::size_t j = 0; j < kMlkemTomontK; ++j) {
            mlkem_poly_tomont(vec[j]);
        }
    }

} // namespace pqnas::dna_pqcore_learn