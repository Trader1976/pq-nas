#include "dna_mlkem_getnoise.h"

#include <array>

#include "dna_mlkem_cbd.h"
#include "dna_mlkem_prf.h"

namespace pqnas::dna_pqcore_learn {

    bool mlkem_getnoise_eta2(std::int16_t coeffs[kMlkemGetNoiseN],
                             const std::uint8_t seed[kMlkemGetNoiseSeedBytes],
                             std::uint8_t nonce,
                             std::string* err) {
        if (coeffs == nullptr || seed == nullptr) {
            if (err) *err = "null pointer input";
            return false;
        }

        std::array<std::uint8_t, kMlkemPrfEta2Bytes> buf{};
        if (!mlkem_prf_eta2(buf.data(), seed, nonce, err)) {
            return false;
        }

        mlkem_poly_cbd_eta2(coeffs, buf.data());
        return true;
    }

    bool mlkem_getnoise_eta3(std::int16_t coeffs[kMlkemGetNoiseN],
                             const std::uint8_t seed[kMlkemGetNoiseSeedBytes],
                             std::uint8_t nonce,
                             std::string* err) {
        if (coeffs == nullptr || seed == nullptr) {
            if (err) *err = "null pointer input";
            return false;
        }

        std::array<std::uint8_t, kMlkemPrfEta3Bytes> buf{};
        if (!mlkem_prf_eta3(buf.data(), seed, nonce, err)) {
            return false;
        }

        mlkem_poly_cbd_eta3(coeffs, buf.data());
        return true;
    }

} // namespace pqnas::dna_pqcore_learn