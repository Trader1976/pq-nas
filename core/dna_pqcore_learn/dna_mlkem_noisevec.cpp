#include "dna_mlkem_noisevec.h"

#include "dna_mlkem_getnoise.h"

namespace pqnas::dna_pqcore_learn {

    bool mlkem_noisevec_eta2(
        std::int16_t vec[kMlkemNoiseVecK][kMlkemNoiseVecN],
        const std::uint8_t seed[kMlkemNoiseVecSeedBytes],
        std::uint8_t nonce0,
        std::string* err) {
        if (vec == nullptr || seed == nullptr) {
            if (err) *err = "null pointer input";
            return false;
        }

        for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
            const std::uint8_t nonce =
                static_cast<std::uint8_t>(nonce0 + static_cast<std::uint8_t>(j));

            if (!mlkem_getnoise_eta2(vec[j], seed, nonce, err)) {
                return false;
            }
        }

        return true;
    }

    bool mlkem_noisevec_eta3(
        std::int16_t vec[kMlkemNoiseVecK][kMlkemNoiseVecN],
        const std::uint8_t seed[kMlkemNoiseVecSeedBytes],
        std::uint8_t nonce0,
        std::string* err) {
        if (vec == nullptr || seed == nullptr) {
            if (err) *err = "null pointer input";
            return false;
        }

        for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
            const std::uint8_t nonce =
                static_cast<std::uint8_t>(nonce0 + static_cast<std::uint8_t>(j));

            if (!mlkem_getnoise_eta3(vec[j], seed, nonce, err)) {
                return false;
            }
        }

        return true;
    }

} // namespace pqnas::dna_pqcore_learn