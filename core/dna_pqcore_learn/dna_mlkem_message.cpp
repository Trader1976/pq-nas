#include "dna_mlkem_message.h"

#include "dna_mlkem_field.h"

namespace pqnas::dna_pqcore_learn {

    void mlkem_poly_frommsg(std::int16_t coeffs[kMlkemMessageN],
                            const std::uint8_t msg[kMlkemMessageBytes]) {
        for (std::size_t i = 0; i < kMlkemMessageBytes; ++i) {
            const std::uint8_t byte = msg[i];

            for (std::size_t j = 0; j < 8; ++j) {
                const std::uint8_t bit = static_cast<std::uint8_t>((byte >> j) & 1u);
                coeffs[8 * i + j] = bit ? kMlkemMessageOneCoeff : 0;
            }
        }
    }

    void mlkem_poly_tomsg(std::uint8_t msg[kMlkemMessageBytes],
                          const std::int16_t coeffs[kMlkemMessageN]) {
        // Mirrors the usual Kyber/ML-KEM decode threshold:
        //
        //   bit = (((2*c) + q/2) / q) & 1
        //
        // after interpreting c modulo q.
        for (std::size_t i = 0; i < kMlkemMessageBytes; ++i) {
            std::uint8_t byte = 0;

            for (std::size_t j = 0; j < 8; ++j) {
                const std::int16_t c = mlkem_canonicalize_q(coeffs[8 * i + j]);

                const std::uint8_t bit = static_cast<std::uint8_t>(
                    (((static_cast<std::int32_t>(c) << 1) + (kMlkemFieldQ / 2)) / kMlkemFieldQ) & 1
                );

                byte |= static_cast<std::uint8_t>(bit << j);
            }

            msg[i] = byte;
        }
    }

} // namespace pqnas::dna_pqcore_learn