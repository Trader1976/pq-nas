#include "dna_mlkem_uniform.h"

#include "dna_mlkem_field.h"

namespace pqnas::dna_pqcore_learn {

    std::size_t mlkem_rej_uniform(std::int16_t* coeffs,
                                  std::size_t max_coeffs,
                                  const std::uint8_t* bytes,
                                  std::size_t bytes_len) {
        if (coeffs == nullptr || bytes == nullptr || max_coeffs == 0) {
            return 0;
        }

        std::size_t ctr = 0;
        std::size_t pos = 0;

        while (ctr < max_coeffs && (pos + 3) <= bytes_len) {
            const std::uint16_t d1 =
                static_cast<std::uint16_t>(bytes[pos + 0]) |
                (static_cast<std::uint16_t>(bytes[pos + 1] & 0x0Fu) << 8);

            const std::uint16_t d2 =
                (static_cast<std::uint16_t>(bytes[pos + 1]) >> 4) |
                (static_cast<std::uint16_t>(bytes[pos + 2]) << 4);

            pos += 3;

            if (d1 < static_cast<std::uint16_t>(kMlkemFieldQ)) {
                coeffs[ctr++] = static_cast<std::int16_t>(d1);
            }

            if (ctr < max_coeffs &&
                d2 < static_cast<std::uint16_t>(kMlkemFieldQ)) {
                coeffs[ctr++] = static_cast<std::int16_t>(d2);
                }
        }

        return ctr;
    }

} // namespace pqnas::dna_pqcore_learn