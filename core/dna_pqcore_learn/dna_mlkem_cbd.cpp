#include "dna_mlkem_cbd.h"

namespace pqnas::dna_pqcore_learn {
namespace {

static_assert(kMlkemCbdN == 256, "CBD layer assumes N = 256");

// Little-endian helpers, matching the usual Kyber / ML-KEM reference style.
std::uint32_t load32_le(const std::uint8_t in[4]) {
    return
        (static_cast<std::uint32_t>(in[0]) << 0)  |
        (static_cast<std::uint32_t>(in[1]) << 8)  |
        (static_cast<std::uint32_t>(in[2]) << 16) |
        (static_cast<std::uint32_t>(in[3]) << 24);
}

std::uint32_t load24_le(const std::uint8_t in[3]) {
    return
        (static_cast<std::uint32_t>(in[0]) << 0)  |
        (static_cast<std::uint32_t>(in[1]) << 8)  |
        (static_cast<std::uint32_t>(in[2]) << 16);
}

} // namespace

void mlkem_poly_cbd_eta2(std::int16_t coeffs[kMlkemCbdN],
                         const std::uint8_t bytes[kMlkemCbdEta2Bytes]) {
    // Standard bit-sliced eta=2 decoding.
    //
    // Every 4 input bytes produce 8 coefficients.
    for (std::size_t i = 0; i < (kMlkemCbdN / 8); ++i) {
        const std::uint32_t t = load32_le(&bytes[4 * i]);

        std::uint32_t d = t & 0x55555555u;
        d += (t >> 1) & 0x55555555u;

        for (std::size_t j = 0; j < 8; ++j) {
            const std::int16_t a =
                static_cast<std::int16_t>((d >> (4 * j + 0)) & 0x3u);
            const std::int16_t b =
                static_cast<std::int16_t>((d >> (4 * j + 2)) & 0x3u);

            coeffs[8 * i + j] = static_cast<std::int16_t>(a - b);
        }
    }
}

void mlkem_poly_cbd_eta3(std::int16_t coeffs[kMlkemCbdN],
                         const std::uint8_t bytes[kMlkemCbdEta3Bytes]) {
    // Standard bit-sliced eta=3 decoding.
    //
    // Every 3 input bytes produce 4 coefficients.
    for (std::size_t i = 0; i < (kMlkemCbdN / 4); ++i) {
        const std::uint32_t t = load24_le(&bytes[3 * i]);

        std::uint32_t d = t & 0x00249249u;
        d += (t >> 1) & 0x00249249u;
        d += (t >> 2) & 0x00249249u;

        for (std::size_t j = 0; j < 4; ++j) {
            const std::int16_t a =
                static_cast<std::int16_t>((d >> (6 * j + 0)) & 0x7u);
            const std::int16_t b =
                static_cast<std::int16_t>((d >> (6 * j + 3)) & 0x7u);

            coeffs[4 * i + j] = static_cast<std::int16_t>(a - b);
        }
    }
}

} // namespace pqnas::dna_pqcore_learn