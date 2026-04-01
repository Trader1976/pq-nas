#include "dna_mlkem_ntt.h"

#include <climits>

#include "dna_mlkem_field.h"

namespace pqnas::dna_pqcore_learn {
namespace {

static_assert(kMlkemNttN == 256, "dna_mlkem_ntt assumes N = 256");
static_assert(kMlkemFieldQ == 3329, "dna_mlkem_ntt assumes q = 3329");
static_assert(kMlkemNttZetaCount == 128, "dna_mlkem_ntt assumes 128 forward zetas");
static_assert(8 * kMlkemFieldQ < INT16_MAX,
              "expected NTT bound growth to stay within int16_t");

// Map to signed-centered representative in [-((q-1)/2), ..., +(q-1)/2].
std::int16_t mlkem_centered_mod_q(std::int32_t a) {
    std::int16_t r = mlkem_canonicalize_q(a);
    if (r > (kMlkemFieldQ / 2)) {
        r = static_cast<std::int16_t>(r - kMlkemFieldQ);
    }
    return r;
}

} // namespace

const std::array<std::int16_t, kMlkemNttZetaCount>& mlkem_ntt_zetas() {
    static const std::array<std::int16_t, kMlkemNttZetaCount> kZetas = {{
        -1044, -758, -359, -1517, 1493, 1422, 287, 202,
        -171, 622, 1577, 182, 962, -1202, -1474, 1468,
        573, -1325, 264, 383, -829, 1458, -1602, -130,
        -681, 1017, 732, 608, -1542, 411, -205, -1571,
        1223, 652, -552, 1015, -1293, 1491, -282, -1544,
        516, -8, -320, -666, -1618, -1162, 126, 1469,
        -853, -90, -271, 830, 107, -1421, -247, -951,
        -398, 961, -1508, -725, 448, -1065, 677, -1275,
        -1103, 430, 555, 843, -1251, 871, 1550, 105,
        422, 587, 177, -235, -291, -460, 1574, 1653,
        -246, 778, 1159, -147, -777, 1483, -602, 1119,
        -1590, 644, -872, 349, 418, 329, -156, -75,
        817, 1097, 603, 610, 1322, -1285, -1465, 384,
        -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
        -1185, -1530, -1278, 794, -1510, -854, -870, 478,
        -108, -308, 996, 991, 958, -1460, 1522, 1628
    }};
    return kZetas;
}

std::int16_t mlkem_fqmul_signed(std::int16_t a, std::int16_t b) {
    const std::int32_t prod =
        static_cast<std::int32_t>(a) * static_cast<std::int32_t>(b);

    return mlkem_centered_mod_q(mlkem_montgomery_reduce(prod));
}

void mlkem_ntt_butterfly_block(std::int16_t coeffs[kMlkemNttN],
                               std::int16_t zeta,
                               std::size_t start,
                               std::size_t len) {
    for (std::size_t j = start; j < start + len; ++j) {
        const std::int16_t t = mlkem_fqmul_signed(coeffs[j + len], zeta);
        const std::int16_t u = coeffs[j];

        coeffs[j + len] = static_cast<std::int16_t>(u - t);
        coeffs[j]       = static_cast<std::int16_t>(u + t);
    }
}

void mlkem_ntt_layer(std::int16_t coeffs[kMlkemNttN], unsigned layer) {
    // Mirrors the clean vendored structure:
    //
    //   k   = 1 << (layer - 1)
    //   len = N >> layer
    //   for start in 0, 2*len, 4*len, ...
    //       zeta = zetas[k++]
    //       butterfly_block(...)
    //
    // Valid layers are 1..7 for N = 256.
    const auto& zetas = mlkem_ntt_zetas();

    const std::size_t k_start = std::size_t{1} << (layer - 1);
    const std::size_t len = kMlkemNttN >> layer;

    std::size_t k = k_start;
    for (std::size_t start = 0; start < kMlkemNttN; start += 2 * len) {
        const std::int16_t zeta = zetas[k++];
        mlkem_ntt_butterfly_block(coeffs, zeta, start, len);
    }
}

} // namespace pqnas::dna_pqcore_learn