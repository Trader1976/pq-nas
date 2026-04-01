#include "dna_mlkem_ntt.h"

#include <array>
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
    const auto& zetas = mlkem_ntt_zetas();

    const std::size_t k_start = std::size_t{1} << (layer - 1);
    const std::size_t len = kMlkemNttN >> layer;

    std::size_t k = k_start;
    for (std::size_t start = 0; start < kMlkemNttN; start += 2 * len) {
        const std::int16_t zeta = zetas[k++];
        mlkem_ntt_butterfly_block(coeffs, zeta, start, len);
    }
}

void mlkem_poly_ntt_forward(std::int16_t coeffs[kMlkemNttN]) {
    for (unsigned layer = 1; layer <= 7; ++layer) {
        mlkem_ntt_layer(coeffs, layer);
    }
}

void mlkem_invntt_layer(std::int16_t coeffs[kMlkemNttN], unsigned layer) {
    const auto& zetas = mlkem_ntt_zetas();

    const std::size_t len = kMlkemNttN >> layer;
    std::size_t k = (std::size_t{1} << layer) - 1;

    for (std::size_t start = 0; start < kMlkemNttN; start += 2 * len) {
        const std::int16_t zeta = zetas[k--];

        for (std::size_t j = start; j < start + len; ++j) {
            const std::int16_t t = coeffs[j];
            coeffs[j] = mlkem_barrett_reduce(
                static_cast<std::int16_t>(t + coeffs[j + len])
            );
            coeffs[j + len] = static_cast<std::int16_t>(coeffs[j + len] - t);
            coeffs[j + len] = mlkem_fqmul_signed(coeffs[j + len], zeta);
        }
    }
}

void mlkem_poly_invntt_tomont(std::int16_t coeffs[kMlkemNttN]) {
    for (std::size_t j = 0; j < kMlkemNttN; ++j) {
        coeffs[j] = mlkem_fqmul_signed(coeffs[j], kMlkemInvNttTomontFactor);
    }

    for (unsigned layer = 7; layer > 0; --layer) {
        mlkem_invntt_layer(coeffs, layer);
    }
}

void mlkem_basemul_pair(std::int16_t out_pair[2],
                        const std::int16_t a_pair[2],
                        const std::int16_t b_pair[2],
                        std::int16_t zeta) {
    const std::int16_t t0 = mlkem_fqmul_signed(a_pair[1], b_pair[1]);
    const std::int16_t t1 = mlkem_fqmul_signed(t0, zeta);
    const std::int16_t t2 = mlkem_fqmul_signed(a_pair[0], b_pair[0]);

    const std::int16_t t3 = mlkem_fqmul_signed(a_pair[0], b_pair[1]);
    const std::int16_t t4 = mlkem_fqmul_signed(a_pair[1], b_pair[0]);

    out_pair[0] = static_cast<std::int16_t>(t1 + t2);
    out_pair[1] = static_cast<std::int16_t>(t3 + t4);
}

void mlkem_poly_basemul_montgomery(std::int16_t out_ntt[kMlkemNttN],
                                   const std::int16_t a_ntt[kMlkemNttN],
                                   const std::int16_t b_ntt[kMlkemNttN]) {
    const auto& zetas = mlkem_ntt_zetas();

    for (std::size_t i = 0; i < (kMlkemNttN / 4); ++i) {
        const std::int16_t zeta = zetas[64 + i];

        mlkem_basemul_pair(&out_ntt[4 * i],
                           &a_ntt[4 * i],
                           &b_ntt[4 * i],
                           zeta);

        const std::int16_t neg_zeta = static_cast<std::int16_t>(-zeta);

        mlkem_basemul_pair(&out_ntt[4 * i + 2],
                           &a_ntt[4 * i + 2],
                           &b_ntt[4 * i + 2],
                           neg_zeta);
    }
}

void mlkem_poly_mul_via_ntt(std::int16_t out_std[kMlkemNttN],
                            const std::int16_t a_std[kMlkemNttN],
                            const std::int16_t b_std[kMlkemNttN]) {
    std::array<std::int16_t, kMlkemNttN> a_ntt{};
    std::array<std::int16_t, kMlkemNttN> b_ntt{};

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        a_ntt[i] = a_std[i];
        b_ntt[i] = b_std[i];
    }

    mlkem_poly_ntt_forward(a_ntt.data());
    mlkem_poly_ntt_forward(b_ntt.data());

    mlkem_poly_basemul_montgomery(out_std, a_ntt.data(), b_ntt.data());
    mlkem_poly_invntt_tomont(out_std);
}

} // namespace pqnas::dna_pqcore_learn