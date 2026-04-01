#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] ntt layer test failed: " << msg << "\n";
    return false;
}

std::int16_t ref_centered_mod_q(std::int32_t a) {
    std::int16_t r = mlkem_canonicalize_q(a);
    if (r > (kMlkemFieldQ / 2)) {
        r = static_cast<std::int16_t>(r - kMlkemFieldQ);
    }
    return r;
}

std::int16_t ref_fqmul(std::int16_t a, std::int16_t b) {
    const std::int32_t prod =
        static_cast<std::int32_t>(a) * static_cast<std::int32_t>(b);
    return ref_centered_mod_q(mlkem_montgomery_reduce(prod));
}

void ref_ntt_layer(std::array<std::int16_t, kMlkemNttN>& coeffs, unsigned layer) {
    const auto& zetas = mlkem_ntt_zetas();

    const std::size_t k_start = std::size_t{1} << (layer - 1);
    const std::size_t len = kMlkemNttN >> layer;

    std::size_t k = k_start;
    for (std::size_t start = 0; start < kMlkemNttN; start += 2 * len) {
        const std::int16_t zeta = zetas[k++];

        for (std::size_t j = start; j < start + len; ++j) {
            const std::int16_t t = ref_fqmul(coeffs[j + len], zeta);
            const std::int16_t u = coeffs[j];

            coeffs[j] = static_cast<std::int16_t>(u + t);
            coeffs[j + len] = static_cast<std::int16_t>(u - t);
        }
    }
}

bool check_case(const std::array<std::int16_t, kMlkemNttN>& src, unsigned layer) {
    auto got = src;
    auto exp = src;

    mlkem_ntt_layer(got.data(), layer);
    ref_ntt_layer(exp, layer);

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        if (got[i] != exp[i]) {
            return fail("layer output mismatch");
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNttN == 256, "test assumes N = 256");
    static_assert(kMlkemNttZetaCount == 128, "test assumes 128 zetas");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    const auto& zetas = mlkem_ntt_zetas();

    if (zetas[1] != -758) return fail("zetas[1]");
    if (zetas[2] != -359) return fail("zetas[2]");
    if (zetas[3] != -1517) return fail("zetas[3]");
    if (zetas[64] != -1103) return fail("zetas[64]");
    if (zetas[127] != 1628) return fail("zetas[127]");

    // Case 1: small signed pattern, safe for all layers.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
        }

        for (unsigned layer = 1; layer <= 7; ++layer) {
            if (!check_case(coeffs, layer)) return 1;
        }
    }

    // Case 2: wider but still modest signed pattern.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            const int v = static_cast<int>((i * 17 + 5) % 41) - 20;
            coeffs[i] = static_cast<std::int16_t>(v);
        }

        for (unsigned layer = 1; layer <= 7; ++layer) {
            if (!check_case(coeffs, layer)) return 1;
        }
    }

    // Case 3: all zero should stay zero.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (unsigned layer = 1; layer <= 7; ++layer) {
            if (!check_case(coeffs, layer)) return 1;
        }
    }

    // Case 4: alternating values.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((i & 1u) ? 12 : -12);
        }

        for (unsigned layer = 1; layer <= 7; ++layer) {
            if (!check_case(coeffs, layer)) return 1;
        }
    }

    std::cout
        << "[dna-pqcore-learn] ntt layer ok"
        << " layers=7"
        << " first_layer_first_zeta=" << zetas[1]
        << " last_layer_first_zeta=" << zetas[64]
        << "\n";

    return 0;
}
