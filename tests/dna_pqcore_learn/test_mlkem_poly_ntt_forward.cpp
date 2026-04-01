#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] poly ntt forward test failed: " << msg << "\n";
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

            coeffs[j]       = static_cast<std::int16_t>(u + t);
            coeffs[j + len] = static_cast<std::int16_t>(u - t);
        }
    }
}

void ref_poly_ntt_forward(std::array<std::int16_t, kMlkemNttN>& coeffs) {
    for (unsigned layer = 1; layer <= 7; ++layer) {
        ref_ntt_layer(coeffs, layer);
    }
}

std::int32_t max_abs(const std::array<std::int16_t, kMlkemNttN>& coeffs) {
    std::int32_t m = 0;
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        const std::int32_t v = coeffs[i];
        const std::int32_t a = (v < 0) ? -v : v;
        if (a > m) m = a;
    }
    return m;
}

bool check_case(const std::array<std::int16_t, kMlkemNttN>& src) {
    auto got = src;
    auto exp = src;

    mlkem_poly_ntt_forward(got.data());
    ref_poly_ntt_forward(exp);

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        if (got[i] != exp[i]) {
            return fail("forward NTT output mismatch");
        }
    }

    if (max_abs(got) > 8 * kMlkemFieldQ) {
        return fail("forward NTT bound exceeded");
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
    if (zetas[64] != -1103) return fail("zetas[64]");
    if (zetas[127] != 1628) return fail("zetas[127]");

    // Case 1: all zero.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        if (!check_case(coeffs)) return 1;
    }

    // Case 2: small signed repeating pattern.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
        }
        if (!check_case(coeffs)) return 1;
    }

    // Case 3: canonical unsigned-ish pattern in [0, q).
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((37 * static_cast<int>(i) + 11) % kMlkemFieldQ);
        }
        if (!check_case(coeffs)) return 1;
    }

    // Case 4: alternating small values.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((i & 1u) ? 12 : -12);
        }
        if (!check_case(coeffs)) return 1;
    }

    // Case 5: delta at index 0.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        coeffs[0] = 1;
        if (!check_case(coeffs)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] poly ntt forward ok"
        << " layers=7"
        << " bound=" << (8 * kMlkemFieldQ)
        << "\n";

    return 0;
}