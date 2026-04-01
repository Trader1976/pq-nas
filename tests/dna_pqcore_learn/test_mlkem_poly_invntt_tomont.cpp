#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] poly invntt tomont test failed: " << msg << "\n";
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

void ref_invntt_layer(std::array<std::int16_t, kMlkemNttN>& coeffs, unsigned layer) {
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
            coeffs[j + len] = ref_fqmul(coeffs[j + len], zeta);
        }
    }
}

void ref_poly_invntt_tomont(std::array<std::int16_t, kMlkemNttN>& coeffs) {
    for (std::size_t j = 0; j < kMlkemNttN; ++j) {
        coeffs[j] = ref_fqmul(coeffs[j], kMlkemInvNttTomontFactor);
    }

    for (unsigned layer = 7; layer > 0; --layer) {
        ref_invntt_layer(coeffs, layer);
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

bool check_inverse_matches_reference(const std::array<std::int16_t, kMlkemNttN>& src) {
    auto got = src;
    auto exp = src;

    mlkem_poly_invntt_tomont(got.data());
    ref_poly_invntt_tomont(exp);

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        if (got[i] != exp[i]) {
            return fail("inverse output mismatch");
        }
    }

    if (max_abs(got) > 8 * kMlkemFieldQ) {
        return fail("inverse bound exceeded");
    }

    return true;
}

bool check_roundtrip_to_mont(const std::array<std::int16_t, kMlkemNttN>& src) {
    auto got = src;

    mlkem_poly_ntt_forward(got.data());
    mlkem_poly_invntt_tomont(got.data());

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        const std::int16_t expected = mlkem_to_montgomery(src[i]);
        const std::int16_t actual = mlkem_canonicalize_q(got[i]);

        if (actual != expected) {
            return fail("roundtrip-to-mont mismatch");
        }
    }

    if (max_abs(got) > 8 * kMlkemFieldQ) {
        return fail("roundtrip bound exceeded");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNttN == 256, "test assumes N = 256");
    static_assert(kMlkemNttZetaCount == 128, "test assumes 128 zetas");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Direct inverse-vs-reference checks on arbitrary int16-ish inputs.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((static_cast<int>(i % 11) - 5) * 7);
        }
        if (!check_inverse_matches_reference(coeffs)) return 1;
    }

    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            const int v = static_cast<int>((i * 29 + 3) % 2001) - 1000;
            coeffs[i] = static_cast<std::int16_t>(v);
        }
        if (!check_inverse_matches_reference(coeffs)) return 1;
    }

    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        if (!check_inverse_matches_reference(coeffs)) return 1;
    }

    // Strong learning check:
    // invntt_tomont(ntt(a)) == to_montgomery(a) coefficient-wise mod q.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 3);
        }
        if (!check_roundtrip_to_mont(coeffs)) return 1;
    }

    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((37 * static_cast<int>(i) + 11) % kMlkemFieldQ);
        }
        if (!check_roundtrip_to_mont(coeffs)) return 1;
    }

    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        coeffs[0] = 1;
        if (!check_roundtrip_to_mont(coeffs)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] poly invntt tomont ok"
        << " factor=" << kMlkemInvNttTomontFactor
        << " bound=" << (8 * kMlkemFieldQ)
        << "\n";

    return 0;
}