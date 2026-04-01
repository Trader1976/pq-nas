#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] ntt butterfly test failed: " << msg << "\n";
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

bool check_block_case(std::array<std::int16_t, kMlkemNttN> input,
                      std::int16_t zeta,
                      std::size_t start,
                      std::size_t len) {
    const auto before = input;

    mlkem_ntt_butterfly_block(input.data(), zeta, start, len);

    for (std::size_t i = 0; i < kMlkemNttN; ++i) {
        const bool in_left  = (i >= start && i < start + len);
        const bool in_right = (i >= start + len && i < start + 2 * len);

        if (!in_left && !in_right) {
            if (input[i] != before[i]) {
                return fail("untouched coefficient changed");
            }
        }
    }

    for (std::size_t j = start; j < start + len; ++j) {
        const std::int16_t t = ref_fqmul(before[j + len], zeta);
        const std::int16_t expected_lo =
            static_cast<std::int16_t>(before[j] + t);
        const std::int16_t expected_hi =
            static_cast<std::int16_t>(before[j] - t);

        if (input[j] != expected_lo) {
            return fail("left butterfly output mismatch");
        }
        if (input[j + len] != expected_hi) {
            return fail("right butterfly output mismatch");
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

    if (zetas.size() != kMlkemNttZetaCount) return fail("zeta size");
    if (zetas[0] != -1044) return fail("zetas[0]");
    if (zetas[1] != -758) return fail("zetas[1]");
    if (zetas[64] != -1103) return fail("zetas[64]");
    if (zetas[127] != 1628) return fail("zetas[127]");

    // Basic fqmul sanity against explicit reference.
    for (std::int16_t a = -2000; a <= 2000; a += 257) {
        for (std::int16_t b = -1664; b <= 1664; b += 193) {
            const auto got = mlkem_fqmul_signed(a, b);
            const auto exp = ref_fqmul(a, b);
            if (got != exp) return fail("fqmul mismatch");
        }
    }

    // Case 1: simple small values, block start=8 len=4.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            coeffs[i] = static_cast<std::int16_t>((static_cast<int>(i % 13) - 6));
        }

        if (!check_block_case(coeffs, zetas[1], 8, 4)) return 1;
    }

    // Case 2: more varied signed values, block start=32 len=8.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            const int v = static_cast<int>((i * 37) % 2001) - 1000;
            coeffs[i] = static_cast<std::int16_t>(v);
        }

        if (!check_block_case(coeffs, zetas[7], 32, 8)) return 1;
    }

    // Case 3: all-zero block stays zero.
    {
        std::array<std::int16_t, kMlkemNttN> coeffs{};
        if (!check_block_case(coeffs, zetas[31], 64, 16)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] ntt butterfly ok"
        << " zetas=" << zetas.size()
        << " first_used=" << zetas[1]
        << "\n";

    return 0;
}