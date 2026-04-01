#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_uniform.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] uniform rej test failed: " << msg << "\n";
    return false;
}

std::size_t ref_rej_uniform(std::int16_t* coeffs,
                            std::size_t max_coeffs,
                            const std::uint8_t* bytes,
                            std::size_t bytes_len) {
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

bool check_case(const std::uint8_t* bytes,
                std::size_t bytes_len,
                std::size_t max_coeffs) {
    std::array<std::int16_t, 512> got{};
    std::array<std::int16_t, 512> exp{};

    const std::size_t got_n = mlkem_rej_uniform(got.data(), max_coeffs, bytes, bytes_len);
    const std::size_t exp_n = ref_rej_uniform(exp.data(), max_coeffs, bytes, bytes_len);

    if (got_n != exp_n) return fail("accepted count mismatch");

    for (std::size_t i = 0; i < got_n; ++i) {
        if (got[i] != exp[i]) return fail("accepted coefficient mismatch");
        if (got[i] < 0 || got[i] >= kMlkemFieldQ) return fail("coefficient out of range");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemUniformN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // 1) three zero bytes -> two accepted zeros
    {
        const std::array<std::uint8_t, 3> in{{0x00u, 0x00u, 0x00u}};
        if (!check_case(in.data(), in.size(), 8)) return 1;

        std::array<std::int16_t, 8> out{};
        const std::size_t n = mlkem_rej_uniform(out.data(), out.size(), in.data(), in.size());
        if (n != 2) return fail("zero case count");
        if (out[0] != 0 || out[1] != 0) return fail("zero case values");
    }

    // 2) three 0xff bytes -> both 12-bit candidates are 4095 -> both rejected
    {
        const std::array<std::uint8_t, 3> in{{0xFFu, 0xFFu, 0xFFu}};
        if (!check_case(in.data(), in.size(), 8)) return 1;

        std::array<std::int16_t, 8> out{};
        const std::size_t n = mlkem_rej_uniform(out.data(), out.size(), in.data(), in.size());
        if (n != 0) return fail("all-ff case count");
    }

    // 3) mixed reject/accept:
    //    d1 = 0xD01 = 3329 -> rejected
    //    d2 = 0x005 = 5    -> accepted
    {
        const std::array<std::uint8_t, 3> in{{0x01u, 0x5Du, 0x00u}};
        if (!check_case(in.data(), in.size(), 8)) return 1;

        std::array<std::int16_t, 8> out{};
        const std::size_t n = mlkem_rej_uniform(out.data(), out.size(), in.data(), in.size());
        if (n != 1) return fail("mixed reject/accept count");
        if (out[0] != 5) return fail("mixed reject/accept value");
    }

    // 4) truncation by max_coeffs
    {
        const std::array<std::uint8_t, 6> in{{0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u}};
        if (!check_case(in.data(), in.size(), 1)) return 1;

        std::array<std::int16_t, 8> out{};
        const std::size_t n = mlkem_rej_uniform(out.data(), 1, in.data(), in.size());
        if (n != 1) return fail("truncation count");
        if (out[0] != 0) return fail("truncation value");
    }

    // 5) deterministic larger buffer
    {
        std::array<std::uint8_t, 513> in{};
        for (std::size_t i = 0; i < in.size(); ++i) {
            in[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }

        if (!check_case(in.data(), in.size(), 256)) return 1;
        if (!check_case(in.data(), in.size(), 37)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] uniform rej ok"
        << " q=" << kMlkemFieldQ
        << " n=" << kMlkemUniformN
        << "\n";

    return 0;
}