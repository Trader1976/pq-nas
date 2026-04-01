#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_cbd.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] cbd test failed: " << msg << "\n";
    return false;
}

std::uint8_t get_bit_lsb_first(const std::uint8_t* bytes, std::size_t bit_index) {
    const std::size_t byte_index = bit_index >> 3;
    const std::size_t bit_in_byte = bit_index & 7u;
    return static_cast<std::uint8_t>((bytes[byte_index] >> bit_in_byte) & 1u);
}

void ref_cbd(std::int16_t* coeffs, const std::uint8_t* bytes, std::size_t eta) {
    for (std::size_t i = 0; i < kMlkemCbdN; ++i) {
        std::int16_t x = 0;
        std::int16_t y = 0;

        const std::size_t base = 2 * i * eta;

        for (std::size_t j = 0; j < eta; ++j) {
            x = static_cast<std::int16_t>(x + get_bit_lsb_first(bytes, base + j));
            y = static_cast<std::int16_t>(y + get_bit_lsb_first(bytes, base + eta + j));
        }

        coeffs[i] = static_cast<std::int16_t>(x - y);
    }
}

bool check_eta2_case(const std::array<std::uint8_t, kMlkemCbdEta2Bytes>& in) {
    std::array<std::int16_t, kMlkemCbdN> got{};
    std::array<std::int16_t, kMlkemCbdN> exp{};

    mlkem_poly_cbd_eta2(got.data(), in.data());
    ref_cbd(exp.data(), in.data(), 2);

    for (std::size_t i = 0; i < kMlkemCbdN; ++i) {
        if (got[i] != exp[i]) return fail("eta2 mismatch");
        if (got[i] < -2 || got[i] > 2) return fail("eta2 range");
    }

    return true;
}

bool check_eta3_case(const std::array<std::uint8_t, kMlkemCbdEta3Bytes>& in) {
    std::array<std::int16_t, kMlkemCbdN> got{};
    std::array<std::int16_t, kMlkemCbdN> exp{};

    mlkem_poly_cbd_eta3(got.data(), in.data());
    ref_cbd(exp.data(), in.data(), 3);

    for (std::size_t i = 0; i < kMlkemCbdN; ++i) {
        if (got[i] != exp[i]) return fail("eta3 mismatch");
        if (got[i] < -3 || got[i] > 3) return fail("eta3 range");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemCbdN == 256, "test assumes N = 256");
    static_assert(kMlkemCbdEta2Bytes == 128, "test assumes eta2 byte count");
    static_assert(kMlkemCbdEta3Bytes == 192, "test assumes eta3 byte count");

    // eta=2 all zero
    {
        std::array<std::uint8_t, kMlkemCbdEta2Bytes> in{};
        if (!check_eta2_case(in)) return 1;
    }

    // eta=2 all ones
    {
        std::array<std::uint8_t, kMlkemCbdEta2Bytes> in{};
        in.fill(0xFFu);
        if (!check_eta2_case(in)) return 1;
    }

    // eta=2 deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemCbdEta2Bytes> in{};
        for (std::size_t i = 0; i < in.size(); ++i) {
            in[i] = static_cast<std::uint8_t>((17u * i + 93u) & 0xFFu);
        }
        if (!check_eta2_case(in)) return 1;
    }

    // eta=3 all zero
    {
        std::array<std::uint8_t, kMlkemCbdEta3Bytes> in{};
        if (!check_eta3_case(in)) return 1;
    }

    // eta=3 all ones
    {
        std::array<std::uint8_t, kMlkemCbdEta3Bytes> in{};
        in.fill(0xFFu);
        if (!check_eta3_case(in)) return 1;
    }

    // eta=3 deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemCbdEta3Bytes> in{};
        for (std::size_t i = 0; i < in.size(); ++i) {
            in[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }
        if (!check_eta3_case(in)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] cbd ok"
        << " eta2_bytes=" << kMlkemCbdEta2Bytes
        << " eta3_bytes=" << kMlkemCbdEta3Bytes
        << "\n";

    return 0;
}