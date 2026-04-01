#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_message.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] message test failed: " << msg << "\n";
    return false;
}

template <std::size_t N>
bool bytes_equal(const std::array<std::uint8_t, N>& a,
                 const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool check_roundtrip(const std::array<std::uint8_t, kMlkemMessageBytes>& msg) {
    std::array<std::int16_t, kMlkemMessageN> poly{};
    std::array<std::uint8_t, kMlkemMessageBytes> out{};

    mlkem_poly_frommsg(poly.data(), msg.data());
    mlkem_poly_tomsg(out.data(), poly.data());

    if (!bytes_equal(msg, out)) return fail("message roundtrip mismatch");

    for (std::size_t i = 0; i < poly.size(); ++i) {
        if (!(poly[i] == 0 || poly[i] == kMlkemMessageOneCoeff)) {
            return fail("encoded coefficient not in {0,1665}");
        }
    }

    return true;
}

bool check_decode_mod_q_behavior() {
    std::array<std::uint8_t, kMlkemMessageBytes> msg{};
    std::array<std::int16_t, kMlkemMessageN> poly{};
    std::array<std::uint8_t, kMlkemMessageBytes> out{};

    msg[0] = 0b10101100u;
    msg[1] = 0b01010011u;

    mlkem_poly_frommsg(poly.data(), msg.data());

    // Perturb by multiples of q; decode should be unchanged.
    for (std::size_t i = 0; i < poly.size(); ++i) {
        if ((i % 3) == 0) {
            poly[i] = static_cast<std::int16_t>(poly[i] + kMlkemFieldQ);
        } else if ((i % 3) == 1) {
            poly[i] = static_cast<std::int16_t>(poly[i] - kMlkemFieldQ);
        }
    }

    mlkem_poly_tomsg(out.data(), poly.data());

    if (!bytes_equal(msg, out)) return fail("decode mod-q behavior mismatch");
    return true;
}

} // namespace

int main() {
    static_assert(kMlkemMessageBytes == 32, "test assumes 32-byte message");
    static_assert(kMlkemMessageN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");
    static_assert(kMlkemMessageOneCoeff == 1665, "test assumes (q+1)/2 = 1665");

    // 1) all zero
    {
        std::array<std::uint8_t, kMlkemMessageBytes> msg{};
        if (!check_roundtrip(msg)) return 1;
    }

    // 2) all ones
    {
        std::array<std::uint8_t, kMlkemMessageBytes> msg{};
        msg.fill(0xFFu);
        if (!check_roundtrip(msg)) return 1;
    }

    // 3) alternating pattern
    {
        std::array<std::uint8_t, kMlkemMessageBytes> msg{};
        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((i & 1u) ? 0xAAu : 0x55u);
        }
        if (!check_roundtrip(msg)) return 1;
    }

    // 4) deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemMessageBytes> msg{};
        for (std::size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }
        if (!check_roundtrip(msg)) return 1;
    }

    // 5) decode modulo-q behavior
    if (!check_decode_mod_q_behavior()) return 1;

    std::cout
        << "[dna-pqcore-learn] message ok"
        << " msg_bytes=" << kMlkemMessageBytes
        << " one_coeff=" << kMlkemMessageOneCoeff
        << "\n";

    return 0;
}