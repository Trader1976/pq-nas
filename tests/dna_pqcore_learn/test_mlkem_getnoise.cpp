#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_cbd.h"
#include "dna_mlkem_getnoise.h"
#include "dna_mlkem_prf.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] getnoise test failed: " << msg << "\n";
    return false;
}

template <std::size_t N>
bool arrays_equal(const std::array<std::int16_t, N>& a,
                  const std::array<std::int16_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool check_eta2_case(const std::array<std::uint8_t, kMlkemGetNoiseSeedBytes>& seed,
                     std::uint8_t nonce) {
    std::string err;

    std::array<std::int16_t, kMlkemGetNoiseN> got{};
    std::array<std::int16_t, kMlkemGetNoiseN> exp{};

    std::array<std::uint8_t, kMlkemPrfEta2Bytes> buf{};
    if (!mlkem_prf_eta2(buf.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta2 failed");
    }

    mlkem_poly_cbd_eta2(exp.data(), buf.data());

    if (!mlkem_getnoise_eta2(got.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta2 failed");
    }

    if (!arrays_equal(got, exp)) return fail("eta2 composition mismatch");

    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i] < -2 || got[i] > 2) return fail("eta2 coefficient range");
    }

    // Determinism check.
    std::array<std::int16_t, kMlkemGetNoiseN> again{};
    if (!mlkem_getnoise_eta2(again.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta2 repeat failed");
    }
    if (!arrays_equal(got, again)) return fail("eta2 determinism mismatch");

    // Different nonce should usually change output.
    std::array<std::int16_t, kMlkemGetNoiseN> diff_nonce{};
    if (!mlkem_getnoise_eta2(diff_nonce.data(), seed.data(),
                             static_cast<std::uint8_t>(nonce + 1), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta2 diff nonce failed");
    }

    bool any_diff = false;
    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i] != diff_nonce[i]) {
            any_diff = true;
            break;
        }
    }
    if (!any_diff) return fail("eta2 nonce did not affect output");

    return true;
}

bool check_eta3_case(const std::array<std::uint8_t, kMlkemGetNoiseSeedBytes>& seed,
                     std::uint8_t nonce) {
    std::string err;

    std::array<std::int16_t, kMlkemGetNoiseN> got{};
    std::array<std::int16_t, kMlkemGetNoiseN> exp{};

    std::array<std::uint8_t, kMlkemPrfEta3Bytes> buf{};
    if (!mlkem_prf_eta3(buf.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta3 failed");
    }

    mlkem_poly_cbd_eta3(exp.data(), buf.data());

    if (!mlkem_getnoise_eta3(got.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta3 failed");
    }

    if (!arrays_equal(got, exp)) return fail("eta3 composition mismatch");

    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i] < -3 || got[i] > 3) return fail("eta3 coefficient range");
    }

    // Determinism check.
    std::array<std::int16_t, kMlkemGetNoiseN> again{};
    if (!mlkem_getnoise_eta3(again.data(), seed.data(), nonce, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta3 repeat failed");
    }
    if (!arrays_equal(got, again)) return fail("eta3 determinism mismatch");

    // Different nonce should usually change output.
    std::array<std::int16_t, kMlkemGetNoiseN> diff_nonce{};
    if (!mlkem_getnoise_eta3(diff_nonce.data(), seed.data(),
                             static_cast<std::uint8_t>(nonce + 1), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_getnoise_eta3 diff nonce failed");
    }

    bool any_diff = false;
    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i] != diff_nonce[i]) {
            any_diff = true;
            break;
        }
    }
    if (!any_diff) return fail("eta3 nonce did not affect output");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemGetNoiseN == 256, "test assumes N = 256");
    static_assert(kMlkemGetNoiseSeedBytes == 32, "test assumes 32-byte seed");

    // Seed 1: 00 01 02 ... 1f
    {
        std::array<std::uint8_t, kMlkemGetNoiseSeedBytes> seed{};
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<std::uint8_t>(i);
        }

        if (!check_eta2_case(seed, 7)) return 1;
        if (!check_eta2_case(seed, 19)) return 1;
        if (!check_eta3_case(seed, 7)) return 1;
        if (!check_eta3_case(seed, 19)) return 1;
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemGetNoiseSeedBytes> seed{};
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        if (!check_eta2_case(seed, 0)) return 1;
        if (!check_eta2_case(seed, 255)) return 1;
        if (!check_eta3_case(seed, 0)) return 1;
        if (!check_eta3_case(seed, 255)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] getnoise ok"
        << " seed_bytes=" << kMlkemGetNoiseSeedBytes
        << " n=" << kMlkemGetNoiseN
        << "\n";

    return 0;
}