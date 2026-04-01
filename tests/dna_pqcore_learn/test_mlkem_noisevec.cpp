#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_getnoise.h"
#include "dna_mlkem_noisevec.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] noisevec test failed: " << msg << "\n";
    return false;
}

bool poly_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool check_eta2_case(const std::array<std::uint8_t, kMlkemNoiseVecSeedBytes>& seed,
                     std::uint8_t nonce0) {
    std::string err;

    std::int16_t got[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t ref[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t again[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t shifted[kMlkemNoiseVecK][kMlkemNoiseVecN]{};

    if (!mlkem_noisevec_eta2(got, seed.data(), nonce0, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta2 failed");
    }

    for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
        const std::uint8_t nonce =
            static_cast<std::uint8_t>(nonce0 + static_cast<std::uint8_t>(j));

        if (!mlkem_getnoise_eta2(ref[j], seed.data(), nonce, &err)) {
            std::cerr << err << "\n";
            return fail("mlkem_getnoise_eta2 reference failed");
        }

        if (!poly_equal(got[j], ref[j], kMlkemNoiseVecN)) {
            return fail("eta2 composition mismatch");
        }

        for (std::size_t i = 0; i < kMlkemNoiseVecN; ++i) {
            if (got[j][i] < -2 || got[j][i] > 2) {
                return fail("eta2 coefficient range");
            }
        }
    }

    if (!mlkem_noisevec_eta2(again, seed.data(), nonce0, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta2 repeat failed");
    }

    for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
        if (!poly_equal(got[j], again[j], kMlkemNoiseVecN)) {
            return fail("eta2 determinism mismatch");
        }
    }

    if (!mlkem_noisevec_eta2(shifted, seed.data(),
                             static_cast<std::uint8_t>(nonce0 + 1), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta2 shifted nonce failed");
    }

    bool any_diff = false;
    for (std::size_t j = 0; j < kMlkemNoiseVecK && !any_diff; ++j) {
        for (std::size_t i = 0; i < kMlkemNoiseVecN; ++i) {
            if (got[j][i] != shifted[j][i]) {
                any_diff = true;
                break;
            }
        }
    }
    if (!any_diff) return fail("eta2 nonce base did not affect output");

    return true;
}

bool check_eta3_case(const std::array<std::uint8_t, kMlkemNoiseVecSeedBytes>& seed,
                     std::uint8_t nonce0) {
    std::string err;

    std::int16_t got[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t ref[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t again[kMlkemNoiseVecK][kMlkemNoiseVecN]{};
    std::int16_t shifted[kMlkemNoiseVecK][kMlkemNoiseVecN]{};

    if (!mlkem_noisevec_eta3(got, seed.data(), nonce0, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta3 failed");
    }

    for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
        const std::uint8_t nonce =
            static_cast<std::uint8_t>(nonce0 + static_cast<std::uint8_t>(j));

        if (!mlkem_getnoise_eta3(ref[j], seed.data(), nonce, &err)) {
            std::cerr << err << "\n";
            return fail("mlkem_getnoise_eta3 reference failed");
        }

        if (!poly_equal(got[j], ref[j], kMlkemNoiseVecN)) {
            return fail("eta3 composition mismatch");
        }

        for (std::size_t i = 0; i < kMlkemNoiseVecN; ++i) {
            if (got[j][i] < -3 || got[j][i] > 3) {
                return fail("eta3 coefficient range");
            }
        }
    }

    if (!mlkem_noisevec_eta3(again, seed.data(), nonce0, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta3 repeat failed");
    }

    for (std::size_t j = 0; j < kMlkemNoiseVecK; ++j) {
        if (!poly_equal(got[j], again[j], kMlkemNoiseVecN)) {
            return fail("eta3 determinism mismatch");
        }
    }

    if (!mlkem_noisevec_eta3(shifted, seed.data(),
                             static_cast<std::uint8_t>(nonce0 + 1), &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_noisevec_eta3 shifted nonce failed");
    }

    bool any_diff = false;
    for (std::size_t j = 0; j < kMlkemNoiseVecK && !any_diff; ++j) {
        for (std::size_t i = 0; i < kMlkemNoiseVecN; ++i) {
            if (got[j][i] != shifted[j][i]) {
                any_diff = true;
                break;
            }
        }
    }
    if (!any_diff) return fail("eta3 nonce base did not affect output");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemNoiseVecK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemNoiseVecN == 256, "test assumes N = 256");
    static_assert(kMlkemNoiseVecSeedBytes == 32, "test assumes 32-byte seed");

    // Seed 1: 00 01 02 ... 1f
    {
        std::array<std::uint8_t, kMlkemNoiseVecSeedBytes> seed{};
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<std::uint8_t>(i);
        }

        if (!check_eta2_case(seed, 0)) return 1;
        if (!check_eta2_case(seed, 17)) return 1;
        if (!check_eta3_case(seed, 0)) return 1;
        if (!check_eta3_case(seed, 17)) return 1;
    }

    // Seed 2: deterministic mixed pattern
    {
        std::array<std::uint8_t, kMlkemNoiseVecSeedBytes> seed{};
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        if (!check_eta2_case(seed, 240)) return 1;
        if (!check_eta3_case(seed, 240)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] noisevec ok"
        << " k=" << kMlkemNoiseVecK
        << " n=" << kMlkemNoiseVecN
        << "\n";

    return 0;
}