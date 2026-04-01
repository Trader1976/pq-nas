#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"
#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_noisevec.h"
#include "dna_mlkem_ntt.h"
#include "dna_mlkem_tomont.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] indcpa keygen skeleton test failed: " << msg << "\n";
    return false;
}

bool poly_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

std::int32_t poly_max_abs(const std::int16_t* a, std::size_t n) {
    std::int32_t m = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const std::int32_t v = a[i];
        const std::int32_t av = (v < 0) ? -v : v;
        if (av > m) m = av;
    }
    return m;
}

bool check_case(const std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes>& rho,
                const std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes>& sigma) {
    std::string err;

    std::int16_t s_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    std::int16_t s_hat_ref[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat_ref[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat_ref[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    std::int16_t a_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t s_std[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_std[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    std::int16_t s_hat_again[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat_again[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat_again[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat, e_hat, t_hat, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("skeleton function failed");
    }

    // Determinism.
    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat_again, e_hat_again, t_hat_again, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("skeleton function repeat failed");
    }

    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        if (!poly_equal(s_hat[j], s_hat_again[j], kMlkemKeygenSkelN)) {
            return fail("s_hat determinism mismatch");
        }
        if (!poly_equal(e_hat[j], e_hat_again[j], kMlkemKeygenSkelN)) {
            return fail("e_hat determinism mismatch");
        }
        if (!poly_equal(t_hat[j], t_hat_again[j], kMlkemKeygenSkelN)) {
            return fail("t_hat determinism mismatch");
        }
    }

    // Independent reference composition using previously tested pieces.
    if (!mlkem_matrix_ntt(a_hat, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("matrix_ntt failed");
    }

    if (!mlkem_noisevec_eta2(s_std, sigma.data(), 0, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(s) failed");
    }

    if (!mlkem_noisevec_eta2(e_std, sigma.data(), 3, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(e) failed");
    }

    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        for (std::size_t i = 0; i < kMlkemKeygenSkelN; ++i) {
            s_hat_ref[j][i] = s_std[j][i];
            e_hat_ref[j][i] = e_std[j][i];
        }

        mlkem_poly_ntt_forward(s_hat_ref[j]);
        mlkem_poly_ntt_forward(e_hat_ref[j]);
    }

    mlkem_matvec_mul_ntt(t_hat_ref, a_hat, s_hat_ref);
    mlkem_vec_tomont(t_hat_ref);

    for (std::size_t row = 0; row < kMlkemKeygenSkelK; ++row) {
        for (std::size_t i = 0; i < kMlkemKeygenSkelN; ++i) {
            t_hat_ref[row][i] =
                static_cast<std::int16_t>(t_hat_ref[row][i] + e_hat_ref[row][i]);
        }
    }

    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        if (!poly_equal(s_hat[j], s_hat_ref[j], kMlkemKeygenSkelN)) {
            return fail("s_hat reference mismatch");
        }
        if (!poly_equal(e_hat[j], e_hat_ref[j], kMlkemKeygenSkelN)) {
            return fail("e_hat reference mismatch");
        }
        if (!poly_equal(t_hat[j], t_hat_ref[j], kMlkemKeygenSkelN)) {
            return fail("t_hat reference mismatch");
        }
    }

    // Sanity bounds: everything should remain far inside int16_t.
    for (std::size_t j = 0; j < kMlkemKeygenSkelK; ++j) {
        if (poly_max_abs(s_hat[j], kMlkemKeygenSkelN) >= 32768) {
            return fail("s_hat int16 bound violation");
        }
        if (poly_max_abs(e_hat[j], kMlkemKeygenSkelN) >= 32768) {
            return fail("e_hat int16 bound violation");
        }
        if (poly_max_abs(t_hat[j], kMlkemKeygenSkelN) >= 32768) {
            return fail("t_hat int16 bound violation");
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemKeygenSkelK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemKeygenSkelN == 256, "test assumes N = 256");
    static_assert(kMlkemKeygenSkelSeedBytes == 32, "test assumes 32-byte rho/sigma");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> sigma{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
            sigma[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
        }

        if (!check_case(rho, sigma)) return 1;
    }

    // Case 2
    {
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> sigma{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((53u * i + 7u) & 0xFFu);
            sigma[i] = static_cast<std::uint8_t>((19u * i + 201u) & 0xFFu);
        }

        if (!check_case(rho, sigma)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] indcpa keygen skeleton ok"
        << " k=" << kMlkemKeygenSkelK
        << " n=" << kMlkemKeygenSkelN
        << "\n";

    return 0;
}