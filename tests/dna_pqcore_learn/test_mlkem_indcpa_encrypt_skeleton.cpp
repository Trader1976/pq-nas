#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_getnoise.h"
#include "dna_mlkem_indcpa_encrypt_skeleton.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"
#include "dna_mlkem_matrix_gen.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_noisevec.h"
#include "dna_mlkem_ntt.h"
#include "dna_mlkem_tomont.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] indcpa encrypt skeleton test failed: " << msg << "\n";
    return false;
}

bool poly_equal(const std::int16_t* a, const std::int16_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

std::int16_t ref_canonical64(std::int64_t x) {
    std::int64_t r = x % kMlkemFieldQ;
    if (r < 0) r += kMlkemFieldQ;
    return static_cast<std::int16_t>(r);
}

void naive_negacyclic_mul(std::int16_t out[kMlkemEncryptSkelN],
                          const std::int16_t a[kMlkemEncryptSkelN],
                          const std::int16_t b[kMlkemEncryptSkelN]) {
    std::array<std::int64_t, kMlkemEncryptSkelN> acc{};
    acc.fill(0);

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        const std::int64_t ai = mlkem_canonicalize_q(a[i]);

        for (std::size_t j = 0; j < kMlkemEncryptSkelN; ++j) {
            const std::int64_t bj = mlkem_canonicalize_q(b[j]);
            const std::size_t deg = i + j;

            if (deg < kMlkemEncryptSkelN) {
                acc[deg] += ai * bj;
            } else {
                acc[deg - kMlkemEncryptSkelN] -= ai * bj;
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        out[i] = ref_canonical64(acc[i]);
    }
}

void add_poly_mod_q(std::int16_t acc[kMlkemEncryptSkelN],
                    const std::int16_t addend[kMlkemEncryptSkelN]) {
    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) + static_cast<std::int64_t>(addend[i])
        );
    }
}

void ntt_to_standard_poly(std::int16_t out_std[kMlkemEncryptSkelN],
                          const std::int16_t in_ntt[kMlkemEncryptSkelN]) {
    std::array<std::int16_t, kMlkemEncryptSkelN> tmp{};

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        tmp[i] = in_ntt[i];
    }

    mlkem_poly_invntt_tomont(tmp.data());

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        out_std[i] = mlkem_from_montgomery(tmp[i]);
    }
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

bool check_case(const std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes>& rho,
                const std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes>& sigma,
                const std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes>& coins,
                const std::array<std::int16_t, kMlkemEncryptSkelN>& m) {
    std::string err;

    // First derive a deterministic t_hat using the existing keygen skeleton.
    std::int16_t s_hat_dummy[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat_dummy[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat_dummy, e_hat_dummy, t_hat, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("keygen skeleton setup failed");
    }

    std::int16_t r_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t u[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v[kMlkemEncryptSkelN]{};

    std::int16_t r_hat_ref[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t u_ref[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v_ref[kMlkemEncryptSkelN]{};

    std::int16_t r_hat_again[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t u_again[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v_again[kMlkemEncryptSkelN]{};

    std::int16_t at_hat[kMlkemEncryptSkelK][kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t at_std[kMlkemEncryptSkelK][kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};

    std::int16_t t_std[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};

    std::int16_t r_std[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t e1[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t e2[kMlkemEncryptSkelN]{};

    std::int16_t u_ntt_ref[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v_ntt_ref[kMlkemEncryptSkelN]{};

    std::int16_t tmp_std[kMlkemEncryptSkelN]{};
    std::int16_t expected_u[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t expected_v[kMlkemEncryptSkelN]{};

    if (!mlkem_indcpa_encrypt_algebra_skeleton(
            r_hat, u, v, t_hat, rho.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt skeleton failed");
    }

    if (!mlkem_indcpa_encrypt_algebra_skeleton(
            r_hat_again, u_again, v_again, t_hat, rho.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt skeleton repeat failed");
    }

    // Determinism.
    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        if (!poly_equal(r_hat[j], r_hat_again[j], kMlkemEncryptSkelN)) {
            return fail("r_hat determinism mismatch");
        }
        if (!poly_equal(u[j], u_again[j], kMlkemEncryptSkelN)) {
            return fail("u determinism mismatch");
        }
    }
    if (!poly_equal(v, v_again, kMlkemEncryptSkelN)) {
        return fail("v determinism mismatch");
    }

    // Independent internal reference using previously tested pieces.
    if (!mlkem_matrix_ntt_transposed(at_hat, rho.data(), &err)) {
        std::cerr << err << "\n";
        return fail("matrix_ntt_transposed failed");
    }

    if (!mlkem_noisevec_eta2(r_std, coins.data(), 0, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(r) failed");
    }

    if (!mlkem_noisevec_eta2(e1, coins.data(), 3, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(e1) failed");
    }

    if (!mlkem_getnoise_eta2(e2, coins.data(), 6, &err)) {
        std::cerr << err << "\n";
        return fail("getnoise_eta2(e2) failed");
    }

    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            r_hat_ref[j][i] = r_std[j][i];
        }
        mlkem_poly_ntt_forward(r_hat_ref[j]);
    }

    mlkem_matvec_mul_ntt(u_ntt_ref, at_hat, r_hat_ref);
    for (std::size_t row = 0; row < kMlkemEncryptSkelK; ++row) {
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            u_ref[row][i] = u_ntt_ref[row][i];
        }
        mlkem_poly_invntt_tomont(u_ref[row]);
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            u_ref[row][i] = static_cast<std::int16_t>(u_ref[row][i] + e1[row][i]);
        }
    }

    mlkem_matvec_mul_row_ntt(v_ntt_ref, t_hat, r_hat_ref);
    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        v_ref[i] = v_ntt_ref[i];
    }
    mlkem_poly_invntt_tomont(v_ref);
    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        v_ref[i] = static_cast<std::int16_t>(v_ref[i] + e2[i] + m[i]);
    }

    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        if (!poly_equal(r_hat[j], r_hat_ref[j], kMlkemEncryptSkelN)) {
            return fail("r_hat reference mismatch");
        }
        if (!poly_equal(u[j], u_ref[j], kMlkemEncryptSkelN)) {
            return fail("u reference mismatch");
        }
    }
    if (!poly_equal(v, v_ref, kMlkemEncryptSkelN)) {
        return fail("v reference mismatch");
    }

    // Stronger external algebra check in standard polynomial domain.
    for (std::size_t row = 0; row < kMlkemEncryptSkelK; ++row) {
        for (std::size_t col = 0; col < kMlkemEncryptSkelK; ++col) {
            ntt_to_standard_poly(at_std[row][col], at_hat[row][col]);
        }
    }

    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        ntt_to_standard_poly(t_std[j], t_hat[j]);
    }

    for (std::size_t row = 0; row < kMlkemEncryptSkelK; ++row) {
        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            expected_u[row][i] = mlkem_canonicalize_q(e1[row][i]);
        }

        for (std::size_t col = 0; col < kMlkemEncryptSkelK; ++col) {
            naive_negacyclic_mul(tmp_std, at_std[row][col], r_std[col]);
            add_poly_mod_q(expected_u[row], tmp_std);
        }

        for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
            const std::int16_t actual = mlkem_canonicalize_q(u[row][i]);
            if (actual != expected_u[row][i]) {
                return fail("u external algebra mismatch");
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        expected_v[i] = ref_canonical64(
            static_cast<std::int64_t>(mlkem_canonicalize_q(e2[i])) +
            static_cast<std::int64_t>(mlkem_canonicalize_q(m[i]))
        );
    }

    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        naive_negacyclic_mul(tmp_std, t_std[j], r_std[j]);
        add_poly_mod_q(expected_v, tmp_std);
    }

    for (std::size_t i = 0; i < kMlkemEncryptSkelN; ++i) {
        const std::int16_t actual = mlkem_canonicalize_q(v[i]);
        if (actual != expected_v[i]) {
            return fail("v external algebra mismatch");
        }
    }

    // Sanity bounds.
    for (std::size_t j = 0; j < kMlkemEncryptSkelK; ++j) {
        if (poly_max_abs(r_hat[j], kMlkemEncryptSkelN) >= 32768) {
            return fail("r_hat int16 bound violation");
        }
        if (poly_max_abs(u[j], kMlkemEncryptSkelN) >= 32768) {
            return fail("u int16 bound violation");
        }
    }
    if (poly_max_abs(v, kMlkemEncryptSkelN) >= 32768) {
        return fail("v int16 bound violation");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemEncryptSkelK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemEncryptSkelN == 256, "test assumes N = 256");
    static_assert(kMlkemEncryptSkelSeedBytes == 32, "test assumes 32-byte seeds");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> coins{};
        std::array<std::int16_t, kMlkemEncryptSkelN> m{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>(i);
            sigma[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
            coins[i] = static_cast<std::uint8_t>((53u * i + 7u) & 0xFFu);
        }

        for (std::size_t i = 0; i < m.size(); ++i) {
            m[i] = static_cast<std::int16_t>((static_cast<int>(i % 9) - 4) * 2);
        }

        if (!check_case(rho, sigma, coins, m)) return 1;
    }

    // Case 2
    {
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes> coins{};
        std::array<std::int16_t, kMlkemEncryptSkelN> m{};

        for (std::size_t i = 0; i < rho.size(); ++i) {
            rho[i] = static_cast<std::uint8_t>((19u * i + 201u) & 0xFFu);
            sigma[i] = static_cast<std::uint8_t>((71u * i + 9u) & 0xFFu);
            coins[i] = static_cast<std::uint8_t>((29u * i + 41u) & 0xFFu);
        }

        for (std::size_t i = 0; i < m.size(); ++i) {
            m[i] = static_cast<std::int16_t>((17 * static_cast<int>(i) + 3) % kMlkemFieldQ);
        }

        if (!check_case(rho, sigma, coins, m)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] indcpa encrypt skeleton ok"
        << " k=" << kMlkemEncryptSkelK
        << " n=" << kMlkemEncryptSkelN
        << "\n";

    return 0;
}