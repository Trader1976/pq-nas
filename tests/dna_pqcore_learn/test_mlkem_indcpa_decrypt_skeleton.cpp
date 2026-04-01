#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_field.h"
#include "dna_mlkem_getnoise.h"
#include "dna_mlkem_indcpa_decrypt_skeleton.h"
#include "dna_mlkem_indcpa_encrypt_skeleton.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"
#include "dna_mlkem_matvec.h"
#include "dna_mlkem_noisevec.h"
#include "dna_mlkem_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] indcpa decrypt skeleton test failed: " << msg << "\n";
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

void naive_negacyclic_mul(std::int16_t out[kMlkemDecryptSkelN],
                          const std::int16_t a[kMlkemDecryptSkelN],
                          const std::int16_t b[kMlkemDecryptSkelN]) {
    std::array<std::int64_t, kMlkemDecryptSkelN> acc{};
    acc.fill(0);

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        const std::int64_t ai = mlkem_canonicalize_q(a[i]);

        for (std::size_t j = 0; j < kMlkemDecryptSkelN; ++j) {
            const std::int64_t bj = mlkem_canonicalize_q(b[j]);
            const std::size_t deg = i + j;

            if (deg < kMlkemDecryptSkelN) {
                acc[deg] += ai * bj;
            } else {
                acc[deg - kMlkemDecryptSkelN] -= ai * bj;
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        out[i] = ref_canonical64(acc[i]);
    }
}

void add_poly_mod_q(std::int16_t acc[kMlkemDecryptSkelN],
                    const std::int16_t addend[kMlkemDecryptSkelN]) {
    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) + static_cast<std::int64_t>(addend[i])
        );
    }
}

void sub_poly_mod_q(std::int16_t acc[kMlkemDecryptSkelN],
                    const std::int16_t subtrahend[kMlkemDecryptSkelN]) {
    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) - static_cast<std::int64_t>(subtrahend[i])
        );
    }
}

void ntt_to_standard_poly(std::int16_t out_std[kMlkemDecryptSkelN],
                          const std::int16_t in_ntt[kMlkemDecryptSkelN]) {
    std::array<std::int16_t, kMlkemDecryptSkelN> tmp{};

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        tmp[i] = in_ntt[i];
    }

    mlkem_poly_invntt_tomont(tmp.data());

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
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

bool check_case(const std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes>& rho,
                const std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes>& sigma,
                const std::array<std::uint8_t, kMlkemEncryptSkelSeedBytes>& coins,
                const std::array<std::int16_t, kMlkemEncryptSkelN>& m) {
    std::string err;

    // Build deterministic keygen algebra objects.
    std::int16_t s_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t e_hat_dummy[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};
    std::int16_t t_hat[kMlkemKeygenSkelK][kMlkemKeygenSkelN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat, e_hat_dummy, t_hat, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("keygen skeleton setup failed");
    }

    // Build deterministic encryption algebra objects.
    std::int16_t r_hat_dummy[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t u[kMlkemEncryptSkelK][kMlkemEncryptSkelN]{};
    std::int16_t v[kMlkemEncryptSkelN]{};

    if (!mlkem_indcpa_encrypt_algebra_skeleton(
            r_hat_dummy, u, v, t_hat, rho.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("encrypt skeleton setup failed");
    }

    std::int16_t u_hat[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t m_poly[kMlkemDecryptSkelN]{};

    std::int16_t u_hat_ref[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t m_poly_ref[kMlkemDecryptSkelN]{};

    std::int16_t u_hat_again[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t m_poly_again[kMlkemDecryptSkelN]{};

    std::int16_t s_std[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t e_std[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t r_std[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t e1[kMlkemDecryptSkelK][kMlkemDecryptSkelN]{};
    std::int16_t e2[kMlkemDecryptSkelN]{};

    std::int16_t tmp_std[kMlkemDecryptSkelN]{};
    std::int16_t expected_external[kMlkemDecryptSkelN]{};

    if (!mlkem_indcpa_decrypt_algebra_skeleton(
            u_hat, m_poly, s_hat, u, v, &err)) {
        std::cerr << err << "\n";
        return fail("decrypt skeleton failed");
    }

    if (!mlkem_indcpa_decrypt_algebra_skeleton(
            u_hat_again, m_poly_again, s_hat, u, v, &err)) {
        std::cerr << err << "\n";
        return fail("decrypt skeleton repeat failed");
    }

    // Determinism.
    for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
        if (!poly_equal(u_hat[j], u_hat_again[j], kMlkemDecryptSkelN)) {
            return fail("u_hat determinism mismatch");
        }
    }
    if (!poly_equal(m_poly, m_poly_again, kMlkemDecryptSkelN)) {
        return fail("m_poly determinism mismatch");
    }

    // Independent internal reference composition.
    for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
        for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
            u_hat_ref[j][i] = u[j][i];
        }
        mlkem_poly_ntt_forward(u_hat_ref[j]);
    }

    mlkem_matvec_mul_row_ntt(m_poly_ref, s_hat, u_hat_ref);
    mlkem_poly_invntt_tomont(m_poly_ref);

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        m_poly_ref[i] = static_cast<std::int16_t>(v[i] - m_poly_ref[i]);
    }

    for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
        if (!poly_equal(u_hat[j], u_hat_ref[j], kMlkemDecryptSkelN)) {
            return fail("u_hat reference mismatch");
        }
    }
    if (!poly_equal(m_poly, m_poly_ref, kMlkemDecryptSkelN)) {
        return fail("m_poly reference mismatch");
    }

    // Stronger external algebra check in standard polynomial domain:
    // m' = m + e2 + <e, r> - <s, e1>
    if (!mlkem_noisevec_eta2(s_std, sigma.data(), 0, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(s) failed");
    }

    if (!mlkem_noisevec_eta2(e_std, sigma.data(), 3, &err)) {
        std::cerr << err << "\n";
        return fail("noisevec_eta2(e) failed");
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

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        expected_external[i] = mlkem_canonicalize_q(m[i]);
    }

    add_poly_mod_q(expected_external, e2);

    for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
        naive_negacyclic_mul(tmp_std, e_std[j], r_std[j]);
        add_poly_mod_q(expected_external, tmp_std);

        naive_negacyclic_mul(tmp_std, s_std[j], e1[j]);
        sub_poly_mod_q(expected_external, tmp_std);
    }

    for (std::size_t i = 0; i < kMlkemDecryptSkelN; ++i) {
        const std::int16_t actual = mlkem_canonicalize_q(m_poly[i]);
        if (actual != expected_external[i]) {
            return fail("external algebra mismatch");
        }
    }

    // Sanity bounds.
    for (std::size_t j = 0; j < kMlkemDecryptSkelK; ++j) {
        if (poly_max_abs(u_hat[j], kMlkemDecryptSkelN) >= 32768) {
            return fail("u_hat int16 bound violation");
        }
    }
    if (poly_max_abs(m_poly, kMlkemDecryptSkelN) >= 32768) {
        return fail("m_poly int16 bound violation");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemDecryptSkelK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemDecryptSkelN == 256, "test assumes N = 256");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> sigma{};
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
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemKeygenSkelSeedBytes> sigma{};
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
        << "[dna-pqcore-learn] indcpa decrypt skeleton ok"
        << " k=" << kMlkemDecryptSkelK
        << " n=" << kMlkemDecryptSkelN
        << "\n";

    return 0;
}