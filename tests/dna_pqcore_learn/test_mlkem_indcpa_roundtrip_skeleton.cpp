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
#include "dna_mlkem_indcpa_roundtrip_skeleton.h"
#include "dna_mlkem_noisevec.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] indcpa roundtrip skeleton test failed: " << msg << "\n";
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

void naive_negacyclic_mul(std::int16_t out[kMlkemRoundtripSkelN],
                          const std::int16_t a[kMlkemRoundtripSkelN],
                          const std::int16_t b[kMlkemRoundtripSkelN]) {
    std::array<std::int64_t, kMlkemRoundtripSkelN> acc{};
    acc.fill(0);

    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        const std::int64_t ai = mlkem_canonicalize_q(a[i]);

        for (std::size_t j = 0; j < kMlkemRoundtripSkelN; ++j) {
            const std::int64_t bj = mlkem_canonicalize_q(b[j]);
            const std::size_t deg = i + j;

            if (deg < kMlkemRoundtripSkelN) {
                acc[deg] += ai * bj;
            } else {
                acc[deg - kMlkemRoundtripSkelN] -= ai * bj;
            }
        }
    }

    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        out[i] = ref_canonical64(acc[i]);
    }
}

void add_poly_mod_q(std::int16_t acc[kMlkemRoundtripSkelN],
                    const std::int16_t addend[kMlkemRoundtripSkelN]) {
    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) + static_cast<std::int64_t>(addend[i])
        );
    }
}

void sub_poly_mod_q(std::int16_t acc[kMlkemRoundtripSkelN],
                    const std::int16_t subtrahend[kMlkemRoundtripSkelN]) {
    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        acc[i] = ref_canonical64(
            static_cast<std::int64_t>(acc[i]) - static_cast<std::int64_t>(subtrahend[i])
        );
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

bool check_case(const std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes>& rho,
                const std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes>& sigma,
                const std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes>& coins,
                const std::array<std::int16_t, kMlkemRoundtripSkelN>& m) {
    std::string err;

    std::int16_t t_hat[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t u[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t v[kMlkemRoundtripSkelN]{};
    std::int16_t m_poly_dec[kMlkemRoundtripSkelN]{};

    std::int16_t t_hat_ref[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t u_ref[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t v_ref[kMlkemRoundtripSkelN]{};
    std::int16_t m_poly_dec_ref[kMlkemRoundtripSkelN]{};

    std::int16_t t_hat_again[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t u_again[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t v_again[kMlkemRoundtripSkelN]{};
    std::int16_t m_poly_dec_again[kMlkemRoundtripSkelN]{};

    std::int16_t s_std[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t e_std[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t r_std[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t e1[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t e2[kMlkemRoundtripSkelN]{};
    std::int16_t tmp_std[kMlkemRoundtripSkelN]{};
    std::int16_t expected_external[kMlkemRoundtripSkelN]{};

    if (!mlkem_indcpa_roundtrip_algebra_skeleton(
            t_hat, u, v, m_poly_dec, rho.data(), sigma.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("roundtrip skeleton failed");
    }

    if (!mlkem_indcpa_roundtrip_algebra_skeleton(
            t_hat_again, u_again, v_again, m_poly_dec_again,
            rho.data(), sigma.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("roundtrip skeleton repeat failed");
    }

    // Determinism.
    for (std::size_t j = 0; j < kMlkemRoundtripSkelK; ++j) {
        if (!poly_equal(t_hat[j], t_hat_again[j], kMlkemRoundtripSkelN)) {
            return fail("t_hat determinism mismatch");
        }
        if (!poly_equal(u[j], u_again[j], kMlkemRoundtripSkelN)) {
            return fail("u determinism mismatch");
        }
    }
    if (!poly_equal(v, v_again, kMlkemRoundtripSkelN)) {
        return fail("v determinism mismatch");
    }
    if (!poly_equal(m_poly_dec, m_poly_dec_again, kMlkemRoundtripSkelN)) {
        return fail("m_poly_dec determinism mismatch");
    }

    // Independent composition using the already-tested skeleton pieces.
    std::int16_t s_hat[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t e_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t r_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};
    std::int16_t u_hat_dummy[kMlkemRoundtripSkelK][kMlkemRoundtripSkelN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat, e_hat_dummy, t_hat_ref, rho.data(), sigma.data(), &err)) {
        std::cerr << err << "\n";
        return fail("independent keygen skeleton failed");
    }

    if (!mlkem_indcpa_encrypt_algebra_skeleton(
            r_hat_dummy, u_ref, v_ref, t_hat_ref, rho.data(), coins.data(), m.data(), &err)) {
        std::cerr << err << "\n";
        return fail("independent encrypt skeleton failed");
    }

    if (!mlkem_indcpa_decrypt_algebra_skeleton(
            u_hat_dummy, m_poly_dec_ref, s_hat, u_ref, v_ref, &err)) {
        std::cerr << err << "\n";
        return fail("independent decrypt skeleton failed");
    }

    for (std::size_t j = 0; j < kMlkemRoundtripSkelK; ++j) {
        if (!poly_equal(t_hat[j], t_hat_ref[j], kMlkemRoundtripSkelN)) {
            return fail("t_hat reference mismatch");
        }
        if (!poly_equal(u[j], u_ref[j], kMlkemRoundtripSkelN)) {
            return fail("u reference mismatch");
        }
    }
    if (!poly_equal(v, v_ref, kMlkemRoundtripSkelN)) {
        return fail("v reference mismatch");
    }
    if (!poly_equal(m_poly_dec, m_poly_dec_ref, kMlkemRoundtripSkelN)) {
        return fail("m_poly_dec reference mismatch");
    }

    // Stronger end-to-end external algebra check:
    // recovered pre-decode message polynomial must satisfy
    //
    //   m' = m + e2 + <e, r> - <s, e1>
    //
    // modulo q in the standard polynomial domain.
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

    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        expected_external[i] = mlkem_canonicalize_q(m[i]);
    }

    add_poly_mod_q(expected_external, e2);

    for (std::size_t j = 0; j < kMlkemRoundtripSkelK; ++j) {
        naive_negacyclic_mul(tmp_std, e_std[j], r_std[j]);
        add_poly_mod_q(expected_external, tmp_std);

        naive_negacyclic_mul(tmp_std, s_std[j], e1[j]);
        sub_poly_mod_q(expected_external, tmp_std);
    }

    for (std::size_t i = 0; i < kMlkemRoundtripSkelN; ++i) {
        const std::int16_t actual = mlkem_canonicalize_q(m_poly_dec[i]);
        if (actual != expected_external[i]) {
            return fail("external roundtrip algebra mismatch");
        }
    }

    // Sanity bounds.
    for (std::size_t j = 0; j < kMlkemRoundtripSkelK; ++j) {
        if (poly_max_abs(t_hat[j], kMlkemRoundtripSkelN) >= 32768) {
            return fail("t_hat int16 bound violation");
        }
        if (poly_max_abs(u[j], kMlkemRoundtripSkelN) >= 32768) {
            return fail("u int16 bound violation");
        }
    }
    if (poly_max_abs(v, kMlkemRoundtripSkelN) >= 32768) {
        return fail("v int16 bound violation");
    }
    if (poly_max_abs(m_poly_dec, kMlkemRoundtripSkelN) >= 32768) {
        return fail("m_poly_dec int16 bound violation");
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemRoundtripSkelK == 3, "test assumes ML-KEM-768 k = 3");
    static_assert(kMlkemRoundtripSkelN == 256, "test assumes N = 256");
    static_assert(kMlkemRoundtripSkelSeedBytes == 32, "test assumes 32-byte seeds");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Case 1
    {
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> coins{};
        std::array<std::int16_t, kMlkemRoundtripSkelN> m{};

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
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> rho{};
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> sigma{};
        std::array<std::uint8_t, kMlkemRoundtripSkelSeedBytes> coins{};
        std::array<std::int16_t, kMlkemRoundtripSkelN> m{};

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
        << "[dna-pqcore-learn] indcpa roundtrip skeleton ok"
        << " k=" << kMlkemRoundtripSkelK
        << " n=" << kMlkemRoundtripSkelN
        << "\n";

    return 0;
}