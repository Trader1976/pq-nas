#include "dna_mlkem_indcpa_packed.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include "dna_mlkem_field.h"
#include "dna_mlkem_indcpa_decrypt_skeleton.h"
#include "dna_mlkem_indcpa_encrypt_skeleton.h"
#include "dna_mlkem_indcpa_keygen_skeleton.h"
#include "dna_mlkem_message.h"

namespace pqnas::dna_pqcore_learn {
namespace {

constexpr std::size_t kPolyBytes = 384;
constexpr std::size_t kPolyVecBytes = 1152;
constexpr std::size_t kPolyVecDu10Bytes = 960;
constexpr std::size_t kPolyDv4Bytes = 128;

static_assert(kMlkemIndcpaPackedK == 3, "packed flow assumes ML-KEM-768 k = 3");
static_assert(kMlkemIndcpaPackedN == 256, "packed flow assumes N = 256");
static_assert(kMlkemIndcpaSecretKeyBytes == kPolyVecBytes, "unexpected sk bytes");
static_assert(kMlkemIndcpaPublicKeyBytes == kPolyVecBytes + 32, "unexpected pk bytes");
static_assert(kMlkemIndcpaCiphertextBytes == kPolyVecDu10Bytes + kPolyDv4Bytes,
              "unexpected ct bytes");

std::uint16_t canonical_u12(std::int16_t c) {
    return static_cast<std::uint16_t>(mlkem_canonicalize_q(c));
}

void pack_poly12(std::uint8_t out[kPolyBytes],
                 const std::int16_t coeffs[kMlkemIndcpaPackedN]) {
    for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 2); ++i) {
        const std::uint16_t t0 = canonical_u12(coeffs[2 * i + 0]);
        const std::uint16_t t1 = canonical_u12(coeffs[2 * i + 1]);

        out[3 * i + 0] = static_cast<std::uint8_t>(t0 & 0xFFu);
        out[3 * i + 1] = static_cast<std::uint8_t>((t0 >> 8) | ((t1 & 0x0Fu) << 4));
        out[3 * i + 2] = static_cast<std::uint8_t>(t1 >> 4);
    }
}

void unpack_poly12(std::int16_t coeffs[kMlkemIndcpaPackedN],
                   const std::uint8_t in[kPolyBytes]) {
    for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 2); ++i) {
        const std::uint16_t t0 =
            static_cast<std::uint16_t>(in[3 * i + 0]) |
            (static_cast<std::uint16_t>(in[3 * i + 1] & 0x0Fu) << 8);

        const std::uint16_t t1 =
            (static_cast<std::uint16_t>(in[3 * i + 1]) >> 4) |
            (static_cast<std::uint16_t>(in[3 * i + 2]) << 4);

        coeffs[2 * i + 0] = static_cast<std::int16_t>(t0);
        coeffs[2 * i + 1] = static_cast<std::int16_t>(t1);
    }
}

void pack_polyvec12(std::uint8_t out[kPolyVecBytes],
                    const std::int16_t vec[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]) {
    for (std::size_t j = 0; j < kMlkemIndcpaPackedK; ++j) {
        pack_poly12(&out[j * kPolyBytes], vec[j]);
    }
}

void unpack_polyvec12(std::int16_t vec[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                      const std::uint8_t in[kPolyVecBytes]) {
    for (std::size_t j = 0; j < kMlkemIndcpaPackedK; ++j) {
        unpack_poly12(vec[j], &in[j * kPolyBytes]);
    }
}

std::uint16_t compress_du10(std::int16_t c) {
    const std::uint32_t x = canonical_u12(c);
    return static_cast<std::uint16_t>(((x << 10) + (kMlkemFieldQ / 2)) / kMlkemFieldQ) & 0x03FFu;
}

std::int16_t decompress_du10(std::uint16_t t) {
    return static_cast<std::int16_t>((static_cast<std::uint32_t>(t) * kMlkemFieldQ + 512u) >> 10);
}

std::uint8_t compress_dv4(std::int16_t c) {
    const std::uint32_t x = canonical_u12(c);
    return static_cast<std::uint8_t>(((x << 4) + (kMlkemFieldQ / 2)) / kMlkemFieldQ) & 0x0Fu;
}

std::int16_t decompress_dv4(std::uint8_t t) {
    return static_cast<std::int16_t>((static_cast<std::uint32_t>(t) * kMlkemFieldQ + 8u) >> 4);
}

void pack_polyvec_du10(std::uint8_t out[kPolyVecDu10Bytes],
                       const std::int16_t vec[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]) {
    for (std::size_t j = 0; j < kMlkemIndcpaPackedK; ++j) {
        const std::int16_t* poly = vec[j];
        std::uint8_t* dst = &out[j * 320];

        for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 4); ++i) {
            const std::uint16_t t0 = compress_du10(poly[4 * i + 0]);
            const std::uint16_t t1 = compress_du10(poly[4 * i + 1]);
            const std::uint16_t t2 = compress_du10(poly[4 * i + 2]);
            const std::uint16_t t3 = compress_du10(poly[4 * i + 3]);

            dst[5 * i + 0] = static_cast<std::uint8_t>(t0 & 0xFFu);
            dst[5 * i + 1] = static_cast<std::uint8_t>((t0 >> 8) | ((t1 & 0x003Fu) << 2));
            dst[5 * i + 2] = static_cast<std::uint8_t>((t1 >> 6) | ((t2 & 0x000Fu) << 4));
            dst[5 * i + 3] = static_cast<std::uint8_t>((t2 >> 4) | ((t3 & 0x0003u) << 6));
            dst[5 * i + 4] = static_cast<std::uint8_t>(t3 >> 2);
        }
    }
}

void unpack_polyvec_du10(std::int16_t vec[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                         const std::uint8_t in[kPolyVecDu10Bytes]) {
    for (std::size_t j = 0; j < kMlkemIndcpaPackedK; ++j) {
        std::int16_t* poly = vec[j];
        const std::uint8_t* src = &in[j * 320];

        for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 4); ++i) {
            const std::uint16_t t0 =
                static_cast<std::uint16_t>(src[5 * i + 0]) |
                ((static_cast<std::uint16_t>(src[5 * i + 1]) & 0x03u) << 8);

            const std::uint16_t t1 =
                (static_cast<std::uint16_t>(src[5 * i + 1]) >> 2) |
                ((static_cast<std::uint16_t>(src[5 * i + 2]) & 0x0Fu) << 6);

            const std::uint16_t t2 =
                (static_cast<std::uint16_t>(src[5 * i + 2]) >> 4) |
                ((static_cast<std::uint16_t>(src[5 * i + 3]) & 0x3Fu) << 4);

            const std::uint16_t t3 =
                (static_cast<std::uint16_t>(src[5 * i + 3]) >> 6) |
                (static_cast<std::uint16_t>(src[5 * i + 4]) << 2);

            poly[4 * i + 0] = decompress_du10(t0);
            poly[4 * i + 1] = decompress_du10(t1);
            poly[4 * i + 2] = decompress_du10(t2);
            poly[4 * i + 3] = decompress_du10(t3);
        }
    }
}

void pack_poly_dv4(std::uint8_t out[kPolyDv4Bytes],
                   const std::int16_t poly[kMlkemIndcpaPackedN]) {
    for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 2); ++i) {
        const std::uint8_t t0 = compress_dv4(poly[2 * i + 0]);
        const std::uint8_t t1 = compress_dv4(poly[2 * i + 1]);

        out[i] = static_cast<std::uint8_t>(t0 | (t1 << 4));
    }
}

void unpack_poly_dv4(std::int16_t poly[kMlkemIndcpaPackedN],
                     const std::uint8_t in[kPolyDv4Bytes]) {
    for (std::size_t i = 0; i < (kMlkemIndcpaPackedN / 2); ++i) {
        const std::uint8_t byte = in[i];
        poly[2 * i + 0] = decompress_dv4(static_cast<std::uint8_t>(byte & 0x0Fu));
        poly[2 * i + 1] = decompress_dv4(static_cast<std::uint8_t>(byte >> 4));
    }
}

void pack_public_key(std::uint8_t pk[kMlkemIndcpaPublicKeyBytes],
                     const std::int16_t t_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                     const std::uint8_t rho[kMlkemIndcpaPackedSeedBytes]) {
    pack_polyvec12(pk, t_hat);
    for (std::size_t i = 0; i < kMlkemIndcpaPackedSeedBytes; ++i) {
        pk[kPolyVecBytes + i] = rho[i];
    }
}

void unpack_public_key(std::int16_t t_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                       std::uint8_t rho[kMlkemIndcpaPackedSeedBytes],
                       const std::uint8_t pk[kMlkemIndcpaPublicKeyBytes]) {
    unpack_polyvec12(t_hat, pk);
    for (std::size_t i = 0; i < kMlkemIndcpaPackedSeedBytes; ++i) {
        rho[i] = pk[kPolyVecBytes + i];
    }
}

void pack_secret_key(std::uint8_t sk[kMlkemIndcpaSecretKeyBytes],
                     const std::int16_t s_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]) {
    pack_polyvec12(sk, s_hat);
}

void unpack_secret_key(std::int16_t s_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                       const std::uint8_t sk[kMlkemIndcpaSecretKeyBytes]) {
    unpack_polyvec12(s_hat, sk);
}

void pack_ciphertext(std::uint8_t ct[kMlkemIndcpaCiphertextBytes],
                     const std::int16_t u[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                     const std::int16_t v[kMlkemIndcpaPackedN]) {
    pack_polyvec_du10(ct, u);
    pack_poly_dv4(&ct[kPolyVecDu10Bytes], v);
}

void unpack_ciphertext(std::int16_t u[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN],
                       std::int16_t v[kMlkemIndcpaPackedN],
                       const std::uint8_t ct[kMlkemIndcpaCiphertextBytes]) {
    unpack_polyvec_du10(u, ct);
    unpack_poly_dv4(v, &ct[kPolyVecDu10Bytes]);
}

} // namespace

bool mlkem_indcpa_keypair_packed_deterministic(
    std::uint8_t pk[kMlkemIndcpaPublicKeyBytes],
    std::uint8_t sk[kMlkemIndcpaSecretKeyBytes],
    const std::uint8_t rho[kMlkemIndcpaPackedSeedBytes],
    const std::uint8_t sigma[kMlkemIndcpaPackedSeedBytes],
    std::string* err) {
    if (pk == nullptr || sk == nullptr || rho == nullptr || sigma == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::int16_t s_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t e_hat_dummy[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t t_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};

    if (!mlkem_indcpa_keygen_algebra_skeleton(
            s_hat, e_hat_dummy, t_hat, rho, sigma, err)) {
        return false;
    }

    pack_secret_key(sk, s_hat);
    pack_public_key(pk, t_hat, rho);
    return true;
}

bool mlkem_indcpa_encrypt_packed_deterministic(
    std::uint8_t ct[kMlkemIndcpaCiphertextBytes],
    const std::uint8_t pk[kMlkemIndcpaPublicKeyBytes],
    const std::uint8_t coins[kMlkemIndcpaPackedSeedBytes],
    const std::uint8_t msg[kMlkemIndcpaPackedMsgBytes],
    std::string* err) {
    if (ct == nullptr || pk == nullptr || coins == nullptr || msg == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::int16_t t_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::uint8_t rho[kMlkemIndcpaPackedSeedBytes]{};
    std::int16_t m_poly[kMlkemIndcpaPackedN]{};

    std::int16_t r_hat_dummy[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t u[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t v[kMlkemIndcpaPackedN]{};

    unpack_public_key(t_hat, rho, pk);
    mlkem_poly_frommsg(m_poly, msg);

    if (!mlkem_indcpa_encrypt_algebra_skeleton(
            r_hat_dummy, u, v, t_hat, rho, coins, m_poly, err)) {
        return false;
    }

    pack_ciphertext(ct, u, v);
    return true;
}

bool mlkem_indcpa_decrypt_packed_deterministic(
    std::uint8_t msg[kMlkemIndcpaPackedMsgBytes],
    const std::uint8_t sk[kMlkemIndcpaSecretKeyBytes],
    const std::uint8_t ct[kMlkemIndcpaCiphertextBytes],
    std::string* err) {
    if (msg == nullptr || sk == nullptr || ct == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::int16_t s_hat[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t u[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t v[kMlkemIndcpaPackedN]{};

    std::int16_t u_hat_dummy[kMlkemIndcpaPackedK][kMlkemIndcpaPackedN]{};
    std::int16_t m_poly[kMlkemIndcpaPackedN]{};

    unpack_secret_key(s_hat, sk);
    unpack_ciphertext(u, v, ct);

    if (!mlkem_indcpa_decrypt_algebra_skeleton(
            u_hat_dummy, m_poly, s_hat, u, v, err)) {
        return false;
    }

    mlkem_poly_tomsg(msg, m_poly);
    return true;
}

} // namespace pqnas::dna_pqcore_learn