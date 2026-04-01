#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "dna_mlkem_field.h"
#include "dna_mlkem_sample_ntt.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

constexpr std::size_t kInitialXofBytes = 280 * 3; // 840
constexpr std::size_t kMaxXofBytes = 1u << 20;

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] sample ntt test failed: " << msg << "\n";
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

bool check_range(const std::array<std::int16_t, kMlkemSampleNttN>& coeffs) {
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] < 0 || coeffs[i] >= kMlkemFieldQ) {
            return false;
        }
    }
    return true;
}

bool ref_shake128_prefix(std::uint8_t* out,
                         std::size_t out_len,
                         const std::uint8_t rho[kMlkemSampleNttSeedBytes],
                         std::uint8_t j,
                         std::uint8_t i,
                         std::string* err) {
    std::array<std::uint8_t, kMlkemSampleNttInputBytes> in{};
    for (std::size_t k = 0; k < kMlkemSampleNttSeedBytes; ++k) {
        in[k] = rho[k];
    }
    in[32] = j;
    in[33] = i;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = true;

    if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex(EVP_shake128) failed";
        ok = false;
    } else if (EVP_DigestUpdate(ctx, in.data(), in.size()) != 1) {
        if (err) *err = "EVP_DigestUpdate failed";
        ok = false;
    } else if (EVP_DigestFinalXOF(ctx, out, out_len) != 1) {
        if (err) *err = "EVP_DigestFinalXOF failed";
        ok = false;
    }

    EVP_MD_CTX_free(ctx);
    return ok;
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

bool ref_sample_ntt(std::int16_t coeffs[kMlkemSampleNttN],
                    const std::uint8_t rho[kMlkemSampleNttSeedBytes],
                    std::uint8_t j,
                    std::uint8_t i,
                    std::string* err) {
    std::size_t xof_bytes = kInitialXofBytes;

    while (xof_bytes <= kMaxXofBytes) {
        std::vector<std::uint8_t> buf(xof_bytes);

        if (!ref_shake128_prefix(buf.data(), buf.size(), rho, j, i, err)) {
            return false;
        }

        const std::size_t accepted =
            ref_rej_uniform(coeffs, kMlkemSampleNttN, buf.data(), buf.size());

        if (accepted == kMlkemSampleNttN) {
            return true;
        }

        xof_bytes *= 2;
    }

    if (err) *err = "reference sample_ntt could not collect 256 coefficients";
    return false;
}

bool check_reference_match(const std::array<std::uint8_t, kMlkemSampleNttSeedBytes>& rho,
                           std::uint8_t j,
                           std::uint8_t i) {
    std::string err;

    std::array<std::int16_t, kMlkemSampleNttN> got{};
    std::array<std::int16_t, kMlkemSampleNttN> exp{};

    if (!mlkem_sample_ntt(got.data(), rho.data(), j, i, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_sample_ntt failed");
    }

    if (!ref_sample_ntt(exp.data(), rho.data(), j, i, &err)) {
        std::cerr << err << "\n";
        return fail("reference sample_ntt failed");
    }

    if (!arrays_equal(got, exp)) return fail("reference mismatch");
    if (!check_range(got)) return fail("range check failed");

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemSampleNttN == 256, "test assumes N = 256");
    static_assert(kMlkemSampleNttSeedBytes == 32, "test assumes 32-byte rho");
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    std::string err;

    // Seed 1: 00 01 02 ... 1f
    std::array<std::uint8_t, kMlkemSampleNttSeedBytes> rho1{};
    for (std::size_t i = 0; i < rho1.size(); ++i) {
        rho1[i] = static_cast<std::uint8_t>(i);
    }

    // Seed 2: deterministic mixed pattern
    std::array<std::uint8_t, kMlkemSampleNttSeedBytes> rho2{};
    for (std::size_t i = 0; i < rho2.size(); ++i) {
        rho2[i] = static_cast<std::uint8_t>((37u * i + 11u) & 0xFFu);
    }

    // Determinism and range: rho1, j=0, i=0
    {
        std::array<std::int16_t, kMlkemSampleNttN> a{};
        std::array<std::int16_t, kMlkemSampleNttN> b{};

        if (!mlkem_sample_ntt(a.data(), rho1.data(), 0, 0, &err)) {
            std::cerr << err << "\n";
            return fail("sample_ntt rho1 0 0 failed");
        }

        if (!mlkem_sample_ntt(b.data(), rho1.data(), 0, 0, &err)) {
            std::cerr << err << "\n";
            return fail("sample_ntt rho1 0 0 repeat failed");
        }

        if (!arrays_equal(a, b)) return fail("determinism mismatch");
        if (!check_range(a)) return fail("range check rho1 0 0 failed");
    }

    // Independent reference checks.
    if (!check_reference_match(rho1, 0, 0)) return 1;
    if (!check_reference_match(rho1, 1, 2)) return 1;
    if (!check_reference_match(rho1, 2, 1)) return 1;
    if (!check_reference_match(rho2, 255, 255)) return 1;
    if (!check_reference_match(rho2, 17, 99)) return 1;

    // j||i order should matter.
    {
        std::array<std::int16_t, kMlkemSampleNttN> a{};
        std::array<std::int16_t, kMlkemSampleNttN> b{};

        if (!mlkem_sample_ntt(a.data(), rho1.data(), 1, 2, &err)) {
            std::cerr << err << "\n";
            return fail("sample_ntt rho1 1 2 failed");
        }

        if (!mlkem_sample_ntt(b.data(), rho1.data(), 2, 1, &err)) {
            std::cerr << err << "\n";
            return fail("sample_ntt rho1 2 1 failed");
        }

        if (arrays_equal(a, b)) return fail("j||i order did not affect output");
    }

    std::cout
        << "[dna-pqcore-learn] sample ntt ok"
        << " q=" << kMlkemFieldQ
        << " n=" << kMlkemSampleNttN
        << "\n";

    return 0;
}