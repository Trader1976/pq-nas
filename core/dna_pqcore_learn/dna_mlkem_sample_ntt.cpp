#include "dna_mlkem_sample_ntt.h"

#include <array>
#include <vector>

#include <openssl/evp.h>

#include "dna_mlkem_uniform.h"

namespace pqnas::dna_pqcore_learn {
namespace {

// FIPS 203 Appendix B gives 280 iterations as the optional safe bound
// if an implementation chooses to bound the SampleNTT loop.
// Each iteration consumes 3 bytes, so 840 bytes is a strong starting prefix.
// For the learning track we do NOT hard-fail there; we retry with longer
// prefixes if ever needed.
constexpr std::size_t kInitialXofBytes = 280 * 3; // 840
constexpr std::size_t kMaxXofBytes = 1u << 20;    // generous retry ceiling

bool mlkem_shake128_prefix(std::uint8_t* out,
                           std::size_t out_len,
                           const std::uint8_t rho[kMlkemSampleNttSeedBytes],
                           std::uint8_t j,
                           std::uint8_t i,
                           std::string* err) {
    if (out == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

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

} // namespace

bool mlkem_sample_ntt(std::int16_t coeffs[kMlkemSampleNttN],
                      const std::uint8_t rho[kMlkemSampleNttSeedBytes],
                      std::uint8_t j,
                      std::uint8_t i,
                      std::string* err) {
    if (coeffs == nullptr || rho == nullptr) {
        if (err) *err = "null pointer input";
        return false;
    }

    std::size_t xof_bytes = kInitialXofBytes;

    while (xof_bytes <= kMaxXofBytes) {
        std::vector<std::uint8_t> buf(xof_bytes);

        if (!mlkem_shake128_prefix(buf.data(), buf.size(), rho, j, i, err)) {
            return false;
        }

        const std::size_t accepted =
            mlkem_rej_uniform(coeffs, kMlkemSampleNttN, buf.data(), buf.size());

        if (accepted == kMlkemSampleNttN) {
            return true;
        }

        xof_bytes *= 2;
    }

    if (err) {
        *err = "mlkem_sample_ntt could not collect 256 coefficients from XOF stream";
    }
    return false;
}

} // namespace pqnas::dna_pqcore_learn