#include "dna_mlkem_prf.h"

#include <array>

#include <openssl/evp.h>

namespace pqnas::dna_pqcore_learn {
    namespace {

        bool mlkem_shake256_expand(std::uint8_t* out,
                                   std::size_t out_len,
                                   const std::uint8_t seed[kMlkemSymBytes],
                                   std::uint8_t nonce,
                                   std::string* err) {
            if (out == nullptr || seed == nullptr) {
                if (err) *err = "null pointer input";
                return false;
            }

            std::array<std::uint8_t, kMlkemSymBytes + 1> in{};
            for (std::size_t i = 0; i < kMlkemSymBytes; ++i) {
                in[i] = seed[i];
            }
            in[kMlkemSymBytes] = nonce;

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                if (err) *err = "EVP_MD_CTX_new failed";
                return false;
            }

            bool ok = true;

            if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1) {
                if (err) *err = "EVP_DigestInit_ex(EVP_shake256) failed";
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

    bool mlkem_prf_eta2(std::uint8_t out[kMlkemPrfEta2Bytes],
                        const std::uint8_t seed[kMlkemSymBytes],
                        std::uint8_t nonce,
                        std::string* err) {
        return mlkem_shake256_expand(out, kMlkemPrfEta2Bytes, seed, nonce, err);
    }

    bool mlkem_prf_eta3(std::uint8_t out[kMlkemPrfEta3Bytes],
                        const std::uint8_t seed[kMlkemSymBytes],
                        std::uint8_t nonce,
                        std::string* err) {
        return mlkem_shake256_expand(out, kMlkemPrfEta3Bytes, seed, nonce, err);
    }

} // namespace pqnas::dna_pqcore_learn