#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "dna_mlkem_field.h"
#include "dna_mlkem_ntt_constants.h"
#include "dna_mlkem_params_768.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] ntt constants test failed: " << msg << "\n";
    return false;
}

} // namespace

int main() {
    static_assert(kMlkemFieldQ == 3329, "test assumes q = 3329");

    // Basic 7-bit bit-reversal sanity.
    if (mlkem_brv7(0) != 0) return fail("brv7(0)");
    if (mlkem_brv7(1) != 64) return fail("brv7(1)");
    if (mlkem_brv7(2) != 32) return fail("brv7(2)");
    if (mlkem_brv7(3) != 96) return fail("brv7(3)");
    if (mlkem_brv7(64) != 1) return fail("brv7(64)");
    if (mlkem_brv7(127) != 127) return fail("brv7(127)");

    // Centered representative sanity.
    if (mlkem_centered_mod_q(0) != 0) return fail("centered 0");
    if (mlkem_centered_mod_q(1) != 1) return fail("centered 1");
    if (mlkem_centered_mod_q(kMlkemFieldQ - 1) != -1) return fail("centered q-1");
    if (mlkem_centered_mod_q(kMlkemFieldQ + 5) != 5) return fail("centered q+5");
    if (mlkem_centered_mod_q(-1) != -1) return fail("centered -1");

    const auto& zetas = mlkem_ntt_zetas();

    if (zetas.size() != kMlkemNttZetaCount) return fail("zetas size");
    if (zetas.front() != -1044) return fail("zetas[0]");
    if (zetas.back() != 1628) return fail("zetas[127]");

    // Reconstruct the published zeta table from:
    //   tmp[0] = R mod q
    //   tmp[i] = fqmul(tmp[i-1], R*root mod q)
    // and then taking tmp[brv7(i)] in centered form.
    //
    // Here fqmul is Montgomery multiplication because tmp entries stay
    // in Montgomery domain the whole time.
    std::array<std::int16_t, kMlkemNttZetaCount> tmp{};
    tmp[0] = static_cast<std::int16_t>(kMlkemMontgomeryRModQ);

    const std::int16_t factor = mlkem_canonicalize_q(
        static_cast<std::int32_t>(kMlkemNttRootOfUnity) * kMlkemMontgomeryRModQ
    );

    for (std::size_t i = 1; i < tmp.size(); ++i) {
        tmp[i] = mlkem_montgomery_mul(tmp[i - 1], factor);
    }

    for (std::size_t i = 0; i < zetas.size(); ++i) {
        const std::uint8_t idx = mlkem_brv7(static_cast<std::uint8_t>(i));
        const std::int16_t expected = mlkem_centered_mod_q(tmp[idx]);

        if (zetas[i] != expected) {
            return fail("zeta reconstruction mismatch");
        }
    }

    // Also verify every published zeta is a valid nonzero residue mod q.
    for (std::size_t i = 0; i < zetas.size(); ++i) {
        const std::int16_t c = mlkem_canonicalize_q(zetas[i]);
        if (c < 0 || c >= kMlkemFieldQ) return fail("zeta canonical range");
        if (c == 0) return fail("zeta zero");
    }

    std::cout
        << "[dna-pqcore-learn] ntt constants ok"
        << " zetas=" << zetas.size()
        << " root=" << kMlkemNttRootOfUnity
        << " inv_factor=" << kMlkemInvNttFinalFactor
        << "\n";

    return 0;
}