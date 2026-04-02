#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "dna_mlkem_backend_oracle.h"
#include "dna_mlkem_kem.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

constexpr std::size_t kCaseCount = 64;
constexpr std::size_t kMsgVariants = 3;
constexpr std::size_t kTamperVariants = 3;

bool fail_case(std::size_t case_idx, const std::string& stage) {
    std::cerr
        << "[dna-pqcore-learn] kem diff many test failed: "
        << "case=" << case_idx
        << " stage=" << stage
        << "\n";
    return false;
}

template <std::size_t N>
bool bytes_equal(const std::array<std::uint8_t, N>& a,
                 const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

template <std::size_t N>
bool any_diff(const std::array<std::uint8_t, N>& a,
              const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return true;
    }
    return false;
}

template <std::size_t N>
std::array<std::uint8_t, N> make_pattern(std::size_t case_idx, std::uint32_t stream_tag) {
    std::array<std::uint8_t, N> out{};

    // Deterministic but well-mixed byte pattern.
    std::uint32_t x =
        0x9E3779B9u ^
        static_cast<std::uint32_t>(case_idx * 0x45d9f3bu) ^
        (stream_tag * 0x27d4eb2du);

    for (std::size_t i = 0; i < N; ++i) {
        x ^= (x << 13);
        x ^= (x >> 17);
        x ^= (x << 5);
        x += static_cast<std::uint32_t>(0xA5u + 17u * i + 29u * stream_tag);
        out[i] = static_cast<std::uint8_t>(x & 0xFFu);
    }

    return out;
}

bool run_one_case(std::size_t case_idx) {
    std::string err;

    const auto d  = make_pattern<kMlkemKemSeedBytes>(case_idx, 1u);
    const auto z  = make_pattern<kMlkemKemSeedBytes>(case_idx, 2u);
    const auto m0 = make_pattern<kMlkemKemMsgBytes>(case_idx, 10u);
    const auto m1 = make_pattern<kMlkemKemMsgBytes>(case_idx, 11u);
    const auto m2 = make_pattern<kMlkemKemMsgBytes>(case_idx, 12u);

    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_learn{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_learn{};
    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_oracle{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_oracle{};

    if (!mlkem_kem_keypair_derand(pk_learn.data(), sk_learn.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail_case(case_idx, "learn_keypair");
    }

    if (!mlkem_oracle_keypair_derand(pk_oracle.data(), sk_oracle.data(), d.data(), z.data(), &err)) {
        std::cerr << err << "\n";
        return fail_case(case_idx, "oracle_keypair");
    }

    if (!bytes_equal(pk_learn, pk_oracle)) {
        return fail_case(case_idx, "pk_mismatch");
    }

    if (!bytes_equal(sk_learn, sk_oracle)) {
        return fail_case(case_idx, "sk_mismatch");
    }

    const std::array<std::array<std::uint8_t, kMlkemKemMsgBytes>, kMsgVariants> msgs{{m0, m1, m2}};

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> prev_ct{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> prev_ss{};
    bool have_prev = false;

    for (std::size_t msg_idx = 0; msg_idx < kMsgVariants; ++msg_idx) {
        const auto& m = msgs[msg_idx];

        std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_learn{};
        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_learn{};
        std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_oracle{};
        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_oracle{};

        if (!mlkem_kem_encaps_derand(ct_learn.data(), ss_learn.data(), pk_learn.data(), m.data(), &err)) {
            std::cerr << err << "\n";
            return fail_case(case_idx, "learn_encaps_" + std::to_string(msg_idx));
        }

        if (!mlkem_oracle_encaps_derand(ct_oracle.data(), ss_oracle.data(), pk_oracle.data(), m.data(), &err)) {
            std::cerr << err << "\n";
            return fail_case(case_idx, "oracle_encaps_" + std::to_string(msg_idx));
        }

        if (!bytes_equal(ct_learn, ct_oracle)) {
            return fail_case(case_idx, "ct_mismatch_" + std::to_string(msg_idx));
        }

        if (!bytes_equal(ss_learn, ss_oracle)) {
            return fail_case(case_idx, "ss_mismatch_" + std::to_string(msg_idx));
        }

        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_learn{};
        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_oracle{};

        if (!mlkem_kem_decaps(ss_dec_learn.data(), ct_learn.data(), sk_learn.data(), &err)) {
            std::cerr << err << "\n";
            return fail_case(case_idx, "learn_decaps_" + std::to_string(msg_idx));
        }

        if (!mlkem_oracle_decaps(ss_dec_oracle.data(), ct_oracle.data(), sk_oracle.data(), &err)) {
            std::cerr << err << "\n";
            return fail_case(case_idx, "oracle_decaps_" + std::to_string(msg_idx));
        }

        if (!bytes_equal(ss_dec_learn, ss_learn)) {
            return fail_case(case_idx, "learn_decaps_roundtrip_" + std::to_string(msg_idx));
        }

        if (!bytes_equal(ss_dec_oracle, ss_oracle)) {
            return fail_case(case_idx, "oracle_decaps_roundtrip_" + std::to_string(msg_idx));
        }

        if (!bytes_equal(ss_dec_learn, ss_dec_oracle)) {
            return fail_case(case_idx, "decaps_mismatch_" + std::to_string(msg_idx));
        }

        if (have_prev) {
            if (!any_diff(prev_ct, ct_learn)) {
                return fail_case(case_idx, "ciphertext_not_changed_" + std::to_string(msg_idx));
            }
            if (!any_diff(prev_ss, ss_learn)) {
                return fail_case(case_idx, "shared_secret_not_changed_" + std::to_string(msg_idx));
            }
        }

        prev_ct = ct_learn;
        prev_ss = ss_learn;
        have_prev = true;

        // Tamper checks against both implementations.
        const std::array<std::size_t, kTamperVariants> tamper_pos{
            0,
            kMlkemKemCiphertextBytes / 2,
            kMlkemKemCiphertextBytes - 1
        };

        for (std::size_t t = 0; t < kTamperVariants; ++t) {
            std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_tampered = ct_learn;
            ct_tampered[tamper_pos[t]] ^= static_cast<std::uint8_t>(0x01u << (t & 7u));

            std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_learn{};
            std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_oracle{};

            if (!mlkem_kem_decaps(ss_tampered_learn.data(), ct_tampered.data(), sk_learn.data(), &err)) {
                std::cerr << err << "\n";
                return fail_case(case_idx, "learn_tampered_decaps_" + std::to_string(msg_idx) + "_" + std::to_string(t));
            }

            if (!mlkem_oracle_decaps(ss_tampered_oracle.data(), ct_tampered.data(), sk_oracle.data(), &err)) {
                std::cerr << err << "\n";
                return fail_case(case_idx, "oracle_tampered_decaps_" + std::to_string(msg_idx) + "_" + std::to_string(t));
            }

            if (!bytes_equal(ss_tampered_learn, ss_tampered_oracle)) {
                return fail_case(case_idx, "tampered_ss_mismatch_" + std::to_string(msg_idx) + "_" + std::to_string(t));
            }

            if (!any_diff(ss_learn, ss_tampered_learn)) {
                return fail_case(case_idx, "tampered_ss_unchanged_" + std::to_string(msg_idx) + "_" + std::to_string(t));
            }
        }
    }

    return true;
}

} // namespace

int main() {
    static_assert(kMlkemKemPublicKeyBytes == kMlkemOraclePublicKeyBytes,
                  "learn/backend pk size mismatch");
    static_assert(kMlkemKemSecretKeyBytes == kMlkemOracleSecretKeyBytes,
                  "learn/backend sk size mismatch");
    static_assert(kMlkemKemCiphertextBytes == kMlkemOracleCiphertextBytes,
                  "learn/backend ct size mismatch");
    static_assert(kMlkemKemSharedSecretBytes == kMlkemOracleSharedSecretBytes,
                  "learn/backend ss size mismatch");

    for (std::size_t case_idx = 0; case_idx < kCaseCount; ++case_idx) {
        if (!run_one_case(case_idx)) return 1;
    }

    std::cout
        << "[dna-pqcore-learn] kem diff many ok"
        << " cases=" << kCaseCount
        << " msg_variants=" << kMsgVariants
        << " tamper_variants=" << kTamperVariants
        << "\n";

    return 0;
}