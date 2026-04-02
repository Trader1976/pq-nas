#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

#include "dna_mlkem_backend_oracle.h"
#include "dna_mlkem_kem.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

constexpr std::uint64_t kDefaultSeed = 0xC0FFEE123456789ULL;
constexpr std::size_t kDefaultCases = 1000;
constexpr std::size_t kDefaultTamperTrialsPerCase = 4;

struct Rng64 {
    std::uint64_t s;

    explicit Rng64(std::uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}

    std::uint64_t next_u64() {
        // xorshift64*
        std::uint64_t x = s;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s = x;
        return x * 2685821657736338717ULL;
    }

    std::uint8_t next_u8() {
        return static_cast<std::uint8_t>(next_u64() & 0xFFu);
    }

    std::size_t next_index(std::size_t limit) {
        if (limit == 0) return 0;
        return static_cast<std::size_t>(next_u64() % static_cast<std::uint64_t>(limit));
    }
};

std::string hex_u64(std::uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

template <std::size_t N>
std::string hex_bytes(const std::array<std::uint8_t, N>& a, std::size_t max_bytes = N) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    const std::size_t shown = (max_bytes < N) ? max_bytes : N;
    for (std::size_t i = 0; i < shown; ++i) {
        if (i) oss << ' ';
        oss << std::setw(2) << static_cast<unsigned>(a[i]);
    }

    if (shown < N) {
        oss << " ...";
    }

    return oss.str();
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
std::size_t first_diff_index(const std::array<std::uint8_t, N>& a,
                             const std::array<std::uint8_t, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a[i] != b[i]) return i;
    }
    return N;
}

template <std::size_t N>
void fill_random(std::array<std::uint8_t, N>& out, Rng64& rng) {
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = rng.next_u8();
    }
}

std::size_t parse_size_arg(const char* s, std::size_t defv) {
    if (s == nullptr || *s == '\0') return defv;

    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 0);
    if (end == nullptr || *end != '\0') return defv;
    if (v == 0) return defv;
    if (v > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) return defv;
    return static_cast<std::size_t>(v);
}

std::uint64_t parse_u64_arg(const char* s, std::uint64_t defv) {
    if (s == nullptr || *s == '\0') return defv;

    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 0);
    if (end == nullptr || *end != '\0') return defv;
    return static_cast<std::uint64_t>(v);
}

[[nodiscard]] bool print_mismatch_header(std::size_t case_idx,
                                         const std::string& stage,
                                         std::uint64_t seed,
                                         const std::array<std::uint8_t, kMlkemKemSeedBytes>& d,
                                         const std::array<std::uint8_t, kMlkemKemSeedBytes>& z,
                                         const std::array<std::uint8_t, kMlkemKemMsgBytes>& m) {
    std::cerr << "[dna-pqcore-learn] kem diff fuzz failed\n";
    std::cerr << "  case          : " << case_idx << "\n";
    std::cerr << "  stage         : " << stage << "\n";
    std::cerr << "  master seed   : " << hex_u64(seed) << "\n";
    std::cerr << "  d             : " << hex_bytes(d) << "\n";
    std::cerr << "  z             : " << hex_bytes(z) << "\n";
    std::cerr << "  m             : " << hex_bytes(m) << "\n";
    return false;
}

template <std::size_t N>
[[nodiscard]] bool report_array_mismatch(
    std::size_t case_idx,
    const std::string& stage,
    std::uint64_t seed,
    const std::array<std::uint8_t, kMlkemKemSeedBytes>& d,
    const std::array<std::uint8_t, kMlkemKemSeedBytes>& z,
    const std::array<std::uint8_t, kMlkemKemMsgBytes>& m,
    const char* lhs_name,
    const std::array<std::uint8_t, N>& lhs,
    const char* rhs_name,
    const std::array<std::uint8_t, N>& rhs) {
    print_mismatch_header(case_idx, stage, seed, d, z, m);

    const std::size_t idx = first_diff_index(lhs, rhs);
    if (idx < N) {
        std::cerr << "  first diff idx: " << idx << "\n";
        std::cerr << "  " << lhs_name << "[" << idx << "]"
                  << "    : 0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(lhs[idx]) << std::dec << "\n";
        std::cerr << "  " << rhs_name << "[" << idx << "]"
                  << "    : 0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(rhs[idx]) << std::dec << "\n";
    }

    std::cerr << "  " << lhs_name << " prefix : " << hex_bytes(lhs, 32) << "\n";
    std::cerr << "  " << rhs_name << " prefix : " << hex_bytes(rhs, 32) << "\n";
    return false;
}

[[nodiscard]] bool report_tamper_mismatch(
    std::size_t case_idx,
    const std::string& stage,
    std::uint64_t seed,
    const std::array<std::uint8_t, kMlkemKemSeedBytes>& d,
    const std::array<std::uint8_t, kMlkemKemSeedBytes>& z,
    const std::array<std::uint8_t, kMlkemKemMsgBytes>& m,
    std::size_t tamper_idx,
    std::uint8_t tamper_mask,
    const std::array<std::uint8_t, kMlkemKemCiphertextBytes>& ct,
    const std::array<std::uint8_t, kMlkemKemSharedSecretBytes>& ss_learn,
    const std::array<std::uint8_t, kMlkemKemSharedSecretBytes>& ss_oracle) {
    print_mismatch_header(case_idx, stage, seed, d, z, m);
    std::cerr << "  tamper idx    : " << tamper_idx << "\n";
    std::cerr << "  tamper mask   : 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(tamper_mask) << std::dec << "\n";
    std::cerr << "  ct prefix     : " << hex_bytes(ct, 32) << "\n";
    std::cerr << "  ss learn      : " << hex_bytes(ss_learn) << "\n";
    std::cerr << "  ss oracle     : " << hex_bytes(ss_oracle) << "\n";
    return false;
}

bool run_one_case(std::size_t case_idx,
                  std::uint64_t master_seed,
                  std::size_t tamper_trials,
                  Rng64& rng) {
    std::string err;

    std::array<std::uint8_t, kMlkemKemSeedBytes> d{};
    std::array<std::uint8_t, kMlkemKemSeedBytes> z{};
    std::array<std::uint8_t, kMlkemKemMsgBytes> m{};

    fill_random(d, rng);
    fill_random(z, rng);
    fill_random(m, rng);

    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_learn{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_learn{};
    std::array<std::uint8_t, kMlkemKemPublicKeyBytes> pk_oracle{};
    std::array<std::uint8_t, kMlkemKemSecretKeyBytes> sk_oracle{};

    if (!mlkem_kem_keypair_derand(pk_learn.data(), sk_learn.data(), d.data(), z.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] learn keypair failed: " << err << "\n";
        return print_mismatch_header(case_idx, "learn_keypair_failed", master_seed, d, z, m);
    }

    if (!mlkem_oracle_keypair_derand(pk_oracle.data(), sk_oracle.data(), d.data(), z.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] oracle keypair failed: " << err << "\n";
        return print_mismatch_header(case_idx, "oracle_keypair_failed", master_seed, d, z, m);
    }

    if (!bytes_equal(pk_learn, pk_oracle)) {
        return report_array_mismatch(case_idx, "public_key_mismatch", master_seed, d, z, m,
                                     "pk_learn", pk_learn, "pk_oracle", pk_oracle);
    }

    if (!bytes_equal(sk_learn, sk_oracle)) {
        return report_array_mismatch(case_idx, "secret_key_mismatch", master_seed, d, z, m,
                                     "sk_learn", sk_learn, "sk_oracle", sk_oracle);
    }

    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_learn{};
    std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_oracle{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_oracle{};

    if (!mlkem_kem_encaps_derand(ct_learn.data(), ss_learn.data(), pk_learn.data(), m.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] learn encaps failed: " << err << "\n";
        return print_mismatch_header(case_idx, "learn_encaps_failed", master_seed, d, z, m);
    }

    if (!mlkem_oracle_encaps_derand(ct_oracle.data(), ss_oracle.data(), pk_oracle.data(), m.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] oracle encaps failed: " << err << "\n";
        return print_mismatch_header(case_idx, "oracle_encaps_failed", master_seed, d, z, m);
    }

    if (!bytes_equal(ct_learn, ct_oracle)) {
        return report_array_mismatch(case_idx, "ciphertext_mismatch", master_seed, d, z, m,
                                     "ct_learn", ct_learn, "ct_oracle", ct_oracle);
    }

    if (!bytes_equal(ss_learn, ss_oracle)) {
        return report_array_mismatch(case_idx, "shared_secret_mismatch", master_seed, d, z, m,
                                     "ss_learn", ss_learn, "ss_oracle", ss_oracle);
    }

    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_learn{};
    std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_dec_oracle{};

    if (!mlkem_kem_decaps(ss_dec_learn.data(), ct_learn.data(), sk_learn.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] learn decaps failed: " << err << "\n";
        return print_mismatch_header(case_idx, "learn_decaps_failed", master_seed, d, z, m);
    }

    if (!mlkem_oracle_decaps(ss_dec_oracle.data(), ct_oracle.data(), sk_oracle.data(), &err)) {
        std::cerr << "[dna-pqcore-learn] oracle decaps failed: " << err << "\n";
        return print_mismatch_header(case_idx, "oracle_decaps_failed", master_seed, d, z, m);
    }

    if (!bytes_equal(ss_dec_learn, ss_learn)) {
        return report_array_mismatch(case_idx, "learn_decaps_roundtrip_mismatch", master_seed, d, z, m,
                                     "ss_dec_learn", ss_dec_learn, "ss_learn", ss_learn);
    }

    if (!bytes_equal(ss_dec_oracle, ss_oracle)) {
        return report_array_mismatch(case_idx, "oracle_decaps_roundtrip_mismatch", master_seed, d, z, m,
                                     "ss_dec_oracle", ss_dec_oracle, "ss_oracle", ss_oracle);
    }

    if (!bytes_equal(ss_dec_learn, ss_dec_oracle)) {
        return report_array_mismatch(case_idx, "decaps_mismatch", master_seed, d, z, m,
                                     "ss_dec_learn", ss_dec_learn, "ss_dec_oracle", ss_dec_oracle);
    }

    for (std::size_t t = 0; t < tamper_trials; ++t) {
        std::array<std::uint8_t, kMlkemKemCiphertextBytes> ct_tampered = ct_learn;
        const std::size_t tamper_idx = rng.next_index(kMlkemKemCiphertextBytes);
        std::uint8_t tamper_mask = static_cast<std::uint8_t>(rng.next_u8() | 0x01u);
        ct_tampered[tamper_idx] ^= tamper_mask;

        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_learn{};
        std::array<std::uint8_t, kMlkemKemSharedSecretBytes> ss_tampered_oracle{};

        if (!mlkem_kem_decaps(ss_tampered_learn.data(), ct_tampered.data(), sk_learn.data(), &err)) {
            std::cerr << "[dna-pqcore-learn] learn tampered decaps failed: " << err << "\n";
            return print_mismatch_header(case_idx, "learn_tampered_decaps_failed", master_seed, d, z, m);
        }

        if (!mlkem_oracle_decaps(ss_tampered_oracle.data(), ct_tampered.data(), sk_oracle.data(), &err)) {
            std::cerr << "[dna-pqcore-learn] oracle tampered decaps failed: " << err << "\n";
            return print_mismatch_header(case_idx, "oracle_tampered_decaps_failed", master_seed, d, z, m);
        }

        if (!bytes_equal(ss_tampered_learn, ss_tampered_oracle)) {
            return report_tamper_mismatch(case_idx, "tampered_decaps_mismatch", master_seed,
                                          d, z, m, tamper_idx, tamper_mask,
                                          ct_tampered, ss_tampered_learn, ss_tampered_oracle);
        }

        if (bytes_equal(ss_tampered_learn, ss_learn)) {
            return report_tamper_mismatch(case_idx, "tampered_shared_secret_unchanged", master_seed,
                                          d, z, m, tamper_idx, tamper_mask,
                                          ct_tampered, ss_tampered_learn, ss_oracle);
        }
    }

    return true;
}

} // namespace

int main(int argc, char** argv) {
    const std::size_t case_count =
        (argc >= 2) ? parse_size_arg(argv[1], kDefaultCases) : kDefaultCases;
    const std::uint64_t seed =
        (argc >= 3) ? parse_u64_arg(argv[2], kDefaultSeed) : kDefaultSeed;
    const std::size_t tamper_trials =
        (argc >= 4) ? parse_size_arg(argv[3], kDefaultTamperTrialsPerCase) : kDefaultTamperTrialsPerCase;

    static_assert(kMlkemKemPublicKeyBytes == kMlkemOraclePublicKeyBytes,
                  "learn/backend pk size mismatch");
    static_assert(kMlkemKemSecretKeyBytes == kMlkemOracleSecretKeyBytes,
                  "learn/backend sk size mismatch");
    static_assert(kMlkemKemCiphertextBytes == kMlkemOracleCiphertextBytes,
                  "learn/backend ct size mismatch");
    static_assert(kMlkemKemSharedSecretBytes == kMlkemOracleSharedSecretBytes,
                  "learn/backend ss size mismatch");

    std::cout
        << "[dna-pqcore-learn] kem diff fuzz starting"
        << " cases=" << case_count
        << " tamper_trials=" << tamper_trials
        << " seed=" << hex_u64(seed)
        << "\n";

    Rng64 rng(seed);

    for (std::size_t case_idx = 0; case_idx < case_count; ++case_idx) {
        if (!run_one_case(case_idx, seed, tamper_trials, rng)) {
            return 1;
        }
    }

    std::cout
        << "[dna-pqcore-learn] kem diff fuzz ok"
        << " cases=" << case_count
        << " tamper_trials=" << tamper_trials
        << " seed=" << hex_u64(seed)
        << "\n";

    return 0;
}