#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pq {

// Stable DNA-owned ML-KEM-768 production API boundary.
//
// This interface is intentionally small and does not know anything about
// shares, envelopes, CEKs, files, browsers, or PQ-NAS routes.
//
// The current implementation may use a vendored provider internally, but
// callers must depend only on the contract documented here.

inline constexpr std::size_t kMlKem768PublicKeyBytes = 1184;
inline constexpr std::size_t kMlKem768SecretKeyBytes = 2400;
inline constexpr std::size_t kMlKem768CiphertextBytes = 1088;
inline constexpr std::size_t kMlKem768SharedSecretBytes = 32;

enum class MlKem768Status {
    ok = 0,
    output_null,
    bad_public_key_len,
    bad_secret_key_len,
    bad_ciphertext_len,
    invalid_public_key,
    invalid_secret_key,
    random_failed,
    provider_failed,
};

struct MlKem768Keypair {
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> secret_key;
};

struct MlKem768EncapResult {
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> shared_secret;
};

// Explicit secret-lifecycle helpers.
//
// These are safe on null and may be called repeatedly.
// For simplicity and consistent caller hygiene, these helpers clear the full
// containers, including public fields that travel alongside secrets.

void mlkem768_wipe_keypair(MlKem768Keypair* kp);
void mlkem768_wipe_encap_result(MlKem768EncapResult* enc);
void mlkem768_wipe_shared_secret(std::vector<std::uint8_t>* ss);

// Stable status-returning production API.
//
// These status-returning entry points are the preferred production API.
// On any non-ok result, secret-bearing outputs are wiped/cleared.

// Generate an ML-KEM-768 keypair.
MlKem768Status mlkem768_keygen_status(MlKem768Keypair* out);

// Encapsulate to an ML-KEM-768 public key.
//
// Requirements:
//   - public_key must be exactly the ML-KEM-768 public-key length
//
// Status contract:
//   - bad_public_key_len: wrong public-key size
//   - invalid_public_key: correct-size public key rejected by provider checks
MlKem768Status mlkem768_encapsulate_status(
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out);

// Decapsulate an ML-KEM-768 ciphertext with a recipient secret key.
//
// Requirements:
//   - secret_key must be exactly the ML-KEM-768 secret-key length
//   - ciphertext must be exactly the ML-KEM-768 ciphertext length
//
// Contract:
//   - Wrong input lengths are API failures.
//   - A structurally invalid/corrupted secret key detected by the provider
//     is an API failure and returns invalid_secret_key.
//   - A correctly sized but invalid/adversarial ciphertext is NOT an API
//     failure. The provider performs implicit rejection internally and still
//     returns a shared secret; this function returns MlKem768Status::ok in
//     that case.
//   - Non-ok is reserved for argument/length/provider failure, not ordinary
//     invalid ciphertext of correct length.
MlKem768Status mlkem768_decapsulate_status(
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>* out_shared_secret);

// Compatibility API.
//
// The status-returning entry points above are the preferred production API.
// The bool + err wrappers below are kept as compatibility helpers for
// existing call sites.
//
// Error-string contract:
//   - On failure, if err is non-null, it receives a stable coarse string
//     derived from MlKem768Status.
//   - These strings are intended for compatibility and simple diagnostics;
//     callers that need structured handling should prefer the status API.
//
// On failure:
//   - returns false
//   - outputs are wiped/cleared
bool mlkem768_keygen(MlKem768Keypair* out, std::string* err);

bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                          MlKem768EncapResult* out,
                          std::string* err);

bool mlkem768_decapsulate(const std::vector<std::uint8_t>& secret_key,
                          const std::vector<std::uint8_t>& ciphertext,
                          std::vector<std::uint8_t>* out_shared_secret,
                          std::string* err);

} // namespace dnanexus::pq