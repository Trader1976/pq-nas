#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dnanexus::pq {

// Stable DNA-owned ML-KEM-768 API boundary.
//
// This interface is intentionally small and does not know anything about
// shares, envelopes, CEKs, files, browsers, or PQ-NAS routes.
//
// The current implementation may use a vendored provider internally, but
// callers must depend only on the contract documented here.

enum class MlKem768Status {
    ok = 0,
    output_null,
    bad_public_key_len,
    bad_secret_key_len,
    bad_ciphertext_len,
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

// Returns whether an ML-KEM-768 provider is compiled in and usable.
// For the current built-in native provider this is constant true.
bool mlkem768_available();

// Human-readable provider/backend label for diagnostics and logs.
// This is not part of the cryptographic contract.
std::string mlkem768_backend_name();

// Stable status-returning API.
//
// On any non-ok result, secret-bearing outputs are wiped/cleared.

// Generate an ML-KEM-768 keypair.
MlKem768Status mlkem768_keygen_status(MlKem768Keypair* out);

// Encapsulate to an ML-KEM-768 public key.
//
// Requirements:
//   - public_key must be exactly the ML-KEM-768 public-key length
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
//     is an API failure.
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
// These wrappers preserve the current bool + err surface while delegating to
// the stable status-returning entry points above.
//
// On failure:
//   - returns false
//   - outputs are wiped/cleared
//   - err receives a stable coarse error string if non-null
bool mlkem768_keygen(MlKem768Keypair* out, std::string* err);

bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                          MlKem768EncapResult* out,
                          std::string* err);

bool mlkem768_decapsulate(const std::vector<std::uint8_t>& secret_key,
                          const std::vector<std::uint8_t>& ciphertext,
                          std::vector<std::uint8_t>* out_shared_secret,
                          std::string* err);

// Diagnostic self-test only.
//
// Useful for startup/integration checks, but not intended to be part of the
// long-term production cryptographic surface.
bool mlkem768_selftest(std::string* err);

} // namespace dnanexus::pq