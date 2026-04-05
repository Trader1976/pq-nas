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

// Generate an ML-KEM-768 keypair.
//
// On success:
//   - returns true
//   - out->public_key and out->secret_key are fully populated
//
// On failure:
//   - returns false
//   - out contents are wiped/cleared
bool mlkem768_keygen(MlKem768Keypair* out, std::string* err);

// Encapsulate to an ML-KEM-768 public key.
//
// Requirements:
//   - public_key must be exactly the ML-KEM-768 public-key length
//
// On success:
//   - returns true
//   - out->ciphertext and out->shared_secret are fully populated
//
// On failure:
//   - returns false
//   - out contents are wiped/cleared
bool mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                          MlKem768EncapResult* out,
                          std::string* err);

// Decapsulate an ML-KEM-768 ciphertext with a recipient secret key.
//
// Requirements:
//   - secret_key must be exactly the ML-KEM-768 secret-key length
//   - ciphertext must be exactly the ML-KEM-768 ciphertext length
//
// Contract:
//   - Wrong input lengths are API failures and return false.
//   - A structurally invalid/corrupted secret key detected by the provider
//     is an API failure and returns false.
//   - A correctly sized but invalid/adversarial ciphertext is NOT an API
//     failure. The provider performs implicit rejection internally and
//     still returns a shared secret; this function returns true in that case.
//   - False is reserved for argument/length/provider failure, not ordinary
//     invalid ciphertext of correct length.
//
// On failure:
//   - out_shared_secret is wiped/cleared
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