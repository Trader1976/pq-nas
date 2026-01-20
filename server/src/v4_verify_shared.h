#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace pqnas {

enum class VerifyV4Rc : int {
  OK = 0,

  JSON_PARSE = 10,
  JSON_SCHEMA = 11,
  MISSING_FIELD = 12,

  ST_INVALID = 30,
  ST_CLAIMS_INVALID = 31,
  ST_EXPIRED = 32,
  ST_TIME_WINDOW_INVALID = 33,

  ST_HASH_MISMATCH = 40,
  CLAIM_MISMATCH = 41,

  ORIGIN_MISMATCH = 50,
  RP_ID_HASH_MISMATCH = 51,

  B64_DECODE = 60,
  FINGERPRINT_MISMATCH = 61,

  POLICY_DENY = 70,

  CANONICAL_BUILD = 80,
  PQ_SIG_INVALID = 81,

  INTERNAL = 99,
};

struct VerifyV4Config {
  // 0 => use pqnas::now_epoch()
  std::int64_t now_unix_sec = 0;

  // If empty => skip that check
  std::string expected_origin; // compared after trim_slashes()
  std::string expected_rp_id;  // sha256_b64_std_str(lower_ascii(expected_rp_id))

  // Authorization (allowlist)
  bool enforce_allowlist = true;

  // If enforce_allowlist=true and callback empty => POLICY_DENY.
  std::function<bool(const std::string& fingerprint_hex)> allowlist_is_allowed;
};

struct VerifyV4Result {
  bool ok = false;
  VerifyV4Rc rc = VerifyV4Rc::INTERNAL;

  std::string fingerprint_hex;
  std::string st_hash_b64;          // sha256_b64_std_str(st)
  std::string canonical_sha256_b64; // sha256_b64_std_str(canonical_json)

  std::string sid;
  std::string origin;
  std::string rp_id_hash;

  std::string detail; // short, no secrets
};

VerifyV4Result verify_v4_json(
    const std::string& verify_body_json,
    const std::array<unsigned char, 32>& server_pk_ed25519,
    const std::optional<VerifyV4Config>& cfg = std::nullopt);

} // namespace pqnas
