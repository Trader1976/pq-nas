#include "v4_verify_shared.h"
#include "verify_v4_crypto.h"
// Use real declarations from your repo (avoid forward-declare drift)
#include "pqnas_util.h"
#include "authz.h"

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas {
using json = nlohmann::json;

static VerifyV4Result fail(VerifyV4Rc rc, const std::string& msg, const std::string& detail = "") {
  VerifyV4Result r;
  r.ok = false;
  r.rc = rc;
  r.detail = detail.empty() ? msg : (msg + ": " + detail);
  return r;
}

VerifyV4Result verify_v4_json(
    const std::string& verify_body_json,
    const std::array<unsigned char, 32>& server_pk_ed25519,
    const std::optional<VerifyV4Config>& cfg_opt)
{
  VerifyV4Config cfg = cfg_opt.value_or(VerifyV4Config{});

  // 1) Parse JSON + envelope + required fields
  json body;
  try {
    body = json::parse(verify_body_json);
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::JSON_PARSE, "json parse failed", e.what());
  }

  if (!body.is_object()) return fail(VerifyV4Rc::JSON_SCHEMA, "body must be object");

  if (body.value("type", "") != "dna.auth.response")
    return fail(VerifyV4Rc::JSON_SCHEMA, "invalid type", body.value("type", ""));

  const int v = body.value("v", 0);
  if (v != 4) return fail(VerifyV4Rc::JSON_SCHEMA, "invalid version", std::to_string(v));

  for (auto k : {"st", "fingerprint", "signature", "signed_payload", "pubkey_b64"}) {
    if (!body.contains(k)) return fail(VerifyV4Rc::MISSING_FIELD, std::string("missing field: ") + k);
  }

  const std::string st         = body.at("st").get<std::string>();
  std::string claimed_fp       = body.at("fingerprint").get<std::string>();
  const std::string sig_b64    = body.at("signature").get<std::string>();
  const std::string pk_b64     = body.at("pubkey_b64").get<std::string>();

  json sp = body.at("signed_payload");
  if (!sp.is_object()) return fail(VerifyV4Rc::JSON_SCHEMA, "signed_payload must be object");

  VerifyV4Result out;
  out.origin    = sp.value("origin", "");
  out.rp_id_hash = sp.value("rp_id_hash", "");
  out.sid       = sp.value("sid", "");

  // 2) Verify st (Ed25519)
  json st_obj;
  try {
    st_obj = verify_token_v4_ed25519(st, server_pk_ed25519.data());
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::ST_INVALID, "invalid st", e.what());
  }

  if (st_obj.value("v", 0) != 4 || st_obj.value("typ", "") != "st") {
    return fail(
        VerifyV4Rc::ST_CLAIMS_INVALID,
        "invalid st claims",
        std::string("v=") + std::to_string(st_obj.value("v", 0)) +
            " typ=" + st_obj.value("typ", ""));
  }

  // 3) TTL / time window
  const long now = (cfg.now_unix_sec != 0) ? (long)cfg.now_unix_sec : now_epoch();

  long st_exp = 0;
  long st_iat = 0;
  try {
    st_exp = st_obj.at("expires_at").get<long>();
    st_iat = st_obj.at("issued_at").get<long>();
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::ST_CLAIMS_INVALID, "st missing/invalid time claims", e.what());
  }

  if (now > st_exp) return fail(VerifyV4Rc::ST_EXPIRED, "st expired");
  if (st_exp <= st_iat) return fail(VerifyV4Rc::ST_TIME_WINDOW_INVALID, "invalid st time window");

  // Prefer st claims for these
  out.sid        = st_obj.value("sid", out.sid);
  out.origin     = st_obj.value("origin", out.origin);
  out.rp_id_hash = st_obj.value("rp_id_hash", out.rp_id_hash);

  // 4) st_hash binding
  out.st_hash_b64 = sha256_b64_std_str(st); // standard b64 with padding
  const std::string got_st_hash = sp.value("st_hash", "");
  if (got_st_hash != out.st_hash_b64) {
    return fail(
        VerifyV4Rc::ST_HASH_MISMATCH,
        "st_hash mismatch",
        std::string("got_len=") + std::to_string(got_st_hash.size()) +
            " expected_len=" + std::to_string(out.st_hash_b64.size()));
  }

  // 5) Claim mirroring (must match st claims exactly)
  try {
    auto req_str = [&](const char* k) -> std::string { return sp.at(k).get<std::string>(); };
    auto req_int = [&](const char* k) -> long { return sp.at(k).get<long>(); };

    if (req_str("sid") != st_obj.value("sid", "")) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: sid");
    if (req_str("origin") != st_obj.value("origin", "")) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: origin");
    if (req_str("rp_id_hash") != st_obj.value("rp_id_hash", "")) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: rp_id_hash");
    if (req_str("nonce") != st_obj.value("nonce", "")) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: nonce");
    if (req_int("issued_at") != st_obj.value("issued_at", 0L)) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: issued_at");
    if (req_int("expires_at") != st_obj.value("expires_at", 0L)) return fail(VerifyV4Rc::CLAIM_MISMATCH, "claim mismatch: expires_at");
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::JSON_SCHEMA, "signed_payload missing/invalid field", e.what());
  }

  // 6) Origin binding (optional)
  if (!cfg.expected_origin.empty()) {
    if (trim_slashes(st_obj.value("origin", "")) != trim_slashes(cfg.expected_origin)) {
      return fail(VerifyV4Rc::ORIGIN_MISMATCH, "origin mismatch");
    }
  }

  // 7) RP binding (optional)
  if (!cfg.expected_rp_id.empty()) {
    const std::string expected_rp_hash = sha256_b64_std_str(lower_ascii(cfg.expected_rp_id));
    if (st_obj.value("rp_id_hash", "") != expected_rp_hash) {
      return fail(VerifyV4Rc::RP_ID_HASH_MISMATCH, "rp_id_hash mismatch");
    }
  }

  // 8) Decode inputs
  std::vector<unsigned char> signature;
  std::vector<unsigned char> pubkey;
  try {
    signature = b64decode_loose(sig_b64);
    pubkey    = b64decode_loose(pk_b64);
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::B64_DECODE, "base64 decode failed", e.what());
  }

  // 9) Identity binding
  const std::string computed_fp = fingerprint_from_pubkey_sha3_512_hex(pubkey);
  claimed_fp = lower_ascii(claimed_fp);
  if (claimed_fp != computed_fp) {
    return fail(VerifyV4Rc::FINGERPRINT_MISMATCH, "fingerprint_pubkey_mismatch");
  }
  out.fingerprint_hex = computed_fp;

  // 10) Policy (optional / configurable)
  if (cfg.enforce_allowlist) {
    if (!cfg.allowlist_is_allowed) {
      return fail(VerifyV4Rc::POLICY_DENY, "identity_not_allowed", "no allowlist callback provided");
    }
    if (!cfg.allowlist_is_allowed(computed_fp)) {
      return fail(VerifyV4Rc::POLICY_DENY, "identity_not_allowed");
    }
  }

  // 11) Canonical bytes (must match server)
  std::string canonical;
  try {
    canonical = canonical_v4_phone_auth(sp);
  } catch (const std::exception& e) {
    return fail(VerifyV4Rc::CANONICAL_BUILD, "canonical build failed", e.what());
  }

  out.canonical_sha256_b64 = sha256_b64_std_str(canonical);
  const std::vector<unsigned char> canonical_bytes(canonical.begin(), canonical.end());

  // 12) PQ verify (native)
  const bool pq_ok = verify_mldsa87_signature_native(pubkey, canonical_bytes, signature);
  if (!pq_ok) {
    return fail(VerifyV4Rc::PQ_SIG_INVALID, "invalid_signature", "PQ verify returned false");
  }

  out.ok = true;
  out.rc = VerifyV4Rc::OK;
  out.detail.clear();
  return out;
}

} // namespace pqnas
