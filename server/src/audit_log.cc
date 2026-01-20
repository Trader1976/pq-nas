#include "audit_log.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
#include <deque>

#include <openssl/sha.h>

namespace pqnas {

/*
Audit log (hash-chained JSONL)
=============================

This module implements an append-only JSONL audit log with hash chaining.

Why this exists
---------------
Security systems need accountability. PQ-NAS records security-relevant events
(session issuance, verification outcomes, policy decisions, cookie minting, etc.)
in a format that is easy to:
- stream (`*.jsonl` line-by-line)
- tail for live ops
- verify for tampering after the fact

Tamper-evidence model (hash chaining)
-------------------------------------
Each log line includes:
- prev_hash: the previous line’s hash
- line_hash: SHA-256(prev_hash + json_without_line_hash)

This creates a linear chain:
  H_i = SHA256( H_{i-1} || JSON_i_without_line_hash )

If any line is modified, inserted, removed, or reordered, verification breaks
starting at that point.

Important limitations (explicit)
--------------------------------
- Hash chaining provides **tamper evidence**, not tamper prevention.
- If an attacker can modify BOTH jsonl and state file, they can rewrite history.
  Mitigations: external append-only storage, remote shipping, immutable volumes.
- This log is not encrypted; do not store secrets. Log identifiers and reason
  codes, not private keys or raw tokens.

Threading model
---------------
append() may be called from multiple request handlers. We serialize writes with
mu_ to avoid interleaving and to keep the chain linear and verifiable.
*/

// Hex encode bytes (lowercase).
static std::string to_hex(const unsigned char* p, size_t n) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.resize(n * 2);
  for (size_t i = 0; i < n; i++) {
    out[i*2+0] = kHex[(p[i] >> 4) & 0xF];
    out[i*2+1] = kHex[(p[i] >> 0) & 0xF];
  }
  return out;
}

AuditLog::AuditLog(std::string jsonl_path, std::string state_path)
  : jsonl_path_(std::move(jsonl_path)), state_path_(std::move(state_path)) {}

/*
Return current UTC time in ISO-8601 format with milliseconds and 'Z' suffix.

Example:
  2026-01-19T12:34:56.123Z

Notes:
- We use UTC for stable, comparable timestamps across hosts/timezones.
- The audit chain integrity does not depend on time; timestamps are for operators
  and forensics.
*/
std::string AuditLog::now_iso_utc() {
  using namespace std::chrono;
  auto now = system_clock::now();
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

  std::time_t tt = system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
      << "." << std::setw(3) << std::setfill('0') << ms.count()
      << "Z";
  return oss.str();
}

/*
SHA-256 helper returning lowercase hex.

Used for:
- deriving line_hash in the audit chain

Security note:
- SHA-256 is used here for integrity chaining, not for password hashing.
- Hex is used for readability/portability; verification can recompute exactly.
*/
std::string AuditLog::sha256_hex(const std::string& s) {
  unsigned char h[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), h);
  return to_hex(h, sizeof(h));
}

/*
Load previous chain hash from the state file.

The state file stores the last committed line_hash, allowing fast append
without re-hashing the entire JSONL file.

Fail-safe behavior:
- If the state file is missing or invalid, we fall back to the all-zero hash.
  This effectively starts a new chain from genesis.

Operational note:
- If the JSONL file exists but the state file was lost, verification will fail
  unless the state file is rebuilt by scanning the log. Consider implementing
  a rebuild tool if you expect state loss scenarios.
*/
std::string AuditLog::load_prev_hash_() {
  std::ifstream f(state_path_);
  if (!f.good()) return std::string(64, '0');
  std::string line;
  std::getline(f, line);
  if (line.size() != 64) return std::string(64, '0');
  return line;
}

/*
Persist last committed line_hash.

Security note:
- This file is part of the tamper-evidence mechanism.
- If an attacker can rewrite both JSONL + state, they can rewrite history.
  Treat the audit directory as sensitive and consider shipping logs off-host.
*/
void AuditLog::store_prev_hash_(const std::string& h) {
  std::ofstream f(state_path_, std::ios::trunc);
  f << h << "\n";
}

/*
Minimal JSON string escaping.

We hand-roll escaping to keep dependencies low and to avoid accidental
serialization differences. This is NOT a general-purpose JSON serializer:
- We only emit JSON objects with string keys and string values (plus fixed fields).
- All caller-provided strings must be treated as untrusted and escaped here.
*/
std::string AuditLog::json_escape_(const std::string& s) {
  std::ostringstream o;
  for (char c : s) {
    switch (c) {
      case '\"': o << "\\\""; break;
      case '\\': o << "\\\\"; break;
      case '\b': o << "\\b"; break;
      case '\f': o << "\\f"; break;
      case '\n': o << "\\n"; break;
      case '\r': o << "\\r"; break;
      case '\t': o << "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << (int)(unsigned char)c << std::dec;
        } else {
          o << c;
        }
    }
  }
  return o.str();
}

/*
Build a JSON object for one audit event and compute its chained hash.

Algorithm:
1) Build JSON without line_hash:
   { ts, event, outcome, prev_hash, (optional) f:{...} }

2) Compute:
   content_hash = SHA256( prev_hash + json_without_line_hash )

3) Build final JSON including line_hash:
   { ..., prev_hash, line_hash, ... }

Why include prev_hash inside the JSON?
- Makes each line self-describing and independently verifiable.
- Verification can stream the file without external context.

Field ordering note:
- We keep a consistent ordering within this function.
- The chain computation depends on the exact bytes of json_without_line_hash,
  so verification MUST use the same serialization rules.
*/
std::string AuditLog::build_json_(const AuditEvent& e,
                                 const std::string& prev_hash,
                                 std::string* out_content_hash_hex) {
  std::ostringstream js;
  js << "{"
     << "\"ts\":\"" << json_escape_(e.ts_utc) << "\""
     << ",\"event\":\"" << json_escape_(e.event) << "\""
     << ",\"outcome\":\"" << json_escape_(e.outcome) << "\""
     << ",\"prev_hash\":\"" << prev_hash << "\"";

  if (!e.f.empty()) {
    // "f" is a flexible map of additional fields (string → string).
    // Use it for identifiers and reason codes (never secrets).
    js << ",\"f\":{";
    bool first = true;
    for (const auto& kv : e.f) {
      if (!first) js << ",";
      first = false;
      js << "\"" << json_escape_(kv.first) << "\":"
         << "\"" << json_escape_(kv.second) << "\"";
    }
    js << "}";
  }

  js << "}";

  const std::string json_without_line_hash = js.str();

  // Chaining input: prev_hash + JSON bytes.
  // Any modification to the JSON line breaks the chain from this point onward.
  const std::string content = prev_hash + json_without_line_hash;
  *out_content_hash_hex = sha256_hex(content);

  std::ostringstream js2;
  // Insert line_hash at end by rebuilding with line_hash.
  //
  // Important:
  // Verification must recompute content_hash using the JSON *without* line_hash.
  // line_hash itself must not be included in the preimage.
  js2 << "{"
      << "\"ts\":\"" << json_escape_(e.ts_utc) << "\""
      << ",\"event\":\"" << json_escape_(e.event) << "\""
      << ",\"outcome\":\"" << json_escape_(e.outcome) << "\""
      << ",\"prev_hash\":\"" << prev_hash << "\""
      << ",\"line_hash\":\"" << *out_content_hash_hex << "\"";

  if (!e.f.empty()) {
    js2 << ",\"f\":{";
    bool first = true;
    for (const auto& kv : e.f) {
      if (!first) js2 << ",";
      first = false;
      js2 << "\"" << json_escape_(kv.first) << "\":"
          << "\"" << json_escape_(kv.second) << "\"";
    }
    js2 << "}";
  }

  js2 << "}";
  return js2.str();
}

/*
Append one audit event to the JSONL file and advance the chain.

Rules:
- Serialized under mu_ to preserve strict line ordering.
- If the caller did not provide a timestamp, we stamp it in UTC here.
- We append the JSONL line, flush, then update the state file.

Durability note:
- flush() reduces the chance of losing trailing events on crash, but does not
  guarantee fsync-level durability. If you need stronger guarantees, consider
  calling fsync() or writing to a journaling/append-only sink.
*/
void AuditLog::append(const AuditEvent& e_in) {
  std::lock_guard<std::mutex> lk(mu_);

  AuditEvent e = e_in;
  if (e.ts_utc.empty()) e.ts_utc = now_iso_utc();

  const std::string prev = load_prev_hash_();

  std::string content_hash;
  const std::string line = build_json_(e, prev, &content_hash);

  // Append JSONL line (one event per line).
  std::ofstream out(jsonl_path_, std::ios::app);
  out << line << "\n";
  out.flush();

  // Update state with the last committed line_hash.
  store_prev_hash_(content_hash);
}

} // namespace pqnas
