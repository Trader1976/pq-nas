#pragma once
#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <deque>
#include <atomic>

namespace pqnas {

/*
AuditEvent
==========

Represents a single security-relevant event recorded in the audit log.

Design goals:
- Human-readable
- Machine-verifiable
- Stable across versions
- Safe to log (no secrets)

All fields are strings to:
- avoid schema drift
- keep JSONL simple and stream-friendly
- prevent accidental logging of structured secrets

IMPORTANT:
- Never store private keys, raw tokens, or full cryptographic material here.
- Log identifiers, outcomes, and reason codes only.
*/
struct AuditEvent {
    // Timestamp in ISO-8601 UTC format with milliseconds and 'Z' suffix.
    // Example: 2026-01-19T12:34:56.123Z
    std::string ts_utc;

    // Event identifier.
    // Convention: "<subsystem>.<action>"
    // Examples:
    //   - "v4.session_issued"
    //   - "v4.verify_ok"
    //   - "v4.verify_fail"
    //   - "policy.denied"
    std::string event;

    // Outcome classification.
    // Typical values:
    //   - "ok"    : operation succeeded
    //   - "fail"  : verification or processing failed
    //   - "deny"  : policy explicitly denied access
    std::string outcome;

    // Additional key-value fields for context.
    //
    // Examples:
    //   - fingerprint
    //   - sid
    //   - reason_code
    //   - origin
    //
    // Constraints:
    // - string → string only
    // - no nesting
    // - no binary data
    //
    // Rationale:
    // Keeps JSONL lines stable, diffable, and easy to verify.
    std::map<std::string, std::string> f;
};

/*
AuditLog
========

Append-only, hash-chained JSONL audit log.

Security properties:
- Tamper-evident (hash chaining)
- Ordered (single writer via mutex)
- Verifiable after the fact

Each log line contains:
- prev_hash : hash of the previous line
- line_hash : SHA-256(prev_hash + json_without_line_hash)

This creates a linear integrity chain:
  H_i = SHA256( H_{i-1} || JSON_i_without_line_hash )

Any modification, insertion, deletion, or reordering of lines
breaks the chain from that point forward.

Important limitations (explicit):
- This provides tamper *evidence*, not tamper *prevention*.
- If an attacker can rewrite both the JSONL file and the state file,
  history can be rewritten.
- For higher assurance, ship logs off-host or store on append-only media.
*/
class AuditLog {
public:
    /*
    Construct an audit log.

    Parameters:
    - jsonl_path : path to the append-only JSONL log file
    - state_path : path to the state file storing the last committed line_hash

    The state file allows fast appends without re-hashing the entire log.
    */
    AuditLog(std::string jsonl_path, std::string state_path);

    /*
    Append a single audit event.

    Thread safety:
    - Fully thread-safe.
    - Calls are serialized internally to preserve strict ordering.

    Behavior:
    - If ts_utc is empty, it is set automatically.
    - The event is appended as one JSONL line.
    - The hash chain is advanced and persisted.

    Fail-closed principle:
    - Partial writes or malformed entries should be treated as fatal
      by operators during verification.
    */
    void append(const AuditEvent& e);


    // Audit verbosity control.
    //
    // Ordering: DEBUG < INFO < ADMIN < SECURITY
    // MinLevel means: "log events with level >= min_level"
    enum class MinLevel : int {
        DEBUG    = 0,
        INFO     = 1,
        ADMIN    = 2,
        SECURITY = 3,
    };

    // Set minimum level. Returns true if accepted, false if invalid.
    bool set_min_level_str(const std::string& s);

    // Get current minimum level as string (SECURITY/ADMIN/INFO/DEBUG).
    std::string min_level_str() const;

    /*
    Convenience helper: return current UTC timestamp in ISO-8601 format.

    Used by:
    - audit logging
    - tests
    - tools that need consistent timestamps
    */

    static std::string now_iso_utc();

    /*
    SHA-256 helper returning lowercase hex.

    Used for:
    - audit hash chaining
    - verification tooling

    Note:
    - This is not a password hash.
    - This is integrity-only.
    */
    static std::string sha256_hex(const std::string& s);


private:
    // Minimum level of events to record. Default is ADMIN.
    std::atomic<int> min_level_{static_cast<int>(MinLevel::ADMIN)};

    // Path to the JSONL audit log file.
    std::string jsonl_path_;

    // Path to the state file storing the last line_hash.
    std::string state_path_;

    // Mutex to serialize appends and preserve chain order.
    std::mutex mu_;

    /*
    Load previous line_hash from state file.

    Returns:
    - 64 hex characters if present and valid
    - "000...0" (64 zeros) if missing or invalid (genesis)
    */
    std::string load_prev_hash_();

    /*
    Store the most recent line_hash to the state file.

    Overwrites previous value.
    */
    void store_prev_hash_(const std::string& h);

    /*
    Escape a string for safe JSON embedding.

    This is a minimal, controlled JSON escape function.
    It is intentionally not a full JSON serializer.
    */
    static std::string json_escape_(const std::string& s);

    /*
    Build a JSON object for an audit event and compute its chained hash.

    Parameters:
    - e         : audit event
    - prev_hash: hash of previous line
    - out_content_hash_hex:
        receives SHA256(prev_hash + json_without_line_hash)

    Returns:
    - final JSON string including line_hash

    IMPORTANT:
    - The hash preimage MUST NOT include line_hash itself.
    - Verification code must replicate this exact logic.
    */
    static std::string build_json_(const AuditEvent& e,
                                   const std::string& prev_hash,
                                   std::string* out_content_hash_hex);
};

} // namespace pqnas
