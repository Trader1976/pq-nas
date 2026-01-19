#include "policy.h"
#include "allowlist.h"

#include <mutex>
#include <iostream>

namespace pqnas {

/*
Policy layer (authorization, not authentication)
=================================================

This file implements the *policy* surface of PQ-NAS:
- It answers the question: "Is this already-authenticated identity allowed?"
- It does NOT perform cryptographic verification.
- It does NOT issue or validate sessions or cookies.

All decisions here assume:
- The caller has already verified cryptographic authenticity
  (Ed25519 st + ML-DSA-87 signature + fingerprint binding).
- The fingerprint passed in is trusted input produced by that verification.

Threading model
---------------
The allowlist is loaded once at startup and then queried concurrently
by multiple request-handling threads. To keep policy checks simple and
robust, access to the Allowlist instance is protected by a single mutex.

This avoids:
- Data races during reload or startup
- Partially-initialized policy state
- The need for lock-free or copy-on-write complexity in a security-critical path

Performance note:
Policy checks are cheap (string lookup). Mutex contention here is negligible
compared to cryptographic verification and network I/O.
*/

static std::mutex g_mu;        // Guards access to g_allow
static Allowlist g_allow;     // In-memory fingerprint → role mapping

/*
Load allowlist policy from disk.

This is typically called once during server startup.
If loading fails, the server should refuse to start, since operating
without an explicit authorization policy would be unsafe.

Security notes:
- The allowlist defines *authorization*, not identity.
- A cryptographically valid user can still be denied here.
- Compromise of allowlist.json compromises policy, not crypto.

Thread safety:
- Protected by g_mu to prevent races if reload support is added later.
*/
bool policy_load_allowlist(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.load(path);
}

/*
Check whether a fingerprint is allowed any access (user or admin).

Used during /api/v4/verify after cryptographic verification succeeds.

Security notes:
- Input must already be verified and normalized (lowercase hex).
- A return value of false must cause verification to fail closed.

This function intentionally does NOT distinguish roles;
it answers only the yes/no authorization question.
*/
bool policy_is_allowed(const std::string& fingerprint_hex) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.is_allowed(fingerprint_hex);
}

/*
Check whether a fingerprint has administrative privileges.

Used by admin-only endpoints (e.g. audit UI, privileged APIs).

Security notes:
- Admin is a *role*, not a separate identity class.
- Admin implies allowed, but allowed does not imply admin.
- Callers must still verify a valid authenticated session
  before invoking this check.

Fail-closed rule:
- Any missing or unknown fingerprint must return false.
*/
bool policy_is_admin(const std::string& fingerprint_hex) {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_allow.is_admin(fingerprint_hex);
}

} // namespace pqnas
