#pragma once
#include <string>
#include <unordered_map>

namespace pqnas {

/*
Allowlist policy interface
==========================

This header defines the authorization policy surface for PQ-NAS.

Key design principle:
- This layer answers *authorization* questions ("is this identity allowed?").
- It does NOT authenticate identities or verify cryptographic proofs.
- Callers must only invoke these methods after successful authentication.

Identity representation
-----------------------
The allowlist keys are normalized *fingerprint strings*.

Despite the parameter name `fp_hex`, the allowlist itself is format-agnostic:
- The fingerprint may be hex, base64, or base64url, as long as it matches
  the server’s canonical identity representation.
- Normalization (lowercasing, trimming) is applied internally.

Important:
- Cryptographic validity and fingerprint binding are enforced elsewhere.
- The allowlist assumes the fingerprint string it receives is trusted input.
*/

struct AllowEntry {
    // True if this identity has administrative privileges.
    // Admin implies user-level access.
    bool admin = false;

    // True if this identity is allowed basic (non-admin) access.
    bool user  = false;
};

class Allowlist {
public:
    /*
    Load allowlist policy from disk.

    Expected JSON format:
    {
      "users": [
        { "fingerprint": "<string>", "role": "user"|"admin" },
        { "fingerprint": "<string>", "tags": ["user","admin"] }
      ]
    }

    Return value:
    - true  on successful load
    - false on I/O or parse errors (caller should treat this as fatal)

    Security note:
    Running without a valid allowlist is unsafe; the server should refuse
    to start if loading fails.
    */
    bool load(const std::string& path);

    /*
    Check whether the given identity is authorized for access.

    Input:
    - fp_hex: normalized fingerprint string (legacy name; may be base64/base64url).

    Return value:
    - true  if identity has user or admin role
    - false otherwise

    Fail-closed:
    - Unknown identities always return false.
    */
    bool is_allowed(const std::string& fp_hex) const;

    /*
    Check whether the given identity has administrative privileges.

    Input:
    - fp_hex: normalized fingerprint string (legacy name; may be base64/base64url).

    Return value:
    - true  if identity has admin role
    - false otherwise

    Admin semantics:
    - Admin implies user access.
    - User does not imply admin.
    */
    bool is_admin(const std::string& fp_hex) const;

    // Bootstrap helpers (used on first successful login)
    bool empty() const;
    bool add_admin(const std::string& fp_hex);
    bool save(const std::string& path) const;


private:
    // Internal map of normalized fingerprint string → role flags.
    //
    // This map is populated atomically during load() and treated as read-only
    // during request handling (external synchronization handled by policy layer).
    std::unordered_map<std::string, AllowEntry> m_;
};

} // namespace pqnas
