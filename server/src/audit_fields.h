#pragma once
#include <string>

namespace pqnas {

    // Keep this list tight: only non-secret metadata.
    // Never log raw tokens, signatures, cookies, challenges, or public keys.
    //
    // OK to log:
    /// - sid (already not secret; but treat as identifier)
    /// - st_hash (already derived SHA256 over st; not the st itself)
    /// - fingerprint (public key hash; ok)
    /// - rp_id_hash / origin (already binding values)
    /// - ip/user_agent (optional)
    /// - reason codes (short)
    ///
    /// NOT OK:
    /// - st
    /// - signature
    /// - cookie value
    /// - raw challenge/session secrets
    ///

    inline std::string shorten(const std::string& s, size_t maxlen = 64) {
        if (s.size() <= maxlen) return s;
        return s.substr(0, maxlen) + "...";
    }

} // namespace pqnas
