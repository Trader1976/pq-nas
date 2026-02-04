#include "allowlist.h"
#include "pqnas_util.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <algorithm>
using json = nlohmann::json;

namespace pqnas {

/*
Allowlist (policy / authorization)
==================================

This module defines *authorization policy* based on a fingerprint string.

Important separation of concerns:
- Authentication (crypto): proving identity and extracting a trusted fingerprint
  is handled elsewhere (v4 verifier + session cookie verification).
- Authorization (policy): deciding whether that fingerprint is allowed and/or admin
  is handled here.

Fingerprint representation
--------------------------
Despite some variable names elsewhere ("fp_hex"), this allowlist is format-agnostic:
it stores and compares a *normalized fingerprint string*.

In v4, qr_proof_claims_t exposes fingerprint_b64 (base64/base64url text). If that
value is used directly as the identity string in cookies and policy checks, then
allowlist.json must contain the same representation.

Normalization rules implemented here:
- ASCII lowercase
- trim leading/trailing ASCII whitespace

No decoding/validation is performed beyond that (by design):
- This keeps policy simple and avoids duplicating crypto-side parsing logic.
- Cryptographic verification must happen before policy checks so the fingerprint
  string is trusted input.
*/

static std::string trim_ws_local(std::string s) {
    // Trim ASCII whitespace only (space, tab, CR, LF).
    // We deliberately avoid locale-dependent whitespace rules.
    auto is_ws = [](unsigned char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; };
    while (!s.empty() && is_ws((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && is_ws((unsigned char)s.back()))  s.pop_back();
    return s;
}

static std::string norm_fp(std::string fp) {
    // Canonical fingerprint representation used in the allowlist map:
    // - lowercased ASCII
    // - trimmed of surrounding ASCII whitespace
    //
    // Security note:
    // This is NOT a validation step; it is normalization to avoid trivial mismatches.
    // Any semantic validation (e.g., signature checks, fingerprint binding) belongs
    // in the cryptographic verifier.
    fp = lower_ascii(fp);
    fp = trim_ws_local(fp);
    return fp;
}

/*
Load allowlist from JSON file.

Expected format:
{
  "users": [
    { "fingerprint": "<string>", "role": "user"|"admin" },
    { "fingerprint": "<string>", "tags": ["user","admin"] }
  ]
}

Role rules:
- "admin" implies "user".
- Entries with no recognized role/tags are ignored.

Operational notes:
- This function loads into a temporary map and swaps into place on success,
  preventing partially-loaded policy state.
- Errors are printed to stderr (consider routing to your audit/log system later).
*/
bool Allowlist::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) {
        std::cerr << "[allowlist] file not found: " << path << std::endl;
        return false;
    }

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        std::cerr << "[allowlist] parse error: " << e.what() << std::endl;
        return false;
    }

    if (!j.is_object() || !j.contains("users") || !j["users"].is_array()) {
        std::cerr << "[allowlist] invalid format (expected {\"users\": [...]})" << std::endl;
        return false;
    }

    // Build policy in a temporary map first (atomic-ish update via swap at end).
    std::unordered_map<std::string, AllowEntry> tmp;

    for (const auto& u : j["users"]) {
        if (!u.is_object()) continue;

        // "fingerprint" here is a string identifier that must match the server's
        // internal identity representation (e.g., fingerprint_b64 from v4 claims).
        std::string fp = norm_fp(u.value("fingerprint", ""));
        if (fp.empty()) continue;

        AllowEntry e;

        // Option A: role string (simple)
        //   { "fingerprint":"...", "role":"admin" } or "user"
        if (u.contains("role")) {
            std::string r = lower_ascii(u.value("role", ""));
            if (r == "admin") { e.admin = true; e.user = true; }
            else if (r == "user") { e.user = true; }
        }

        // Option B: tags array (future-proof / extensible)
        //   { "fingerprint":"...", "tags":["user","admin"] }
        if (u.contains("tags") && u["tags"].is_array()) {
            for (const auto& t : u["tags"]) {
                if (!t.is_string()) continue;
                std::string ts = lower_ascii(t.get<std::string>());
                if (ts == "admin") e.admin = true;
                if (ts == "user")  e.user  = true;
            }
            if (e.admin) e.user = true; // admin implies user
        }

        // If neither user nor admin was granted, ignore entry.
        if (!e.user && !e.admin) continue;

        // Later duplicates overwrite earlier ones; last entry wins.
        // This is acceptable for a simple policy file, but should be documented.
        tmp[fp] = e;
    }

    // Swap in the freshly-loaded policy (discard old map).
    m_.swap(tmp);
    std::cerr << "[allowlist] loaded " << m_.size() << " entries from " << path << std::endl;
    return true;
}

/*
Return true if fingerprint is authorized for basic access.

Caller contract:
- fp_* must be the *trusted* identity string obtained after cryptographic verification.
- This function does not validate signature correctness or binding; it is policy-only.

Fail-closed:
- Unknown fingerprints return false.
*/
bool Allowlist::is_allowed(const std::string& fp_hex) const {
    // NOTE: parameter name fp_hex is legacy; the allowlist stores a normalized fingerprint string.
    auto it = m_.find(norm_fp(fp_hex));
    if (it == m_.end()) return false;
    return it->second.user || it->second.admin;
}

/*
Return true if fingerprint has admin privileges.

Admin implies user, but not vice versa.
Unknown fingerprints return false (fail-closed).
*/
bool Allowlist::is_admin(const std::string& fp_hex) const {
    // NOTE: parameter name fp_hex is legacy; the allowlist stores a normalized fingerprint string.
    auto it = m_.find(norm_fp(fp_hex));
    if (it == m_.end()) return false;
    return it->second.admin;
}

    bool Allowlist::empty() const {
    return m_.empty();
}

    bool Allowlist::add_admin(const std::string& fp_hex) {
    const std::string fp = norm_fp(fp_hex);
    if (fp.empty()) return false;

    auto it = m_.find(fp);
    if (it != m_.end()) {
        bool changed = false;
        if (!it->second.admin) { it->second.admin = true; changed = true; }
        if (!it->second.user)  { it->second.user  = true; changed = true; }
        return changed;
    }

    AllowEntry e;
    e.admin = true;
    e.user  = true;
    m_[fp] = e;
    return true;
}

    bool Allowlist::save(const std::string& path) const {
    // Stable output ordering
    std::vector<std::string> keys;
    keys.reserve(m_.size());
    for (const auto& kv : m_) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());

    json j;
    j["users"] = json::array();

    // Persist in the simple "role" form (load() supports it)
    for (const auto& fp : keys) {
        const auto& e = m_.at(fp);
        if (!e.user && !e.admin) continue;

        const std::string role = e.admin ? "admin" : "user";
        j["users"].push_back(json{
            {"fingerprint", fp},
            {"role", role}
        });
    }

    // Atomic-ish write: tmp + rename
    std::filesystem::path p(path);
    std::filesystem::create_directories(p.parent_path());
    auto tmp = p;
    tmp += ".tmp";

    {
        std::ofstream out(tmp.string(), std::ios::trunc);
        if (!out.good()) return false;
        out << j.dump(2) << "\n";
        out.flush();
    }

    std::error_code ec;
    std::filesystem::rename(tmp, p, ec);
    if (ec) {
        std::filesystem::remove(p, ec);
        ec.clear();
        std::filesystem::rename(tmp, p, ec);
        if (ec) return false;
    }

    return true;
}

} // namespace pqnas
