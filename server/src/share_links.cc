#include "share_links.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <sodium.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace pqnas {

/*
================================================================================
Share Links Registry — Architectural Overview
================================================================================

This module provides a small, self-contained registry for "public share links"
(file and directory shares). Conceptually, it behaves like a tiny local database
backed by a JSON file.

Key design goals:
  1) Simple persistence: JSON file on disk (shares.json or configured path).
  2) Strong token unpredictability: cryptographically-random URL-safe tokens.
  3) Concurrency safety: registry is safe to use from multiple threads.
  4) Crash safety: writes are atomic (write temp -> rename).

Data model:
  - ShareLink: { token, owner_fp, path, type, created_at, expires_at, downloads }
  - "path" is stored as a relative path (to whatever root the higher-level API uses).

Threading model:
  - All accesses to shares_ are guarded by mu_.
  - Public methods typically lock mu_ for the duration of the operation.
  - Persistence occurs under the same lock to keep in-memory and on-disk state
    consistent (linearizable updates).

Persistence strategy:
  - save_atomic() writes a complete snapshot of shares_ to <path>.tmp, flushes,
    then renames tmp -> path.
  - This guarantees that readers either see the old full file or the new full file,
    avoiding partial writes.
  - Note: On POSIX, rename is atomic within the same filesystem. Ensure tmp is on
    the same filesystem as the target path.

Security considerations:
  - Token is 32 bytes of randomness encoded as base64url without padding.
    This yields ~256 bits of entropy before encoding.
  - Owner enforcement is implemented by revoke_owner(): it never reveals whether
    a token exists if the caller is not the owner (returns false either way).
  - Expiration parsing is strict ISO8601 UTC to avoid locale/timezone ambiguity.

Caveats / future improvements:
  - save_atomic() does not fsync() directory entry; on some filesystems, a power
    loss could lose the rename. Consider fsync file + fsync parent directory for
    stronger durability if you need it.
  - is_expired_utc() currently "fails open" on parse errors (treat as not expired).
    Depending on your threat model, you may prefer "fail closed" (treat as expired).
================================================================================
*/


//------------------------------------------------------------------------------
// Encoding helpers
//------------------------------------------------------------------------------

/*
b64url_enc()
  - Encodes binary data as base64url *without padding*, suitable for URLs.
  - Uses libsodium's URLSAFE_NO_PADDING variant.
  - Output is safe to place in URLs without escaping (except you may still want
    to treat it as opaque and avoid rewriting).
*/
static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}


//------------------------------------------------------------------------------
// Time helpers (UTC ISO8601)
//------------------------------------------------------------------------------

/*
We use ISO8601 UTC timestamps ("YYYY-MM-DDTHH:MM:SSZ") for:
  - created_at
  - expires_at

This format is:
  - lexicographically sortable (when fixed-width and UTC)
  - unambiguous across locales/timezones
  - easy to read in logs and JSON

Important:
  - All conversions here assume UTC.
  - We intentionally avoid localtime() to prevent DST/timezone surprises.
*/

// ISO8601 UTC: "YYYY-MM-DDTHH:MM:SSZ"
static std::string tm_to_iso8601_utc(const std::tm& tm) {
    // "YYYY-MM-DDTHH:MM:SSZ" => 20 chars + '\0' = 21
    // Use a larger buffer to silence fortify truncation warnings.
    char buf[64];

    const int n = std::snprintf(buf, sizeof(buf),
                                "%04d-%02d-%02dT%02d:%02d:%02dZ",
                                tm.tm_year + 1900,
                                tm.tm_mon + 1,
                                tm.tm_mday,
                                tm.tm_hour,
                                tm.tm_min,
                                tm.tm_sec);

    if (n < 0) return std::string();
    if (n >= (int)sizeof(buf)) {
        // Should never happen with this format, but fail-safe.
        return std::string();
    }
    return std::string(buf);
}

/*
iso8601_utc_to_tm()
  - Strict parser for the exact format "YYYY-MM-DDTHH:MM:SSZ"
  - Does not accept offsets, fractions, or missing 'Z'
  - This strictness is intentional: expiration should be unambiguous.
*/
static bool iso8601_utc_to_tm(const std::string& s, std::tm* out) {
    // strict parse: YYYY-MM-DDTHH:MM:SSZ
    if (!out) return false;
    if (s.size() != 20) return false;
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z') return false;

    auto to_int = [&](int a, int b, int* v) -> bool {
        int x = 0;
        for (int i = a; i < b; i++) {
            char c = s[(size_t)i];
            if (c < '0' || c > '9') return false;
            x = x * 10 + (c - '0');
        }
        *v = x;
        return true;
    };

    int Y=0,M=0,D=0,h=0,m=0,se=0;
    if (!to_int(0,4,&Y)) return false;
    if (!to_int(5,7,&M)) return false;
    if (!to_int(8,10,&D)) return false;
    if (!to_int(11,13,&h)) return false;
    if (!to_int(14,16,&m)) return false;
    if (!to_int(17,19,&se)) return false;

    std::tm tm{};
    tm.tm_year = Y - 1900;
    tm.tm_mon  = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min  = m;
    tm.tm_sec  = se;
    *out = tm;
    return true;
}

/*
timegm_portable()
  - Converts a UTC tm to time_t in a cross-platform way.
  - On GNU/Linux we use timegm() directly (interprets tm as UTC).
  - On other systems we temporarily set TZ=UTC and call mktime().

Note:
  - The TZ-environment trick is process-global and can be surprising in
    multi-threaded programs. If PQ-NAS ever runs this on non-Linux in a
    multi-threaded environment, consider replacing this with a safer UTC
    conversion utility (e.g., a dedicated chrono-based conversion).
*/
static std::time_t timegm_portable(std::tm* tm) {
#if defined(_GNU_SOURCE) || defined(__linux__)
    return ::timegm(tm);
#else
    // Fallback: treat as UTC by temporarily forcing TZ=UTC.
    // If you don’t want environment tricks, replace with a proper UTC conversion util you already have.
    char* old = std::getenv("TZ");
    std::string oldv = old ? old : "";
    ::setenv("TZ", "UTC", 1);
    ::tzset();
    std::time_t t = std::mktime(tm);
    if (old) ::setenv("TZ", oldv.c_str(), 1);
    else ::unsetenv("TZ");
    ::tzset();
    return t;
#endif
}


//------------------------------------------------------------------------------
// ShareRegistry — lifecycle
//------------------------------------------------------------------------------

/*
ShareRegistry stores the path to a JSON file and maintains an in-memory vector of
ShareLink entries.

Invariant:
  - shares_ contains only well-formed entries:
      token, owner_fp, path, type are non-empty
      type ∈ {"file", "dir"}
  - No strong uniqueness invariant is stored beyond token uniqueness at creation
    time. (load() may read duplicates if file is corrupted; current code keeps
    what it reads. Consider de-dup on load if desired.)
*/
ShareRegistry::ShareRegistry(std::string json_path)
    : json_path_(std::move(json_path)) {}

/*
load()
  - Best-effort load from disk into memory.
  - Missing file is not an error (empty registry).
  - Invalid JSON yields an error message and returns false.
  - Malformed entries are skipped.
*/
bool ShareRegistry::load(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    shares_.clear();

    std::ifstream f(json_path_);
    if (!f.good()) {
        // Missing file is fine => empty registry
        return true;
    }

    json root;
    try {
        f >> root;
    } catch (const std::exception& e) {
        if (err) *err = std::string("shares.json parse failed: ") + e.what();
        return false;
    }

    // Schema is intentionally tolerant: if expected keys are missing,
    // we treat registry as empty rather than failing hard.
    if (!root.is_object()) return true;
    if (!root.contains("shares") || !root["shares"].is_array()) return true;

    for (const auto& it : root["shares"]) {
        if (!it.is_object()) continue;

        ShareLink s;
        if (it.contains("token") && it["token"].is_string()) s.token = it["token"].get<std::string>();
        if (it.contains("owner_fp") && it["owner_fp"].is_string()) s.owner_fp = it["owner_fp"].get<std::string>();
        if (it.contains("path") && it["path"].is_string()) s.path = it["path"].get<std::string>();
        if (it.contains("type") && it["type"].is_string()) s.type = it["type"].get<std::string>();
        if (it.contains("created_at") && it["created_at"].is_string()) s.created_at = it["created_at"].get<std::string>();
        if (it.contains("expires_at") && it["expires_at"].is_string()) s.expires_at = it["expires_at"].get<std::string>();
        if (it.contains("downloads")) {
            // downloads is tolerant: we accept unsigned int, signed int (>=0), or string.
            // This helps in case older versions wrote it differently.
            try {
                if (it["downloads"].is_number_unsigned()) s.downloads = it["downloads"].get<std::uint64_t>();
                else if (it["downloads"].is_number_integer())  s.downloads = (std::uint64_t)std::max<long long>(0, it["downloads"].get<long long>());
                else if (it["downloads"].is_string()) s.downloads = (std::uint64_t)std::stoull(it["downloads"].get<std::string>());
            } catch (...) {}
        }

        // Enforce minimal validity & type whitelist.
        if (s.token.empty() || s.owner_fp.empty() || s.path.empty() || s.type.empty()) continue;
        if (s.type != "file" && s.type != "dir") continue;

        shares_.push_back(std::move(s));
    }

    return true;
}

/*
list()
  - Returns a snapshot copy of the registry.
  - Caller gets its own vector copy; subsequent mutations will not affect it.
  - This is a convenient pattern for APIs that want to serialize or filter shares
    without holding the lock for long.
*/
std::vector<ShareLink> ShareRegistry::list() const {
    std::lock_guard<std::mutex> lk(mu_);
    return shares_;
}


//------------------------------------------------------------------------------
// Token generation
//------------------------------------------------------------------------------

/*
gen_token_b64url_32()
  - Generates 32 bytes of cryptographically-secure randomness via libsodium,
    then encodes it in base64url (no padding).
  - Used as the external share token presented to users.
*/
static std::string gen_token_b64url_32() {
    unsigned char rnd[32];
    randombytes_buf(rnd, sizeof(rnd));
    return b64url_enc(rnd, sizeof(rnd));
}


//------------------------------------------------------------------------------
// Persistence
//------------------------------------------------------------------------------

/*
save_atomic()
  - Serializes shares_ and replaces the on-disk registry atomically.
  - Implements a "full rewrite" approach:
        shares_ -> JSON -> tmp file -> rename over target
  - This is simple and robust for small registries.

Durability notes:
  - flush() ensures std::ofstream buffers are written, but does not guarantee the
    OS has committed to stable storage.
  - If you want "hard" durability across power loss:
      - fsync(tmp_fd) after writing
      - fsync(parent_dir_fd) after rename
*/
bool ShareRegistry::save_atomic(std::string* err) {
    json root;
    root["shares"] = json::array();

    for (const auto& s : shares_) {
        json it;
        it["token"] = s.token;
        it["owner_fp"] = s.owner_fp;
        it["path"] = s.path;
        it["type"] = s.type;
        it["created_at"] = s.created_at;
        if (!s.expires_at.empty()) it["expires_at"] = s.expires_at;
        it["downloads"] = s.downloads;
        root["shares"].push_back(std::move(it));
    }

    std::filesystem::path p(json_path_);
    std::filesystem::path dir = p.parent_path();
    std::error_code ec;
    if (!dir.empty()) std::filesystem::create_directories(dir, ec);

    std::filesystem::path tmp = p;
    tmp += ".tmp";

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.good()) {
            if (err) *err = "failed to open tmp for write: " + tmp.string();
            return false;
        }
        out << root.dump(2) << "\n";
        out.flush();
        if (!out.good()) {
            if (err) *err = "failed writing tmp: " + tmp.string();
            return false;
        }
    }

    std::filesystem::rename(tmp, p, ec);
    if (ec) {
        // try replace (rename over existing might fail on some setups)
        std::filesystem::remove(p, ec);
        ec.clear();
        std::filesystem::rename(tmp, p, ec);
    }
    if (ec) {
        if (err) *err = std::string("rename(tmp->shares.json) failed: ") + ec.message();
        return false;
    }

    return true;
}


//------------------------------------------------------------------------------
// Time utilities (public helpers)
//------------------------------------------------------------------------------

/*
now_utc_iso8601()
  - Returns current time in ISO8601 UTC with 'Z'.
  - Used for created_at.
*/
std::string ShareRegistry::now_utc_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(__linux__)
    gmtime_r(&t, &tm);
#else
    tm = *std::gmtime(&t);
#endif
    return tm_to_iso8601_utc(tm);
}

/*
add_seconds_utc_iso8601()
  - Returns now + seconds (if seconds > 0) in ISO8601 UTC.
  - Used for expires_at.
*/
std::string ShareRegistry::add_seconds_utc_iso8601(long long seconds) {
    std::time_t t = std::time(nullptr);
    if (seconds > 0) t += (std::time_t)seconds;

    std::tm tm{};
#if defined(__linux__)
    gmtime_r(&t, &tm);
#else
    tm = *std::gmtime(&t);
#endif
    return tm_to_iso8601_utc(tm);
}

/*
is_expired_utc()
  - Determines whether an ISO8601 UTC timestamp is in the past.
  - If expires_at is empty -> not expired.
  - If parse fails -> currently treated as not expired (fail-open).
    Consider fail-closed if you treat malformed expiration as suspicious.
*/
bool ShareRegistry::is_expired_utc(const std::string& expires_at_iso8601) {
    if (expires_at_iso8601.empty()) return false;
    std::tm tm{};
    if (!iso8601_utc_to_tm(expires_at_iso8601, &tm)) return false; // fail-open: choose NOT expired on parse issues
    std::time_t exp = timegm_portable(&tm);
    std::time_t now = std::time(nullptr);
    return exp > 0 && now >= exp;
}


//------------------------------------------------------------------------------
// Mutations
//------------------------------------------------------------------------------

/*
create()
  - Creates a new share entry.
  - Enforces:
      - owner_fp and path_rel must be non-empty
      - type is whitelisted
      - token is unique among current in-memory shares_ (up to 10 tries)
  - Persists immediately via save_atomic().
  - On persistence failure, it rolls back the in-memory insertion.

Architectural note:
  - This is "write-through" persistence: each mutation flushes to disk.
    This is great for correctness and simplicity; for very high churn you might
    batch writes, but correctness becomes more complex.
*/
bool ShareRegistry::create(const std::string& owner_fp,
                           const std::string& path_rel,
                           const std::string& type,
                           long long expires_sec,
                           ShareLink* out,
                           std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (owner_fp.empty() || path_rel.empty()) {
        if (err) *err = "missing owner_fp/path";
        return false;
    }
    if (type != "file" && type != "dir") {
        if (err) *err = "invalid type";
        return false;
    }

    // Token uniqueness:
    // Extremely likely to succeed on first attempt, but we still enforce
    // uniqueness in the current registry to avoid accidental collisions.
    std::string token;
    for (int i = 0; i < 10; i++) {
        token = gen_token_b64url_32();
        auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
        if (it == shares_.end()) break;
        token.clear();
    }
    if (token.empty()) {
        if (err) *err = "failed to generate unique token";
        return false;
    }

    ShareLink s;
    s.token = token;
    s.owner_fp = owner_fp;
    s.path = path_rel;
    s.type = type;
    s.created_at = now_utc_iso8601();
    s.expires_at = (expires_sec > 0) ? add_seconds_utc_iso8601(expires_sec) : "";
    s.downloads = 0;

    shares_.push_back(s);

    if (!save_atomic(err)) {
        // Rollback in-memory state if persistence fails.
        shares_.pop_back();
        return false;
    }

    if (out) *out = s;
    return true;
}

/*
revoke()
  - Removes a share by token.
  - Intended for admin/system-level revoke where ownership is not required.
  - Returns false if token not found.
*/
bool ShareRegistry::revoke(const std::string& token, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return false;

    shares_.erase(it);
    if (!save_atomic(err)) return false;
    return true;
}

/*
revoke_owner()
  - Owner-scoped revoke: only the owner may revoke their share.
  - Security property: it does NOT leak existence to non-owners:
      - If token doesn't exist -> false
      - If token exists but owner mismatch -> false
    Both cases look the same to the caller.
*/
bool ShareRegistry::revoke_owner(const std::string& owner_fp,
                                 const std::string& token,
                                 std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = std::find_if(shares_.begin(), shares_.end(),
                           [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return false;

    // Owner check (do not leak existence to other users)
    if (it->owner_fp != owner_fp) return false;

    shares_.erase(it);
    if (!save_atomic(err)) return false;
    return true;
}


//------------------------------------------------------------------------------
// Queries
//------------------------------------------------------------------------------

/*
find()
  - Returns the stored ShareLink if present.
  - Used by higher layers to resolve tokens into share metadata.
*/
std::optional<ShareLink> ShareRegistry::find(const std::string& token) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return std::nullopt;
    return *it;
}

/*
is_valid_now()
  - Returns:
      std::nullopt  => token not found
      true          => token exists and is not expired
      false         => token exists but is expired
  - If out != nullptr, returns the ShareLink metadata regardless of validity.
  - This is useful for APIs that want to differentiate "not found" from "expired"
    while still being able to show share info to admins/owners.
*/
std::optional<bool> ShareRegistry::is_valid_now(const std::string& token, ShareLink* out, std::string* err) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return std::nullopt;

    if (is_expired_utc(it->expires_at)) {
        if (out) *out = *it;
        return false;
    }

    if (out) *out = *it;
    (void)err;
    return true;
}

/*
increment_downloads()
  - Increments the download counter and persists immediately.
  - This gives a simple audit/analytics capability.
  - Note: For high-volume download links, write-through persistence may become
    expensive. Future optimization could:
      - keep an in-memory counter and flush periodically
      - or log increments append-only and compact later
*/
bool ShareRegistry::increment_downloads(const std::string& token, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return false;
    it->downloads += 1;
    return save_atomic(err);
}

} // namespace pqnas