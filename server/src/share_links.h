#pragma once
#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

namespace pqnas {

struct ShareLink {
    std::string token;      // b64url
    std::string owner_fp;   // fingerprint hex
    std::string path;       // rel path under user's storage root
    std::string type;       // "file" | "dir"
    std::string created_at; // ISO8601 UTC string
    std::string expires_at; // ISO8601 UTC string ("" => no expiry)
    std::uint64_t downloads = 0;
};

class ShareRegistry {
public:
    explicit ShareRegistry(std::string json_path);

    bool load(std::string* err = nullptr);

    // Returns a snapshot list (admin convenience)
    std::vector<ShareLink> list() const;

    // Create a share for owner_fp + path/type. expires_sec<=0 => no expiry.
    // Returns token on success.
    bool create(const std::string& owner_fp,
                const std::string& path_rel,
                const std::string& type,
                long long expires_sec,
                ShareLink* out,
                std::string* err);

    // Revoke token. Returns true if removed.
    bool revoke(const std::string& token, std::string* err);

    // Revoke token only if it belongs to owner_fp. Returns true if removed.
    // If token exists but is owned by someone else, returns false (no leak).
    bool revoke_owner(const std::string& owner_fp, const std::string& token, std::string* err);

    // Lookup without modifying downloads.
    std::optional<ShareLink> find(const std::string& token) const;

    // Returns:
    // - std::nullopt if token not found
    // - false if found but expired (and keeps it; caller may choose to revoke later)
    // - true if found & valid
    std::optional<bool> is_valid_now(const std::string& token, ShareLink* out, std::string* err) const;

    // Best-effort: increments downloads for token and saves.
    bool increment_downloads(const std::string& token, std::string* err);

private:
    // 🔒 protects shares_ + json_path_ + save_atomic()
    mutable std::mutex mu_;

    std::string json_path_;
    std::vector<ShareLink> shares_;

    bool save_atomic(std::string* err);

    static std::string now_utc_iso8601();
    static std::string add_seconds_utc_iso8601(long long seconds);
    static bool is_expired_utc(const std::string& expires_at_iso8601);
};

} // namespace pqnas
