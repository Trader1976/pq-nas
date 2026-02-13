#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <vector>
#include <cstdint>

namespace pqnas {

struct UserRec {
    std::string fingerprint;   // hex (identity)

    // Existing fields
    std::string name;
    std::string role;          // "admin" | "user"
    std::string status;        // "enabled" | "disabled" | "revoked"
    std::string added_at;      // ISO-8601 UTC
    std::string last_seen;     // ISO-8601 UTC
    std::string notes;
    std::string avatar_url;

    // New: admin profile metadata (non-security)
    std::string group;         // e.g. "Family", "Work"
    std::string email;
    std::string address;

    // New: storage metadata (Option A; metadata only for now)
    std::string storage_state; // "unallocated" | "allocated"
    std::uint64_t quota_bytes = 0;
    std::string root_rel;      // e.g. "users/<fingerprint>"
    std::string storage_set_at; // ISO-8601 UTC
    std::string storage_set_by; // actor fingerprint (hex)
};

class UsersRegistry {
public:
    bool load(const std::string& path);
    bool save(const std::string& path) const;

    // Lookups
    bool exists(const std::string& fp_hex) const;
    std::optional<UserRec> get(const std::string& fp_hex) const;

    // Policy helpers
    bool is_enabled_user(const std::string& fp_hex) const;   // status == enabled
    bool is_admin_enabled(const std::string& fp_hex) const;  // enabled + role==admin
    std::string role_of(const std::string& fp_hex) const;

    // Mutations (auditable by caller)
    bool ensure_present_disabled_user(const std::string& fp_hex, const std::string& now_iso);
    bool upsert(const UserRec& u);
    bool set_status(const std::string& fp_hex, const std::string& status);
    bool set_role(const std::string& fp_hex, const std::string& role);
    bool set_name_notes(const std::string& fp_hex, const std::string& name, const std::string& notes);
    bool touch_last_seen(const std::string& fp_hex, const std::string& now_iso);
    bool erase(const std::string& fp_hex);

    // Snapshot for API
    std::unordered_map<std::string, UserRec> snapshot() const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, UserRec> by_fp_;
};

} // namespace pqnas
