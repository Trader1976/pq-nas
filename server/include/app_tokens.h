#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace pqnas {

struct TrustedAppDevice {
    std::string device_id;
    std::string fingerprint_hex;
    std::string role;

    std::string platform;
    std::string device_name;
    std::string app_version;

    std::string created_at;
    std::string last_seen_at;
    std::string last_ip;

	std::string device_model;
	std::string device_manufacturer;
	std::string os_version;

    bool revoked = false;
};

struct AppAccessSession {
    std::string access_token_hash;
    std::string device_id;
    std::string fingerprint_hex;
    std::string role;

    long issued_at = 0;
    long expires_at = 0;

    bool revoked = false;
};

struct AppRefreshSession {
    std::string refresh_token_hash;
    std::string device_id;
    std::string fingerprint_hex;

    long issued_at = 0;
    long expires_at = 0;

    bool revoked = false;
};

class AppTokenStore {
public:
    AppTokenStore() = default;

    bool load(const std::string& path, std::string* err);
    bool save(std::string* err) const;

    void set_now_epoch_fn(std::function<long()> fn) { now_epoch_fn_ = std::move(fn); }
    void set_now_iso_utc_fn(std::function<std::string()> fn) { now_iso_utc_fn_ = std::move(fn); }
    void set_random_b64url_fn(std::function<std::string(size_t)> fn) { random_b64url_fn_ = std::move(fn); }

	bool mint_from_approved_fingerprint(
    	const std::string& fingerprint_hex,
    	const std::string& role,
    	const std::string& device_name,
	    const std::string& platform,
    	const std::string& app_version,
    	const std::string& device_model,
	    const std::string& device_manufacturer,
    	const std::string& os_version,
	    const std::string& client_ip,
    	std::string* out_device_id,
	    std::string* out_access_token,
    	long* out_access_exp,
	    std::string* out_refresh_token,
    	long* out_refresh_exp,
    	std::string* err);

    bool verify_access_token(
        const std::string& raw_access_token,
        std::string* out_fingerprint_hex,
        std::string* out_role,
        std::string* out_device_id,
        std::string* err);

    bool refresh_access_token(
        const std::string& raw_refresh_token,
        const std::string& device_id,
        const std::string& client_ip,
        std::string* out_fingerprint_hex,
        std::string* out_role,
        std::string* out_access_token,
        long* out_access_exp,
        std::string* err);

    void prune_expired_access_tokens(long now);
    void prune_expired_refresh_tokens(long now);

    bool revoke_device(const std::string& device_id, std::string* err);

    bool get_device(const std::string& device_id, TrustedAppDevice* out) const;
    bool get_refresh_expiry_for_device(const std::string& device_id,
                                   long* out_expires_at) const;
    std::vector<TrustedAppDevice> list_devices_for_fingerprint(const std::string& fingerprint_hex) const;

private:
    long now_epoch_safe() const;
    std::string now_iso_utc_safe() const;
    std::string random_b64url_safe(size_t nbytes) const;

    std::string make_device_id() const;
    std::string make_access_token() const;
    std::string make_refresh_token() const;

    static std::string sha256_hex_lower(const std::string& s);

    TrustedAppDevice* find_device_mut(const std::string& device_id);
    const TrustedAppDevice* find_device(const std::string& device_id) const;

    std::string path_;
    std::map<std::string, TrustedAppDevice> devices_by_id_;
    std::map<std::string, AppRefreshSession> refresh_by_hash_;
    std::map<std::string, AppAccessSession> access_by_hash_;

    std::function<long()> now_epoch_fn_;
    std::function<std::string()> now_iso_utc_fn_;
    std::function<std::string(size_t)> random_b64url_fn_;

    mutable std::mutex mu_;
};

} // namespace pqnas