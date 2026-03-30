#include "app_tokens.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

using nlohmann::json;

namespace pqnas {
namespace {

constexpr long kAccessTtlSec = 15 * 60;                 // 15 minutes
constexpr long kRefreshTtlSec = 365L * 24 * 3600;    // 1 year

static std::string json_string_or_empty(const json& j, const char* key) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::string{};
    return it->get<std::string>();
}

static long json_long_or_default(const json& j, const char* key, long defv = 0) {
    auto it = j.find(key);
    if (it == j.end()) return defv;
    if (it->is_number_integer()) return it->get<long>();
    if (it->is_number_unsigned()) return static_cast<long>(it->get<unsigned long long>());
    return defv;
}

static bool json_bool_or_default(const json& j, const char* key, bool defv = false) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_boolean()) return defv;
    return it->get<bool>();
}

static bool write_json_atomic(const std::string& path, const json& j, std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    const std::filesystem::path p(path);
    const std::filesystem::path dir = p.parent_path();

    if (!dir.empty()) {
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            if (err) *err = "create_directories failed: " + ec.message();
            return false;
        }
    }

    const std::filesystem::path tmp =
        dir / (p.filename().string() + ".tmp.app_auth");

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            if (err) *err = "open tmp failed";
            return false;
        }
        f << j.dump(2);
        f.flush();
        if (!f.good()) {
            if (err) *err = "write tmp failed";
            return false;
        }
    }

    std::filesystem::rename(tmp, p, ec);
    if (!ec) return true;

    // Best-effort Windows-ish fallback pattern used elsewhere in tree.
    std::filesystem::remove(p, ec);
    ec.clear();
    std::filesystem::rename(tmp, p, ec);
    if (ec) {
        if (err) *err = "rename(tmp->target) failed: " + ec.message();
        return false;
    }
    return true;
}

} // namespace

std::string AppTokenStore::sha256_hex_lower(const std::string& s) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    if (!c) return std::string{};

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(c, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(c);
        return std::string{};
    }
    if (EVP_DigestUpdate(c, s.data(), s.size()) != 1) {
        EVP_MD_CTX_free(c);
        return std::string{};
    }
    if (EVP_DigestFinal_ex(c, md, &md_len) != 1) {
        EVP_MD_CTX_free(c);
        return std::string{};
    }
    EVP_MD_CTX_free(c);

    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        unsigned char b = md[i];
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

long AppTokenStore::now_epoch_safe() const {
    return now_epoch_fn_ ? now_epoch_fn_() : 0L;
}

std::string AppTokenStore::now_iso_utc_safe() const {
    return now_iso_utc_fn_ ? now_iso_utc_fn_() : std::string{};
}

std::string AppTokenStore::random_b64url_safe(size_t nbytes) const {
    return random_b64url_fn_ ? random_b64url_fn_(nbytes) : std::string{};
}

std::string AppTokenStore::make_device_id() const {
    return sha256_hex_lower("device|" + random_b64url_safe(24) + "|" + now_iso_utc_safe());
}

std::string AppTokenStore::make_access_token() const {
    return random_b64url_safe(32);
}

std::string AppTokenStore::make_refresh_token() const {
    return random_b64url_safe(48);
}

TrustedAppDevice* AppTokenStore::find_device_mut(const std::string& device_id) {
    auto it = devices_by_id_.find(device_id);
    if (it == devices_by_id_.end()) return nullptr;
    return &it->second;
}

const TrustedAppDevice* AppTokenStore::find_device(const std::string& device_id) const {
    auto it = devices_by_id_.find(device_id);
    if (it == devices_by_id_.end()) return nullptr;
    return &it->second;
}

bool AppTokenStore::load(const std::string& path, std::string* err) {
    if (err) err->clear();

    std::lock_guard<std::mutex> lk(mu_);

    path_ = path;
    devices_by_id_.clear();
    refresh_by_hash_.clear();
    access_by_hash_.clear();

    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        if (ec) {
            if (err) *err = "exists(" + path + ") failed: " + ec.message();
            return false;
        }
        return true; // missing file => clean empty state
    }

    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "open(" + path + ") failed";
        return false;
    }

    json root;
    try {
        f >> root;
    } catch (const std::exception& e) {
        if (err) *err = std::string("json parse failed: ") + e.what();
        return false;
    }

    if (!root.is_object()) {
        if (err) *err = "root is not object";
        return false;
    }

    const int version = root.value("version", 0);
    if (version != 1) {
        if (err) *err = "unsupported version";
        return false;
    }

    auto it_dev = root.find("devices");
    if (it_dev != root.end()) {
        if (!it_dev->is_object()) {
            if (err) *err = "devices is not object";
            return false;
        }

        for (auto it = it_dev->begin(); it != it_dev->end(); ++it) {
            if (!it.value().is_object()) {
                if (err) *err = "device entry is not object";
                return false;
            }
            const json& dj = it.value();

            TrustedAppDevice d;
            d.device_id       = json_string_or_empty(dj, "device_id");
            d.fingerprint_hex = json_string_or_empty(dj, "fingerprint_hex");
            d.role            = json_string_or_empty(dj, "role");
            d.platform        = json_string_or_empty(dj, "platform");
            d.device_name     = json_string_or_empty(dj, "device_name");
            d.app_version     = json_string_or_empty(dj, "app_version");
            d.device_model        = json_string_or_empty(dj, "device_model");
            d.device_manufacturer = json_string_or_empty(dj, "device_manufacturer");
            d.os_version          = json_string_or_empty(dj, "os_version");
            d.created_at      = json_string_or_empty(dj, "created_at");
            d.last_seen_at    = json_string_or_empty(dj, "last_seen_at");
            d.last_ip         = json_string_or_empty(dj, "last_ip");
            d.revoked         = json_bool_or_default(dj, "revoked", false);

            if (d.device_id.empty()) d.device_id = it.key();
            if (d.device_id.empty()) {
                if (err) *err = "device entry missing device_id";
                return false;
            }

            devices_by_id_[d.device_id] = std::move(d);
        }
    }

    auto it_ref = root.find("refresh_tokens");
    if (it_ref != root.end()) {
        if (!it_ref->is_object()) {
            if (err) *err = "refresh_tokens is not object";
            return false;
        }

        for (auto it = it_ref->begin(); it != it_ref->end(); ++it) {
            if (!it.value().is_object()) {
                if (err) *err = "refresh token entry is not object";
                return false;
            }
            const json& rj = it.value();

            AppRefreshSession rs;
            rs.refresh_token_hash = json_string_or_empty(rj, "refresh_token_hash");
            rs.device_id          = json_string_or_empty(rj, "device_id");
            rs.fingerprint_hex    = json_string_or_empty(rj, "fingerprint_hex");
            rs.issued_at          = json_long_or_default(rj, "issued_at", 0);
            rs.expires_at         = json_long_or_default(rj, "expires_at", 0);
            rs.revoked            = json_bool_or_default(rj, "revoked", false);

            if (rs.refresh_token_hash.empty()) rs.refresh_token_hash = it.key();
            if (rs.refresh_token_hash.empty()) {
                if (err) *err = "refresh token entry missing hash";
                return false;
            }

            refresh_by_hash_[rs.refresh_token_hash] = std::move(rs);
        }
    }

    return true;
}

bool AppTokenStore::save(std::string* err) const {
    if (err) err->clear();

    std::lock_guard<std::mutex> lk(mu_);

    if (path_.empty()) {
        if (err) *err = "path not set";
        return false;
    }

    json root = json::object();
    root["version"] = 1;
    root["devices"] = json::object();
    root["refresh_tokens"] = json::object();

    for (const auto& kv : devices_by_id_) {
        const auto& d = kv.second;
        root["devices"][kv.first] = json{
            {"device_id", d.device_id},
            {"fingerprint_hex", d.fingerprint_hex},
            {"role", d.role},
            {"platform", d.platform},
            {"device_name", d.device_name},
            {"app_version", d.app_version},
            {"device_model", d.device_model},
            {"device_manufacturer", d.device_manufacturer},
            {"os_version", d.os_version},
            {"created_at", d.created_at},
            {"last_seen_at", d.last_seen_at},
            {"last_ip", d.last_ip},
            {"revoked", d.revoked}
        };
    }

    for (const auto& kv : refresh_by_hash_) {
        const auto& r = kv.second;
        root["refresh_tokens"][kv.first] = json{
            {"refresh_token_hash", r.refresh_token_hash},
            {"device_id", r.device_id},
            {"fingerprint_hex", r.fingerprint_hex},
            {"issued_at", r.issued_at},
            {"expires_at", r.expires_at},
            {"revoked", r.revoked}
        };
    }

    return write_json_atomic(path_, root, err);
}

bool AppTokenStore::mint_from_approved_fingerprint(
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
    std::string* err) {

    if (err) err->clear();

    if (fingerprint_hex.empty()) {
        if (err) *err = "empty fingerprint";
        return false;
    }

    const long now = now_epoch_safe();
    const std::string now_iso = now_iso_utc_safe();

    const std::string device_id = make_device_id();
    const std::string access_token = make_access_token();
    const std::string refresh_token = make_refresh_token();
    if (device_id.empty() || access_token.empty() || refresh_token.empty()) {
        if (err) *err = "token rng failed";
        return false;
    }

    const std::string access_hash = sha256_hex_lower(access_token);
    const std::string refresh_hash = sha256_hex_lower(refresh_token);
    if (access_hash.empty() || refresh_hash.empty()) {
        if (err) *err = "token hash failed";
        return false;
    }

    const long access_exp = now + kAccessTtlSec;
    const long refresh_exp = now + kRefreshTtlSec;

    {
        std::lock_guard<std::mutex> lk(mu_);

        TrustedAppDevice d;
        d.device_id = device_id;
        d.fingerprint_hex = fingerprint_hex;
        d.role = role;
        d.platform = platform.empty() ? "android" : platform;
        d.device_name = device_name;
        d.app_version = app_version;
        d.device_model = device_model;
        d.device_manufacturer = device_manufacturer;
        d.os_version = os_version;
        d.created_at = now_iso;
        d.last_seen_at = now_iso;
        d.last_ip = client_ip;
        d.revoked = false;
        devices_by_id_[device_id] = std::move(d);

        AppRefreshSession rs;
        rs.refresh_token_hash = refresh_hash;
        rs.device_id = device_id;
        rs.fingerprint_hex = fingerprint_hex;
        rs.issued_at = now;
        rs.expires_at = refresh_exp;
        rs.revoked = false;
        refresh_by_hash_[refresh_hash] = std::move(rs);

        AppAccessSession as;
        as.access_token_hash = access_hash;
        as.device_id = device_id;
        as.fingerprint_hex = fingerprint_hex;
        as.role = role;
        as.issued_at = now;
        as.expires_at = access_exp;
        as.revoked = false;
        access_by_hash_[access_hash] = std::move(as);
    }

    if (out_device_id) *out_device_id = device_id;
    if (out_access_token) *out_access_token = access_token;
    if (out_access_exp) *out_access_exp = access_exp;
    if (out_refresh_token) *out_refresh_token = refresh_token;
    if (out_refresh_exp) *out_refresh_exp = refresh_exp;

    std::string save_err;
    if (!save(&save_err)) {
        if (err) *err = "save failed: " + save_err;
        return false;
    }

    return true;
}

bool AppTokenStore::verify_access_token(
    const std::string& raw_access_token,
    std::string* out_fingerprint_hex,
    std::string* out_role,
    std::string* out_device_id,
    std::string* err) {

    if (err) err->clear();
    if (raw_access_token.empty()) {
        if (err) *err = "empty access token";
        return false;
    }

    const std::string h = sha256_hex_lower(raw_access_token);
    const long now = now_epoch_safe();

    std::lock_guard<std::mutex> lk(mu_);

    auto it = access_by_hash_.find(h);
    if (it == access_by_hash_.end()) {
        if (err) *err = "access token not found";
        return false;
    }

    const AppAccessSession& as = it->second;
    if (as.revoked) {
        if (err) *err = "access token revoked";
        return false;
    }
    if (as.expires_at > 0 && now > as.expires_at) {
        if (err) *err = "access token expired";
        return false;
    }

    const TrustedAppDevice* d = find_device(as.device_id);
    if (!d) {
        if (err) *err = "device missing";
        return false;
    }
    if (d->revoked) {
        if (err) *err = "device revoked";
        return false;
    }

    if (out_fingerprint_hex) *out_fingerprint_hex = as.fingerprint_hex;
    if (out_role) *out_role = as.role;
    if (out_device_id) *out_device_id = as.device_id;
    return true;
}

bool AppTokenStore::refresh_access_token(
    const std::string& raw_refresh_token,
    const std::string& device_id,
    const std::string& client_ip,
    std::string* out_fingerprint_hex,
    std::string* out_role,
    std::string* out_access_token,
    long* out_access_exp,
    std::string* err) {

    if (err) err->clear();

    if (raw_refresh_token.empty()) {
        if (err) *err = "empty refresh token";
        return false;
    }
    if (device_id.empty()) {
        if (err) *err = "empty device_id";
        return false;
    }

    const std::string h = sha256_hex_lower(raw_refresh_token);
    const long now = now_epoch_safe();
    const std::string now_iso = now_iso_utc_safe();

    std::string fingerprint_hex;
    std::string role;
    std::string new_access_token;
    long new_access_exp = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = refresh_by_hash_.find(h);
        if (it == refresh_by_hash_.end()) {
            if (err) *err = "refresh token not found";
            return false;
        }

        const AppRefreshSession& rs = it->second;
        if (rs.revoked) {
            if (err) *err = "refresh token revoked";
            return false;
        }
        if (rs.expires_at > 0 && now > rs.expires_at) {
            if (err) *err = "refresh token expired";
            return false;
        }
        if (rs.device_id != device_id) {
            if (err) *err = "device mismatch";
            return false;
        }

        TrustedAppDevice* d = find_device_mut(device_id);
        if (!d) {
            if (err) *err = "device missing";
            return false;
        }
        if (d->revoked) {
            if (err) *err = "device revoked";
            return false;
        }

        fingerprint_hex = rs.fingerprint_hex;
        role = d->role;

        new_access_token = make_access_token();
        if (new_access_token.empty()) {
            if (err) *err = "access token rng failed";
            return false;
        }

        const std::string access_hash = sha256_hex_lower(new_access_token);
        if (access_hash.empty()) {
            if (err) *err = "access token hash failed";
            return false;
        }

        new_access_exp = now + kAccessTtlSec;

        AppAccessSession as;
        as.access_token_hash = access_hash;
        as.device_id = device_id;
        as.fingerprint_hex = fingerprint_hex;
        as.role = role;
        as.issued_at = now;
        as.expires_at = new_access_exp;
        as.revoked = false;
        access_by_hash_[access_hash] = std::move(as);

        d->last_seen_at = now_iso;
        d->last_ip = client_ip;
    }

    if (out_fingerprint_hex) *out_fingerprint_hex = fingerprint_hex;
    if (out_role) *out_role = role;
    if (out_access_token) *out_access_token = new_access_token;
    if (out_access_exp) *out_access_exp = new_access_exp;

    return true;
}

void AppTokenStore::prune_expired_access_tokens(long now) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = access_by_hash_.begin(); it != access_by_hash_.end();) {
        const auto& s = it->second;
        if ((s.expires_at > 0 && now > s.expires_at) || s.revoked) it = access_by_hash_.erase(it);
        else ++it;
    }
}

void AppTokenStore::prune_expired_refresh_tokens(long now) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = refresh_by_hash_.begin(); it != refresh_by_hash_.end();) {
        const auto& s = it->second;
        if ((s.expires_at > 0 && now > s.expires_at) || s.revoked) it = refresh_by_hash_.erase(it);
        else ++it;
    }
}

bool AppTokenStore::revoke_device(const std::string& device_id, std::string* err) {
    if (err) err->clear();
    if (device_id.empty()) {
        if (err) *err = "empty device_id";
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(mu_);

        TrustedAppDevice* d = find_device_mut(device_id);
        if (!d) {
            if (err) *err = "device not found";
            return false;
        }
        d->revoked = true;

        for (auto& kv : refresh_by_hash_) {
            if (kv.second.device_id == device_id) kv.second.revoked = true;
        }
        for (auto& kv : access_by_hash_) {
            if (kv.second.device_id == device_id) kv.second.revoked = true;
        }
    }

    std::string save_err;
    if (!save(&save_err)) {
        if (err) *err = "save failed: " + save_err;
        return false;
    }
    return true;
}
    bool AppTokenStore::get_refresh_expiry_for_device(const std::string& device_id,
                                                      long* out_expires_at) const {
    if (out_expires_at) *out_expires_at = 0;
    if (device_id.empty()) return false;

    std::lock_guard<std::mutex> lk(mu_);

    long best = 0;
    bool found = false;

    for (const auto& kv : refresh_by_hash_) {
        const auto& rs = kv.second;
        if (rs.device_id != device_id) continue;
        if (rs.revoked) continue;

        if (!found || rs.expires_at > best) {
            best = rs.expires_at;
            found = true;
        }
    }

    if (!found) return false;
    if (out_expires_at) *out_expires_at = best;
    return true;
}

bool AppTokenStore::get_device(const std::string& device_id, TrustedAppDevice* out) const {
    if (!out) return false;
    std::lock_guard<std::mutex> lk(mu_);
    const TrustedAppDevice* d = find_device(device_id);
    if (!d) return false;
    *out = *d;
    return true;
}

std::vector<TrustedAppDevice> AppTokenStore::list_devices_for_fingerprint(const std::string& fingerprint_hex) const {
    std::vector<TrustedAppDevice> out;
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& kv : devices_by_id_) {
        if (kv.second.fingerprint_hex == fingerprint_hex) out.push_back(kv.second);
    }
    return out;
}

} // namespace pqnas