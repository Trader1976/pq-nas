#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <string>

namespace pqnas {

struct AppPairingSession {
    std::string pair_id;
    std::string pair_token;
    std::string fingerprint_hex;
    std::string role;
    long issued_at = 0;
    long expires_at = 0;
    bool consumed = false;
    long consumed_at = 0;
    std::string consumed_device_id;
};

class AppPairingStore {
public:
    AppPairingStore() = default;

    void set_now_epoch_fn(std::function<long()> fn) { now_epoch_fn_ = std::move(fn); }
    void set_random_b64url_fn(std::function<std::string(size_t)> fn) { random_b64url_fn_ = std::move(fn); }

    bool start_pairing(const std::string& fingerprint_hex,
                       const std::string& role,
                       long ttl_sec,
                       AppPairingSession* out,
                       std::string* err);

    bool get_by_pair_id(const std::string& pair_id,
                        AppPairingSession* out,
                        std::string* err) const;

    bool get_by_pair_token(const std::string& pair_token,
                           AppPairingSession* out,
                           std::string* err) const;

    bool consume_pair_token(const std::string& pair_token,
                            std::string* out_pair_id,
                            std::string* out_fingerprint_hex,
                            std::string* out_role,
                            std::string* err);

    bool mark_consumed_device(const std::string& pair_id,
                              const std::string& device_id,
                              std::string* err);

    void prune_expired(long now);

    static std::string build_pair_qr_uri(const std::string& origin,
                                         const std::string& pair_token,
                                         const std::string& app_name,
                                         const std::function<std::string(const std::string&)>& url_encode);

private:
    long now_epoch_safe() const;
    std::string random_b64url_safe(size_t nbytes) const;

    std::function<long()> now_epoch_fn_;
    std::function<std::string(size_t)> random_b64url_fn_;

    std::map<std::string, AppPairingSession> by_pair_id_;
    std::map<std::string, std::string> pair_id_by_token_;
    mutable std::mutex mu_;
};

} // namespace pqnas