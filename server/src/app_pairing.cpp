#include "app_pairing.h"

namespace pqnas {

long AppPairingStore::now_epoch_safe() const {
    return now_epoch_fn_ ? now_epoch_fn_() : 0L;
}

std::string AppPairingStore::random_b64url_safe(size_t nbytes) const {
    return random_b64url_fn_ ? random_b64url_fn_(nbytes) : std::string{};
}

bool AppPairingStore::start_pairing(const std::string& fingerprint_hex,
                                    const std::string& role,
                                    long ttl_sec,
                                    AppPairingSession* out,
                                    std::string* err) {
    if (err) err->clear();
    if (out) *out = AppPairingSession{};

    if (fingerprint_hex.empty()) {
        if (err) *err = "empty fingerprint";
        return false;
    }
    if (ttl_sec <= 0) {
        if (err) *err = "invalid ttl";
        return false;
    }

    const long now = now_epoch_safe();
    const std::string pair_id = random_b64url_safe(18);
    const std::string pair_token = random_b64url_safe(32);

    if (pair_id.empty() || pair_token.empty()) {
        if (err) *err = "rng failed";
        return false;
    }

    AppPairingSession s;
    s.pair_id = pair_id;
    s.pair_token = pair_token;
    s.fingerprint_hex = fingerprint_hex;
    s.role = role;
    s.issued_at = now;
    s.expires_at = now + ttl_sec;
    s.consumed = false;
    s.consumed_at = 0;
    s.consumed_device_id.clear();

    {
        std::lock_guard<std::mutex> lk(mu_);
        by_pair_id_[s.pair_id] = s;
        pair_id_by_token_[s.pair_token] = s.pair_id;
    }

    if (out) *out = s;
    return true;
}

bool AppPairingStore::get_by_pair_id(const std::string& pair_id,
                                     AppPairingSession* out,
                                     std::string* err) const {
    if (err) err->clear();
    if (out) *out = AppPairingSession{};

    if (pair_id.empty()) {
        if (err) *err = "empty pair_id";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto it = by_pair_id_.find(pair_id);
    if (it == by_pair_id_.end()) {
        if (err) *err = "pair_id_not_found";
        return false;
    }

    if (out) *out = it->second;
    return true;
}
    bool AppPairingStore::cancel_pairing(const std::string& pair_id,
                                         std::string* err) {
    if (err) err->clear();

    if (pair_id.empty()) {
        if (err) *err = "empty pair_id";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);

    auto it = by_pair_id_.find(pair_id);
    if (it == by_pair_id_.end()) {
        if (err) *err = "pair_id_not_found";
        return false;
    }

    pair_id_by_token_.erase(it->second.pair_token);
    by_pair_id_.erase(it);
    return true;
}
bool AppPairingStore::get_by_pair_token(const std::string& pair_token,
                                        AppPairingSession* out,
                                        std::string* err) const {
    if (err) err->clear();
    if (out) *out = AppPairingSession{};

    if (pair_token.empty()) {
        if (err) *err = "empty pair_token";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto it_id = pair_id_by_token_.find(pair_token);
    if (it_id == pair_id_by_token_.end()) {
        if (err) *err = "pair_token_not_found";
        return false;
    }

    auto it = by_pair_id_.find(it_id->second);
    if (it == by_pair_id_.end()) {
        if (err) *err = "pair_session_missing";
        return false;
    }

    if (out) *out = it->second;
    return true;
}

bool AppPairingStore::consume_pair_token(const std::string& pair_token,
                                         std::string* out_pair_id,
                                         std::string* out_fingerprint_hex,
                                         std::string* out_role,
                                         std::string* err) {
    if (err) err->clear();
    if (out_pair_id) out_pair_id->clear();
    if (out_fingerprint_hex) out_fingerprint_hex->clear();
    if (out_role) out_role->clear();

    if (pair_token.empty()) {
        if (err) *err = "empty pair_token";
        return false;
    }

    const long now = now_epoch_safe();

    std::lock_guard<std::mutex> lk(mu_);

    auto it_id = pair_id_by_token_.find(pair_token);
    if (it_id == pair_id_by_token_.end()) {
        if (err) *err = "pair_token_not_found";
        return false;
    }

    auto it = by_pair_id_.find(it_id->second);
    if (it == by_pair_id_.end()) {
        if (err) *err = "pair_session_missing";
        return false;
    }

    AppPairingSession& s = it->second;

    if (s.expires_at > 0 && now > s.expires_at) {
        if (err) *err = "pair_token_expired";
        return false;
    }

    if (s.consumed) {
        if (err) *err = "pair_token_already_consumed";
        return false;
    }

    s.consumed = true;
    s.consumed_at = now;

    if (out_pair_id) *out_pair_id = s.pair_id;
    if (out_fingerprint_hex) *out_fingerprint_hex = s.fingerprint_hex;
    if (out_role) *out_role = s.role;

    return true;
}

bool AppPairingStore::mark_consumed_device(const std::string& pair_id,
                                           const std::string& device_id,
                                           std::string* err) {
    if (err) err->clear();

    if (pair_id.empty()) {
        if (err) *err = "empty pair_id";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto it = by_pair_id_.find(pair_id);
    if (it == by_pair_id_.end()) {
        if (err) *err = "pair_id_not_found";
        return false;
    }

    it->second.consumed_device_id = device_id;
    return true;
}

void AppPairingStore::prune_expired(long now) {
    std::lock_guard<std::mutex> lk(mu_);

    for (auto it = by_pair_id_.begin(); it != by_pair_id_.end(); ) {
        const AppPairingSession& s = it->second;

        bool erase = false;

        if (s.expires_at > 0 && now > s.expires_at) {
            erase = true;
        }

        if (erase) {
            pair_id_by_token_.erase(s.pair_token);
            it = by_pair_id_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string AppPairingStore::build_pair_qr_uri(
    const std::string& origin,
    const std::string& pair_token,
    const std::string& app_name,
    const std::string& tls_pin_sha256,
    const std::function<std::string(const std::string&)>& url_encode) {

    const auto enc = [&](const std::string& s) -> std::string {
        return url_encode ? url_encode(s) : s;
    };

    return "dna://pair?v=2"
           "&pt=" + enc(pair_token) +
           "&origin=" + enc(origin) +
           "&app=" + enc(app_name) +
           "&tls_pin_sha256=" + enc(tls_pin_sha256);
}

} // namespace pqnas