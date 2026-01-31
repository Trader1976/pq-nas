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

static std::string b64url_enc(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

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

ShareRegistry::ShareRegistry(std::string json_path)
    : json_path_(std::move(json_path)) {}

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
            try {
                if (it["downloads"].is_number_unsigned()) s.downloads = it["downloads"].get<std::uint64_t>();
                else if (it["downloads"].is_number_integer())  s.downloads = (std::uint64_t)std::max<long long>(0, it["downloads"].get<long long>());
                else if (it["downloads"].is_string()) s.downloads = (std::uint64_t)std::stoull(it["downloads"].get<std::string>());
            } catch (...) {}
        }

        if (s.token.empty() || s.owner_fp.empty() || s.path.empty() || s.type.empty()) continue;
        if (s.type != "file" && s.type != "dir") continue;

        shares_.push_back(std::move(s));
    }

    return true;
}

std::vector<ShareLink> ShareRegistry::list() const {
    std::lock_guard<std::mutex> lk(mu_);
    return shares_;
}

static std::string gen_token_b64url_32() {
    unsigned char rnd[32];
    randombytes_buf(rnd, sizeof(rnd));
    return b64url_enc(rnd, sizeof(rnd));
}

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

bool ShareRegistry::is_expired_utc(const std::string& expires_at_iso8601) {
    if (expires_at_iso8601.empty()) return false;
    std::tm tm{};
    if (!iso8601_utc_to_tm(expires_at_iso8601, &tm)) return false; // fail-open? we choose NOT expired on parse issues
    std::time_t exp = timegm_portable(&tm);
    std::time_t now = std::time(nullptr);
    return exp > 0 && now >= exp;
}

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

    // Token uniqueness (extremely likely first try, but enforce anyway)
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
        // rollback
        shares_.pop_back();
        return false;
    }

    if (out) *out = s;
    return true;
}

bool ShareRegistry::revoke(const std::string& token, std::string* err) {
	std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return false;

    shares_.erase(it);
    if (!save_atomic(err)) return false;
    return true;
}

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

std::optional<ShareLink> ShareRegistry::find(const std::string& token) const {
	std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return std::nullopt;
    return *it;
}

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

bool ShareRegistry::increment_downloads(const std::string& token, std::string* err) {
	std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(shares_.begin(), shares_.end(), [&](const ShareLink& s){ return s.token == token; });
    if (it == shares_.end()) return false;
    it->downloads += 1;
    return save_atomic(err);
}

} // namespace pqnas
