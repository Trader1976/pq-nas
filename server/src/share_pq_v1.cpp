#include "share_pq_v1.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>

using nlohmann::json;

namespace pqnas {
namespace {

static std::string json_string_or(const json& j, const char* key, const std::string& defv = {}) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return defv;
    return it->get<std::string>();
}

static int json_int_or(const json& j, const char* key, int defv = 0) {
    auto it = j.find(key);
    if (it == j.end()) return defv;
    if (it->is_number_integer()) return it->get<int>();
    if (it->is_number_unsigned()) return static_cast<int>(it->get<unsigned int>());
    return defv;
}

static std::int64_t json_i64_or(const json& j, const char* key, std::int64_t defv = 0) {
    auto it = j.find(key);
    if (it == j.end()) return defv;
    if (it->is_number_integer()) return it->get<std::int64_t>();
    if (it->is_number_unsigned()) return static_cast<std::int64_t>(it->get<std::uint64_t>());
    return defv;
}

static std::uint64_t json_u64_or(const json& j, const char* key, std::uint64_t defv = 0) {
    auto it = j.find(key);
    if (it == j.end()) return defv;
    if (it->is_number_unsigned()) return it->get<std::uint64_t>();
    if (it->is_number_integer()) {
        const auto v = it->get<std::int64_t>();
        return v < 0 ? 0 : static_cast<std::uint64_t>(v);
    }
    return defv;
}

static std::vector<std::string> json_string_array_or(const json& j, const char* key) {
    std::vector<std::string> out;
    auto it = j.find(key);
    if (it == j.end() || !it->is_array()) return out;
    for (const auto& v : *it) {
        if (v.is_string()) out.push_back(v.get<std::string>());
    }
    return out;
}

static json snapshot_to_json(const PqShareSnapshotV1& s) {
    return json{
        {"size_bytes", s.size_bytes},
        {"mtime_epoch", s.mtime_epoch},
        {"sha256_hex", s.sha256_hex}
    };
}

static bool snapshot_from_json(const json& j, PqShareSnapshotV1* out) {
    if (!out || !j.is_object()) return false;
    out->size_bytes = json_u64_or(j, "size_bytes", 0);
    out->mtime_epoch = json_i64_or(j, "mtime_epoch", 0);
    out->sha256_hex = json_string_or(j, "sha256_hex", "");
    return true;
}

static json manifest_to_json(const PqShareManifestV1& m) {
    return json{
        {"version", m.version},
        {"share_token", m.share_token},
        {"kind", m.kind},
        {"owner_fp", m.owner_fp},
        {"rel_path", m.rel_path},
        {"created_at", m.created_at},
        {"expires_at", m.expires_at},
        {"state", m.state},
        {"snapshot", snapshot_to_json(m.snapshot)},
        {"recipient_device_ids", m.recipient_device_ids},
        {"kem_alg", m.kem_alg},
        {"sig_alg", m.sig_alg},
        {"crypto_backend", m.crypto_backend}
    };
}

static bool manifest_from_json(const json& j, PqShareManifestV1* out) {
    if (!out || !j.is_object()) return false;
    out->version = json_int_or(j, "version", 1);
    out->share_token = json_string_or(j, "share_token", "");
    out->kind = json_string_or(j, "kind", "");
    out->owner_fp = json_string_or(j, "owner_fp", "");
    out->rel_path = json_string_or(j, "rel_path", "");
    out->created_at = json_string_or(j, "created_at", "");
    out->expires_at = json_string_or(j, "expires_at", "");
    out->state = json_string_or(j, "state", "");
    out->recipient_device_ids = json_string_array_or(j, "recipient_device_ids");
    out->kem_alg = json_string_or(j, "kem_alg", "");
    out->sig_alg = json_string_or(j, "sig_alg", "");
    out->crypto_backend = json_string_or(j, "crypto_backend", "");
    auto it = j.find("snapshot");
    if (it == j.end() || !snapshot_from_json(*it, &out->snapshot)) return false;
    return !out->share_token.empty();
}

static json invite_to_json(const PqShareInviteV1& i) {
    return json{
        {"version", i.version},
        {"invite_id", i.invite_id},
        {"share_token", i.share_token},
        {"owner_fp", i.owner_fp},
        {"state", i.state},
        {"created_at", i.created_at},
        {"expires_at", i.expires_at},
        {"max_claims", i.max_claims},
        {"claim_count", i.claim_count},
        {"claimed_recipient_device_id", i.claimed_recipient_device_id},
        {"label_hint", i.label_hint}
    };
}

static bool invite_from_json(const json& j, PqShareInviteV1* out) {
    if (!out || !j.is_object()) return false;
    out->version = json_int_or(j, "version", 1);
    out->invite_id = json_string_or(j, "invite_id", "");
    out->share_token = json_string_or(j, "share_token", "");
    out->owner_fp = json_string_or(j, "owner_fp", "");
    out->state = json_string_or(j, "state", "");
    out->created_at = json_string_or(j, "created_at", "");
    out->expires_at = json_string_or(j, "expires_at", "");
    out->max_claims = json_int_or(j, "max_claims", 1);
    out->claim_count = json_int_or(j, "claim_count", 0);
    out->claimed_recipient_device_id = json_string_or(j, "claimed_recipient_device_id", "");
    out->label_hint = json_string_or(j, "label_hint", "");
    return !out->invite_id.empty();
}

static json recipient_to_json(const PqShareRecipientDeviceV1& d) {
    return json{
        {"version", d.version},
        {"owner_fp", d.owner_fp},
        {"recipient_device_id", d.recipient_device_id},
        {"label", d.label},
        {"note", d.note},
        {"state", d.state},
        {"created_at", d.created_at},
        {"updated_at", d.updated_at},
        {"last_used_at", d.last_used_at},
        {"registered_via", d.registered_via},
        {"invite_id", d.invite_id},
        {"kem_alg", d.kem_alg},
        {"key_id", d.key_id},
        {"public_key_b64", d.public_key_b64}
    };
}

static bool recipient_from_json(const json& j, PqShareRecipientDeviceV1* out) {
    if (!out || !j.is_object()) return false;
    out->version = json_int_or(j, "version", 1);
    out->owner_fp = json_string_or(j, "owner_fp", "");
    out->recipient_device_id = json_string_or(j, "recipient_device_id", "");
    out->label = json_string_or(j, "label", "");
    out->note = json_string_or(j, "note", "");
    out->state = json_string_or(j, "state", "");
    out->created_at = json_string_or(j, "created_at", "");
    out->updated_at = json_string_or(j, "updated_at", "");
    out->last_used_at = json_string_or(j, "last_used_at", "");
    out->registered_via = json_string_or(j, "registered_via", "");
    out->invite_id = json_string_or(j, "invite_id", "");
    out->kem_alg = json_string_or(j, "kem_alg", "");
    out->key_id = json_string_or(j, "key_id", "");
    out->public_key_b64 = json_string_or(j, "public_key_b64", "");
    return !out->owner_fp.empty() && !out->recipient_device_id.empty();
}

static json session_to_json(const PqShareRecipientSessionV1& s) {
    return json{
        {"version", s.version},
        {"session_id", s.session_id},
        {"owner_fp", s.owner_fp},
        {"recipient_device_id", s.recipient_device_id},
        {"created_at", s.created_at},
        {"expires_at", s.expires_at},
        {"last_used_at", s.last_used_at},
        {"state", s.state}
    };
}

static bool session_from_json(const json& j, PqShareRecipientSessionV1* out) {
    if (!out || !j.is_object()) return false;
    out->version = json_int_or(j, "version", 1);
    out->session_id = json_string_or(j, "session_id", "");
    out->owner_fp = json_string_or(j, "owner_fp", "");
    out->recipient_device_id = json_string_or(j, "recipient_device_id", "");
    out->created_at = json_string_or(j, "created_at", "");
    out->expires_at = json_string_or(j, "expires_at", "");
    out->last_used_at = json_string_or(j, "last_used_at", "");
    out->state = json_string_or(j, "state", "");
    return !out->session_id.empty();
}
static json open_stream_session_to_json(const PqShareOpenStreamSessionV1& s) {
    return json{
        {"open_id", s.open_id},
        {"owner_fp", s.owner_fp},
        {"share_token", s.share_token},
        {"recipient_session_id", s.recipient_session_id},
        {"recipient_device_id", s.recipient_device_id},
        {"rel_path", s.rel_path},
        {"file_name", s.file_name},
        {"mime_type", s.mime_type},
        {"file_size_bytes", s.file_size_bytes},
        {"chunk_size_bytes", s.chunk_size_bytes},
        {"chunk_count", s.chunk_count},
        {"snapshot_mtime_epoch", s.snapshot_mtime_epoch},
        {"snapshot_sha256_hex", s.snapshot_sha256_hex},
        {"aad_b64", s.aad_b64},
        {"cek_b64", s.cek_b64},
        {"chunk_nonce_prefix_b64", s.chunk_nonce_prefix_b64},
        {"created_at", s.created_at},
        {"expires_at", s.expires_at},
        {"state", s.state}
    };
}

static bool open_stream_session_from_json(const json& j, PqShareOpenStreamSessionV1* out) {
    if (!out) return false;
    *out = PqShareOpenStreamSessionV1{};

    auto json_string = [&](const char* key) -> std::string {
        auto it = j.find(key);
        return (it != j.end() && it->is_string()) ? it->get<std::string>() : std::string{};
    };
    auto json_u64 = [&](const char* key) -> std::uint64_t {
        auto it = j.find(key);
        if (it == j.end()) return 0;
        if (it->is_number_unsigned()) return it->get<std::uint64_t>();
        if (it->is_number_integer()) return static_cast<std::uint64_t>(it->get<std::int64_t>());
        return 0;
    };
    auto json_i64 = [&](const char* key) -> std::int64_t {
        auto it = j.find(key);
        if (it == j.end()) return 0;
        if (it->is_number_integer()) return it->get<std::int64_t>();
        if (it->is_number_unsigned()) return static_cast<std::int64_t>(it->get<std::uint64_t>());
        return 0;
    };

    out->open_id = json_string("open_id");
    out->owner_fp = json_string("owner_fp");
    out->share_token = json_string("share_token");
    out->recipient_session_id = json_string("recipient_session_id");
    out->recipient_device_id = json_string("recipient_device_id");
    out->rel_path = json_string("rel_path");
    out->file_name = json_string("file_name");
    out->mime_type = json_string("mime_type");
    out->file_size_bytes = json_u64("file_size_bytes");
    out->chunk_size_bytes = json_u64("chunk_size_bytes");
    out->chunk_count = json_u64("chunk_count");
    out->snapshot_mtime_epoch = json_i64("snapshot_mtime_epoch");
    out->snapshot_sha256_hex = json_string("snapshot_sha256_hex");
    out->aad_b64 = json_string("aad_b64");
    out->cek_b64 = json_string("cek_b64");
    out->chunk_nonce_prefix_b64 = json_string("chunk_nonce_prefix_b64");
    out->created_at = json_string("created_at");
    out->expires_at = json_string("expires_at");
    out->state = json_string("state");

    return !out->open_id.empty() &&
           !out->owner_fp.empty() &&
           !out->share_token.empty() &&
           !out->recipient_session_id.empty() &&
           !out->recipient_device_id.empty();
}
static std::int64_t file_mtime_epoch_local(const std::filesystem::path& p, std::string* err) {
    if (err) err->clear();
    std::error_code ec;
    const auto ft = std::filesystem::last_write_time(p, ec);
    if (ec) {
        if (err) *err = "last_write_time failed: " + ec.message();
        return 0;
    }
    const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ft - decltype(ft)::clock::now() + std::chrono::system_clock::now());
    return static_cast<std::int64_t>(std::chrono::system_clock::to_time_t(sctp));
}

static bool parse_iso_utc_local(const std::string& iso, std::tm* out) {
    if (!out) return false;
    if (iso.size() != 20) return false;
    int Y=0,M=0,D=0,h=0,m=0,s=0;
    if (std::sscanf(iso.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ", &Y, &M, &D, &h, &m, &s) != 6) return false;
    std::tm tm{};
    tm.tm_year = Y - 1900;
    tm.tm_mon = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min = m;
    tm.tm_sec = s;
    *out = tm;
    return true;
}

static std::time_t timegm_local(std::tm* tm) {
#if defined(__linux__)
    return ::timegm(tm);
#else
    return std::mktime(tm);
#endif
}

static std::string b64url_no_pad_local(const unsigned char* data, std::size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= len) {
        const unsigned v = (unsigned(data[i]) << 16) | (unsigned(data[i + 1]) << 8) | unsigned(data[i + 2]);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
        i += 3;
    }

    if (i < len) {
        unsigned v = unsigned(data[i]) << 16;
        if (i + 1 < len) v |= unsigned(data[i + 1]) << 8;

        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        if (i + 1 < len) out.push_back(tbl[(v >> 6) & 63]);
    }

    return out;
}

} // namespace

SharePqStoreV1::SharePqStoreV1(std::filesystem::path base_cfg_dir)
    : base_cfg_dir_(std::move(base_cfg_dir)) {}

std::filesystem::path SharePqStoreV1::manifests_dir() const { return base_cfg_dir_ / "share_manifests_v1"; }
std::filesystem::path SharePqStoreV1::invites_dir() const { return base_cfg_dir_ / "share_invites_v1"; }
std::filesystem::path SharePqStoreV1::recipients_dir() const { return base_cfg_dir_ / "share_recipients_v1"; }
std::filesystem::path SharePqStoreV1::sessions_dir() const { return base_cfg_dir_ / "share_recipient_sessions_v1"; }

std::filesystem::path SharePqStoreV1::manifest_path(const std::string& token) const {
    return manifests_dir() / (token + ".json");
}

std::filesystem::path SharePqStoreV1::invite_path(const std::string& invite_id) const {
    return invites_dir() / (invite_id + ".json");
}

std::filesystem::path SharePqStoreV1::recipient_path(const std::string& owner_fp,
                                                     const std::string& recipient_device_id) const {
    return recipients_dir() / owner_fp / (recipient_device_id + ".json");
}

std::filesystem::path SharePqStoreV1::session_path(const std::string& session_id) const {
    return sessions_dir() / (session_id + ".json");
}

    bool SharePqStoreV1::write_json_atomic_local(const std::filesystem::path& path,
                                                 const std::string& text,
                                                 std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        if (err) {
            *err = "create_directories failed: dir=" + path.parent_path().string() +
                   " target=" + path.string() +
                   " err=" + ec.message();
        }
        return false;
    }

    const auto tmp = path.parent_path() /
        ("." + path.filename().string() + ".tmp." + random_id_b64url_local(6));

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            if (err) *err = "open tmp failed: tmp=" + tmp.string();
            return false;
        }

        f << text;
        f.flush();
        if (!f.good()) {
            if (err) {
                *err = "write tmp failed: tmp=" + tmp.string() +
                       " target=" + path.string();
            }
            std::filesystem::remove(tmp, ec);
            return false;
        }
    }

    std::filesystem::rename(tmp, path, ec);
    if (!ec) return true;

    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        if (err) {
            *err = "rename failed: tmp=" + tmp.string() +
                   " target=" + path.string() +
                   " err=" + ec.message();
        }
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

    std::filesystem::path SharePqStoreV1::open_stream_session_path(const std::string& open_id) const {
    return session_path("open_" + open_id);
}
bool SharePqStoreV1::read_text_file_local(const std::filesystem::path& path,
                                          std::string* out,
                                          std::string* err) {
    if (out) out->clear();
    if (err) err->clear();

    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return false;
    }

    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "open failed";
        return false;
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    if (out) *out = ss.str();
    return true;
}

std::string SharePqStoreV1::now_iso_utc_local() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(__linux__)
    gmtime_r(&t, &tm);
#else
    tm = *std::gmtime(&t);
#endif

    char buf[64];
    const int n = std::snprintf(
        buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );

    if (n < 0 || n >= (int)sizeof(buf)) return std::string{};
    return std::string(buf);
}

std::string SharePqStoreV1::add_seconds_iso_utc_local(long long seconds) {
    std::time_t t = std::time(nullptr);
    t += static_cast<std::time_t>(seconds);

    std::tm tm{};
#if defined(__linux__)
    gmtime_r(&t, &tm);
#else
    tm = *std::gmtime(&t);
#endif

    char buf[64];
    const int n = std::snprintf(
        buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );

    if (n < 0 || n >= (int)sizeof(buf)) return std::string{};
    return std::string(buf);
}

bool SharePqStoreV1::iso_expired_local(const std::string& iso) {
    if (iso.empty()) return false;
    std::tm tm{};
    if (!parse_iso_utc_local(iso, &tm)) return false;
    const std::time_t exp = timegm_local(&tm);
    return exp > 0 && std::time(nullptr) >= exp;
}

std::string SharePqStoreV1::random_id_b64url_local(std::size_t nbytes) {
    std::vector<unsigned char> buf(nbytes);
    if (nbytes == 0) return {};
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) return {};
    return b64url_no_pad_local(buf.data(), buf.size());
}

bool SharePqStoreV1::sha256_file_hex_local(const std::filesystem::path& abs,
                                           std::string* out_hex,
                                           std::string* err) {
    if (out_hex) out_hex->clear();
    if (err) err->clear();

    std::ifstream f(abs, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "open failed";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    bool ok = false;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    do {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            if (err) *err = "DigestInit failed";
            break;
        }

        std::array<char, 64 * 1024> buf{};
        while (f.good()) {
            f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize got = f.gcount();
            if (got > 0) {
                if (EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(got)) != 1) {
                    if (err) *err = "DigestUpdate failed";
                    break;
                }
            }
            if (got < static_cast<std::streamsize>(buf.size())) break;
        }

        if (err && !err->empty()) break;

        if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
            if (err) *err = "DigestFinal failed";
            break;
        }

        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(md_len * 2);
        for (unsigned int i = 0; i < md_len; ++i) {
            out.push_back(hex[(md[i] >> 4) & 0xF]);
            out.push_back(hex[md[i] & 0xF]);
        }
        if (out_hex) *out_hex = std::move(out);
        ok = true;
    } while (false);

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool SharePqStoreV1::load_manifest(const std::string& token, PqShareManifestV1* out, std::string* err) const {
    if (out) *out = PqShareManifestV1{};
    std::lock_guard<std::mutex> lk(mu_);
    std::string text;
    if (!read_text_file_local(manifest_path(token), &text, err)) return false;
    try {
        const json j = json::parse(text);
        return manifest_from_json(j, out);
    } catch (const std::exception& e) {
        if (err) *err = std::string("json parse failed: ") + e.what();
        return false;
    }
}

bool SharePqStoreV1::save_manifest(const PqShareManifestV1& m, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    return write_json_atomic_local(manifest_path(m.share_token), manifest_to_json(m).dump(2) + "\n", err);
}

bool SharePqStoreV1::delete_manifest(const std::string& token, std::string* err) {
    if (err) err->clear();
    std::lock_guard<std::mutex> lk(mu_);
    std::error_code ec;
    const auto p = manifest_path(token);
    if (!std::filesystem::exists(p, ec)) return false;
    std::filesystem::remove(p, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }
    return true;
}

bool SharePqStoreV1::load_invite(const std::string& invite_id, PqShareInviteV1* out, std::string* err) const {
    if (out) *out = PqShareInviteV1{};
    std::lock_guard<std::mutex> lk(mu_);
    std::string text;
    if (!read_text_file_local(invite_path(invite_id), &text, err)) return false;
    try {
        const json j = json::parse(text);
        return invite_from_json(j, out);
    } catch (const std::exception& e) {
        if (err) *err = std::string("json parse failed: ") + e.what();
        return false;
    }
}

bool SharePqStoreV1::save_invite(const PqShareInviteV1& i, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    return write_json_atomic_local(invite_path(i.invite_id), invite_to_json(i).dump(2) + "\n", err);
}

bool SharePqStoreV1::delete_invite(const std::string& invite_id, std::string* err) {
    if (err) err->clear();
    std::lock_guard<std::mutex> lk(mu_);
    std::error_code ec;
    const auto p = invite_path(invite_id);
    if (!std::filesystem::exists(p, ec)) return false;
    std::filesystem::remove(p, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }
    return true;
}

bool SharePqStoreV1::revoke_invites_for_share(const std::string& share_token, std::string* err) {
    if (err) err->clear();
    std::lock_guard<std::mutex> lk(mu_);

    std::error_code ec;
    std::filesystem::create_directories(invites_dir(), ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }

    for (const auto& de : std::filesystem::directory_iterator(invites_dir(), ec)) {
        if (ec) {
            if (err) *err = ec.message();
            return false;
        }
        if (!de.is_regular_file()) continue;

        std::ifstream f(de.path(), std::ios::binary);
        if (!f.good()) continue;

        try {
            json j;
            f >> j;
            PqShareInviteV1 inv;
            if (!invite_from_json(j, &inv)) continue;
            if (inv.share_token != share_token) continue;
            if (inv.state == "revoked") continue;
            inv.state = "revoked";
            if (!write_json_atomic_local(de.path(), invite_to_json(inv).dump(2) + "\n", err)) return false;
        } catch (...) {
        }
    }
    return true;
}

    bool SharePqStoreV1::load_pending_invite_for_share(const std::string& share_token,
                                                       PqShareInviteV1* out,
                                                       std::string* err) const {
    if (out) *out = PqShareInviteV1{};
    if (err) err->clear();

    std::lock_guard<std::mutex> lk(mu_);

    std::error_code ec;
    std::filesystem::create_directories(invites_dir(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    bool found = false;
    PqShareInviteV1 best;

    for (const auto& de : std::filesystem::directory_iterator(invites_dir(), ec)) {
        if (ec) {
            if (err) *err = "directory_iterator failed: " + ec.message();
            return false;
        }
        if (!de.is_regular_file()) continue;

        std::string text;
        std::string read_err;
        if (!read_text_file_local(de.path(), &text, &read_err)) continue;

        try {
            const json j = json::parse(text);
            PqShareInviteV1 inv;
            if (!invite_from_json(j, &inv)) continue;
            if (inv.share_token != share_token) continue;
            if (inv.state != "pending") continue;
            if (SharePqStoreV1::iso_expired_local(inv.expires_at)) continue;

            if (!found || inv.created_at > best.created_at) {
                best = std::move(inv);
                found = true;
            }
        } catch (...) {
            continue;
        }
    }

    if (found && out) *out = best;
    return found;
}
    bool SharePqStoreV1::load_latest_invite_for_share(const std::string& share_token,
                                                      PqShareInviteV1* out,
                                                      std::string* err) const {
    if (out) *out = PqShareInviteV1{};
    if (err) err->clear();

    std::lock_guard<std::mutex> lk(mu_);

    std::error_code ec;
    if (!std::filesystem::exists(invites_dir(), ec)) {
        if (ec && err) *err = ec.message();
        return false;
    }

    PqShareInviteV1 best{};
    bool found = false;

    auto state_rank = [](const std::string& s) -> int {
        if (s == "pending") return 3;
        if (s == "claimed") return 2;
        if (s == "revoked") return 1;
        return 0;
    };

    for (const auto& de : std::filesystem::directory_iterator(invites_dir(), ec)) {
        if (ec) {
            if (err) *err = ec.message();
            return false;
        }
        if (!de.is_regular_file()) continue;

        std::ifstream f(de.path(), std::ios::binary);
        if (!f.good()) continue;

        try {
            json j;
            f >> j;

            PqShareInviteV1 inv;
            if (!invite_from_json(j, &inv)) continue;
            if (inv.share_token != share_token) continue;

            if (!found) {
                best = inv;
                found = true;
                continue;
            }

            const int br = state_rank(best.state);
            const int ir = state_rank(inv.state);

            if (ir > br) {
                best = inv;
                continue;
            }

            if (ir == br && inv.created_at > best.created_at) {
                best = inv;
                continue;
            }
        } catch (...) {
        }
    }

    if (!found) {
        if (err) *err = "invite not found";
        return false;
    }

    if (out) *out = best;
    return true;
}
bool SharePqStoreV1::load_recipient_device(const std::string& owner_fp,
                                           const std::string& recipient_device_id,
                                           PqShareRecipientDeviceV1* out,
                                           std::string* err) const {
    if (out) *out = PqShareRecipientDeviceV1{};
    std::lock_guard<std::mutex> lk(mu_);
    std::string text;
    if (!read_text_file_local(recipient_path(owner_fp, recipient_device_id), &text, err)) return false;
    try {
        const json j = json::parse(text);
        return recipient_from_json(j, out);
    } catch (const std::exception& e) {
        if (err) *err = std::string("json parse failed: ") + e.what();
        return false;
    }
}

bool SharePqStoreV1::save_recipient_device(const PqShareRecipientDeviceV1& d, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    return write_json_atomic_local(recipient_path(d.owner_fp, d.recipient_device_id),
                                   recipient_to_json(d).dump(2) + "\n",
                                   err);
}

    bool SharePqStoreV1::find_active_recipient_device_by_public_key(
    const std::string& owner_fp,
    const std::string& kem_alg,
    const std::string& public_key_b64,
    PqShareRecipientDeviceV1* out,
    std::string* err) const {

    if (out) *out = PqShareRecipientDeviceV1{};
    if (err) err->clear();

    if (owner_fp.empty() || public_key_b64.empty()) {
        if (err) *err = "missing owner_fp or public_key_b64";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);

    const auto dir = recipients_dir() / owner_fp;

    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        if (ec && err) *err = ec.message();
        return false;
    }

    for (const auto& de : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            if (err) *err = ec.message();
            return false;
        }
        if (!de.is_regular_file()) continue;

        std::string text;
        std::string read_err;
        if (!read_text_file_local(de.path(), &text, &read_err)) continue;

        try {
            const json j = json::parse(text);
            PqShareRecipientDeviceV1 d;
            if (!recipient_from_json(j, &d)) continue;

            if (d.owner_fp != owner_fp) continue;
            if (d.state != "active") continue;
            if (!kem_alg.empty() && d.kem_alg != kem_alg) continue;
            if (d.public_key_b64 != public_key_b64) continue;

            if (out) *out = std::move(d);
            return true;
        } catch (...) {
            continue;
        }
    }

    return false;
}

    bool SharePqStoreV1::list_recipient_devices_for_owner(
    const std::string& owner_fp,
    std::vector<PqShareRecipientDeviceV1>* out,
    std::string* err) const {

    if (out) out->clear();
    if (err) err->clear();

    if (owner_fp.empty()) {
        if (err) *err = "missing owner_fp";
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);

    const auto dir = recipients_dir() / owner_fp;

    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        if (ec && err) *err = ec.message();
        return false;
    }

    std::vector<PqShareRecipientDeviceV1> items;

    for (const auto& de : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            if (err) *err = ec.message();
            return false;
        }
        if (!de.is_regular_file()) continue;

        std::string text;
        std::string read_err;
        if (!read_text_file_local(de.path(), &text, &read_err)) continue;

        try {
            const json j = json::parse(text);
            PqShareRecipientDeviceV1 d;
            if (!recipient_from_json(j, &d)) continue;
            if (d.owner_fp != owner_fp) continue;
            items.push_back(std::move(d));
        } catch (...) {
            continue;
        }
    }

    if (out) *out = std::move(items);
    return true;
}

bool SharePqStoreV1::revoke_recipient_device(const std::string& owner_fp,
                                             const std::string& recipient_device_id,
                                             std::string* err) {
    PqShareRecipientDeviceV1 d;
    if (!load_recipient_device(owner_fp, recipient_device_id, &d, err)) return false;
    d.state = "revoked";
    d.updated_at = now_iso_utc_local();
    return save_recipient_device(d, err);
}

bool SharePqStoreV1::load_session(const std::string& session_id, PqShareRecipientSessionV1* out, std::string* err) const {
    if (out) *out = PqShareRecipientSessionV1{};
    std::lock_guard<std::mutex> lk(mu_);
    std::string text;
    if (!read_text_file_local(session_path(session_id), &text, err)) return false;
    try {
        const json j = json::parse(text);
        return session_from_json(j, out);
    } catch (const std::exception& e) {
        if (err) *err = std::string("json parse failed: ") + e.what();
        return false;
    }
}

bool SharePqStoreV1::save_session(const PqShareRecipientSessionV1& s, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    return write_json_atomic_local(session_path(s.session_id), session_to_json(s).dump(2) + "\n", err);
}

bool SharePqStoreV1::load_open_stream_session(const std::string& open_id, PqShareOpenStreamSessionV1* out, std::string* err) const {
    if (out) *out = PqShareOpenStreamSessionV1{};

    std::string text;
    if (!read_text_file_local(open_stream_session_path(open_id), &text, err)) return false;

    json j;
    try {
        j = json::parse(text);
    } catch (...) {
        if (err) *err = "bad_json";
        return false;
    }

    if (!open_stream_session_from_json(j, out)) {
        if (err) *err = "bad_open_stream_session";
        return false;
    }
    return true;
}

    bool SharePqStoreV1::save_open_stream_session(const PqShareOpenStreamSessionV1& s, std::string* err) {
    return write_json_atomic_local(
        open_stream_session_path(s.open_id),
        open_stream_session_to_json(s).dump(2) + "\n",
        err);
}

    bool SharePqStoreV1::revoke_open_stream_session(const std::string& open_id, std::string* err) {
    PqShareOpenStreamSessionV1 s;
    if (!load_open_stream_session(open_id, &s, err)) return false;
    s.state = "revoked";
    return save_open_stream_session(s, err);
}
bool SharePqStoreV1::touch_session(const std::string& session_id, const std::string& now_iso, std::string* err) {
    PqShareRecipientSessionV1 s;
    if (!load_session(session_id, &s, err)) return false;
    s.last_used_at = now_iso;
    return save_session(s, err);
}

bool SharePqStoreV1::file_snapshot_from_abs_path(const std::filesystem::path& abs,
                                                 PqShareSnapshotV1* out,
                                                 std::string* err) const {
    if (out) *out = PqShareSnapshotV1{};
    if (err) err->clear();

    std::error_code ec;
    if (!std::filesystem::exists(abs, ec) || ec) {
        if (err) *err = "path not found";
        return false;
    }
    if (!std::filesystem::is_regular_file(abs, ec) || ec) {
        if (err) *err = "not a regular file";
        return false;
    }

    PqShareSnapshotV1 s;
    s.size_bytes = std::filesystem::file_size(abs, ec);
    if (ec) {
        if (err) *err = "file_size failed: " + ec.message();
        return false;
    }

    s.mtime_epoch = file_mtime_epoch_local(abs, err);
    if (s.mtime_epoch == 0 && err && !err->empty()) return false;

    if (!sha256_file_hex_local(abs, &s.sha256_hex, err)) return false;

    if (out) *out = std::move(s);
    return true;
}

bool SharePqStoreV1::verify_snapshot(const std::filesystem::path& abs,
                                     const PqShareSnapshotV1& snap,
                                     bool* out_match,
                                     std::string* err) const {
    if (out_match) *out_match = false;
    if (err) err->clear();

    std::error_code ec;
    if (!std::filesystem::exists(abs, ec) || ec) {
        if (err) *err = "path not found";
        return false;
    }
    if (!std::filesystem::is_regular_file(abs, ec) || ec) {
        if (err) *err = "not a regular file";
        return false;
    }

    const auto cur_size = std::filesystem::file_size(abs, ec);
    if (ec) {
        if (err) *err = "file_size failed: " + ec.message();
        return false;
    }

    const auto cur_mtime = file_mtime_epoch_local(abs, err);
    if (cur_mtime == 0 && err && !err->empty()) return false;

    if (cur_size == snap.size_bytes && cur_mtime == snap.mtime_epoch) {
        if (out_match) *out_match = true;
        return true;
    }

    std::string cur_sha;
    if (!sha256_file_hex_local(abs, &cur_sha, err)) return false;

    if (out_match) *out_match = (!snap.sha256_hex.empty() && cur_sha == snap.sha256_hex);
    return true;
}

bool SharePqStoreV1::create_recipient_enrolled_share(const std::string& share_token,
                                                     const std::string& owner_fp,
                                                     const std::string& rel_path,
                                                     const std::string& created_at,
                                                     const std::string& expires_at,
                                                     const std::filesystem::path& abs_path,
                                                     long long invite_expires_sec,
                                                     const std::string& recipient_label_hint,
                                                     PqShareCreateResultV1* out,
                                                     std::string* err) {
    if (out) *out = PqShareCreateResultV1{};
    if (err) err->clear();

    PqShareSnapshotV1 snap;
    if (!file_snapshot_from_abs_path(abs_path, &snap, err)) return false;

    PqShareManifestV1 mf;
    mf.version = 1;
    mf.share_token = share_token;
    mf.kind = "pq_recipient_enrolled_v1";
    mf.owner_fp = owner_fp;
    mf.rel_path = rel_path;
    mf.created_at = created_at.empty() ? now_iso_utc_local() : created_at;
    mf.expires_at = expires_at;
    mf.state = "pending_enrollment";
    mf.snapshot = snap;
    mf.kem_alg = "X25519";
    mf.sig_alg.clear();
    mf.crypto_backend = "x25519_aes256gcm_v1";

    PqShareInviteV1 inv;
    inv.version = 1;
    inv.invite_id = random_id_b64url_local(18);
    if (inv.invite_id.empty()) {
        if (err) *err = "invite_id generation failed";
        return false;
    }
    inv.share_token = share_token;
    inv.owner_fp = owner_fp;
    inv.state = "pending";
    inv.created_at = now_iso_utc_local();
    inv.expires_at = add_seconds_iso_utc_local(invite_expires_sec > 0 ? invite_expires_sec : 24 * 3600);
    inv.max_claims = 1;
    inv.claim_count = 0;
    inv.label_hint = recipient_label_hint;

    if (!save_manifest(mf, err)) return false;

    std::string inv_err;
    if (!save_invite(inv, &inv_err)) {
        std::string rollback_err;
        (void)delete_manifest(share_token, &rollback_err);
        if (err) *err = inv_err.empty() ? "save_invite failed" : inv_err;
        return false;
    }

    if (out) {
        out->manifest = mf;
        out->invite = inv;
    }
    return true;
}

std::string SharePqStoreV1::invite_url_path(const std::string& invite_id) const {
    return "/pq/invite/" + invite_id;
}

} // namespace pqnas