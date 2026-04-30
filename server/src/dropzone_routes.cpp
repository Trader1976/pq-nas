#include "dropzone_routes.h"
#include "storage_resolver.h"
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <algorithm>
#include <openssl/evp.h>
#include <sstream>
#include <nlohmann/json.hpp>
#include <ctime>
#include <array>
#include <iterator>
#include <stdexcept>

namespace pqnas {
namespace {

using json = nlohmann::json;

static void reply_json_local(const DropZoneRoutesDeps& deps,
                             httplib::Response& res,
                             int status,
                             const json& body) {
    if (deps.reply_json) {
        deps.reply_json(res, status, body.dump());
        return;
    }

    res.status = status;
    res.set_header("Content-Type", "application/json; charset=utf-8");
    res.body = body.dump();
}

static void audit_local(const DropZoneRoutesDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& fields) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, fields);
}

    static json dropzone_to_json_local(const DropZoneRec& rec) {
    return json{
            {"id", rec.id},
            {"name", rec.name},
            {"destination_path", rec.destination_path},

            {"created_epoch", rec.created_epoch},
            {"expires_epoch", rec.expires_epoch},
            {"last_used_epoch", rec.last_used_epoch},

            {"max_file_bytes", rec.max_file_bytes},
            {"max_total_bytes", rec.max_total_bytes},
            {"bytes_uploaded", rec.bytes_uploaded},
            {"upload_count", rec.upload_count},

            {"password_required", !rec.password_hash.empty()},
            {"disabled", rec.disabled}
    };
}
static std::string header_value_local(const httplib::Request& req, const char* key) {
    auto it = req.headers.find(key);
    return (it == req.headers.end()) ? std::string() : it->second;
}

static bool require_same_origin_for_cookie_mutation_local(
    const httplib::Request& req,
    httplib::Response& res,
    const DropZoneRoutesDeps& deps
) {
    const std::string auth = header_value_local(req, "Authorization");
    if (auth.rfind("Bearer ", 0) == 0) return true;

    if (!deps.origin || deps.origin->empty()) {
        reply_json_local(deps, res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "origin not configured"}
        });
        return false;
    }

    const std::string& expected_origin = *deps.origin;

    const std::string origin = header_value_local(req, "Origin");
    if (!origin.empty()) {
        if (origin == expected_origin) return true;

        reply_json_local(deps, res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "origin mismatch"}
        });
        return false;
    }

    const std::string referer = header_value_local(req, "Referer");
    if (!referer.empty()) {
        const std::string allowed_prefix = expected_origin + "/";
        if (referer == expected_origin || referer.rfind(allowed_prefix, 0) == 0) {
            return true;
        }

        reply_json_local(deps, res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "origin mismatch"}
        });
        return false;
    }

    reply_json_local(deps, res, 403, json{
        {"ok", false},
        {"error", "forbidden"},
        {"message", "origin required"}
    });
    return false;
}

static std::string hex_encode_lower_local(const unsigned char* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.resize(len * 2);

    for (std::size_t i = 0; i < len; ++i) {
        const unsigned char b = data[i];
        out[i * 2 + 0] = kHex[(b >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[b & 0x0F];
    }

    return out;
}

static std::string sha256_hex_string_local(const std::string& s, std::string* err) {
    if (err) err->clear();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return {};
    }

    struct Guard {
        EVP_MD_CTX* p;
        ~Guard() { if (p) EVP_MD_CTX_free(p); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return {};
    }

    if (!s.empty() && EVP_DigestUpdate(ctx, s.data(), s.size()) != 1) {
        if (err) *err = "EVP_DigestUpdate failed";
        return {};
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return {};
    }

    return hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
}

static std::string pbkdf2_sha256_hash_password_local(
    const std::string& password,
    const std::string& salt,
    std::string* err
) {
    if (err) err->clear();

    if (password.empty()) return "";

    constexpr int kIterations = 120000;
    constexpr int kOutLen = 32;

    unsigned char out[kOutLen];

    const int ok = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()),
        kIterations,
        EVP_sha256(),
        kOutLen,
        out
    );

    if (ok != 1) {
        if (err) *err = "PKCS5_PBKDF2_HMAC failed";
        return {};
    }

    return "pbkdf2-sha256$" +
           std::to_string(kIterations) + "$" +
           salt + "$" +
           hex_encode_lower_local(out, kOutLen);
}

static std::uint64_t json_u64_local(const json& j,
                                    const char* key,
                                    std::uint64_t defv,
                                    std::uint64_t maxv) {
    if (!j.contains(key)) return defv;

    try {
        if (j[key].is_number_unsigned()) {
            return std::min<std::uint64_t>(j[key].get<std::uint64_t>(), maxv);
        }

        if (j[key].is_number_integer()) {
            const auto v = j[key].get<std::int64_t>();
            if (v <= 0) return 0;
            return std::min<std::uint64_t>(static_cast<std::uint64_t>(v), maxv);
        }
    } catch (...) {
    }

    return defv;
}
static std::string safe_upload_filename_local(std::string name) {
    for (char& c : name) {
        if (c == '\\') c = '/';
    }

    const auto slash = name.find_last_of('/');
    if (slash != std::string::npos) {
        name = name.substr(slash + 1);
    }

    std::string out;
    out.reserve(name.size());

    for (unsigned char c : name) {
        if (c <= 31 || c == 127 || c == '/' || c == '\\') {
            out.push_back('_');
            continue;
        }

        out.push_back(static_cast<char>(c));
    }

    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.front()))) {
        out.erase(out.begin());
    }

    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) {
        out.pop_back();
    }

    if (out.empty() || out == "." || out == "..") {
        out = "upload.bin";
    }

    if (out.size() > 180) {
        out.resize(180);
    }

    return out;
}

static bool path_has_prefix_components_local(const std::filesystem::path& root,
                                             const std::filesystem::path& child) {
    const auto rnorm = root.lexically_normal();
    const auto cnorm = child.lexically_normal();

    auto ri = rnorm.begin();
    auto ci = cnorm.begin();

    for (; ri != rnorm.end(); ++ri, ++ci) {
        if (ci == cnorm.end()) return false;
        if (*ri != *ci) return false;
    }

    return true;
}

static std::filesystem::path unique_child_path_local(const std::filesystem::path& dir,
                                                     const std::string& filename) {
    std::filesystem::path base(filename);

    const std::string stem = base.stem().string().empty()
        ? filename
        : base.stem().string();

    const std::string ext = base.has_extension() ? base.extension().string() : "";

    std::filesystem::path candidate = dir / filename;

    std::error_code ec;
    if (!std::filesystem::exists(candidate, ec)) return candidate;

    for (int i = 1; i <= 1000; ++i) {
        candidate = dir / (stem + " (" + std::to_string(i) + ")" + ext);
        ec.clear();

        if (!std::filesystem::exists(candidate, ec)) return candidate;
    }

    return dir / ("upload-" + std::to_string(std::time(nullptr)) + "-" + filename);
}

static bool write_file_atomic_local(const std::filesystem::path& final_path,
                                    const std::string& data,
                                    const std::function<std::string(std::size_t)>& random_b64url,
                                    std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    std::filesystem::create_directories(final_path.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    const std::string suffix = random_b64url ? random_b64url(8) : std::to_string(std::time(nullptr));
    const std::filesystem::path tmp =
        final_path.parent_path() / (final_path.filename().string() + ".tmp." + suffix);

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            if (err) *err = "open tmp failed";
            return false;
        }

        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!f.good()) {
            f.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "write tmp failed";
            return false;
        }

        f.flush();
        if (!f.good()) {
            f.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "flush tmp failed";
            return false;
        }
    }

    std::filesystem::rename(tmp, final_path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        if (err) *err = "rename failed: " + ec.message();
        return false;
    }

    return true;
}


} // namespace
static constexpr std::uint64_t k_dropzone_chunk_bytes =
    64ull * 1024ull * 1024ull; // 64 MiB, Cloudflare-safe

static constexpr std::uint64_t k_dropzone_max_session_bytes =
    64ull * 1024ull * 1024ull * 1024ull; // 64 GiB MVP safety cap

[[maybe_unused]] static bool dz_upload_id_ok_local(const std::string& s) {
    if (s.size() < 16 || s.size() > 96) return false;

    for (unsigned char c : s) {
        const bool ok =
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-';

        if (!ok) return false;
    }

    return true;
}

static std::filesystem::path dz_upload_session_dir_local(const std::filesystem::path& owner_root,
                                                         const std::string& dropzone_id,
                                                         const std::string& upload_id) {
    return owner_root /
           ".pqnas" /
           "dropzone_upload_sessions" /
           dropzone_id /
           upload_id;
}

[[maybe_unused]] static std::string dz_chunk_name_local(std::uint64_t idx) {
    std::string n = std::to_string(static_cast<unsigned long long>(idx));
    if (n.size() < 8) n = std::string(8 - n.size(), '0') + n;
    return n + ".part";
}

static bool dz_write_json_file_local(const std::filesystem::path& path,
                                     const json& j,
                                     const std::function<std::string(std::size_t)>& random_b64url,
                                     std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    const std::string suffix = random_b64url ? random_b64url(8) : std::to_string(std::time(nullptr));
    const auto tmp = path.parent_path() / (path.filename().string() + ".tmp." + suffix);

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            if (err) *err = "open tmp failed";
            return false;
        }

        const std::string body = j.dump(2);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        f.flush();

        if (!f.good()) {
            f.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "write tmp failed";
            return false;
        }
    }

    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        if (err) *err = "rename failed: " + ec.message();
        return false;
    }

    return true;
}

[[maybe_unused]] static bool dz_read_json_file_local(const std::filesystem::path& path,
                                    json* out,
                                    std::string* err) {
    if (err) err->clear();

    if (!out) {
        if (err) *err = "null output";
        return false;
    }

    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    std::string body((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (!f.good() && !f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        if (err) *err = "invalid json";
        return false;
    }

    *out = std::move(j);
    return true;
}

static bool dz_json_u64_local(const json& j,
                              const char* key,
                              std::uint64_t* out) {
    if (!out || !key) return false;
    if (!j.contains(key)) return false;

    try {
        const auto& v = j[key];

        if (v.is_number_unsigned()) {
            *out = v.get<std::uint64_t>();
            return true;
        }

        if (v.is_number_integer()) {
            long long x = v.get<long long>();
            if (x < 0) return false;
            *out = static_cast<std::uint64_t>(x);
            return true;
        }

        if (v.is_string()) {
            const std::string s = v.get<std::string>();
            if (s.empty()) return false;

            size_t idx = 0;
            unsigned long long x = std::stoull(s, &idx, 10);
            if (idx != s.size()) return false;

            *out = static_cast<std::uint64_t>(x);
            return true;
        }
    } catch (...) {
        return false;
    }

    return false;
}

[[maybe_unused]] static bool dz_header_u64_local(const httplib::Request& req,
                                const char* name,
                                std::uint64_t* out) {
    if (!out || !name) return false;

    auto it = req.headers.find(name);
    if (it == req.headers.end()) return false;

    try {
        const std::string& s = it->second;
        size_t idx = 0;
        unsigned long long v = std::stoull(s, &idx, 10);
        if (idx != s.size()) return false;

        *out = static_cast<std::uint64_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

[[maybe_unused]] static std::uint64_t dz_expected_chunk_bytes_local(std::uint64_t size_bytes,
                                                   std::uint64_t chunk_size,
                                                   std::uint64_t chunks_total,
                                                   std::uint64_t idx) {
    if (chunks_total == 0) return 0;
    if (idx + 1 < chunks_total) return chunk_size;

    const std::uint64_t already = chunk_size * idx;
    if (already >= size_bytes) return 0;

    return size_bytes - already;
}
static std::string sha256_hex_file_local(const std::filesystem::path& path, std::string* err);
void register_dropzone_routes(httplib::Server& srv, const DropZoneRoutesDeps& deps) {
    // MVP/stub endpoint:
    // - authenticated user only
    // - returns an empty list until Drop Zone persistence is added
    srv.Get("/api/v4/dropzones/list", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.users || !deps.cookie_key || !deps.require_user_auth_users_actor) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!deps.dropzone_index) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone index missing"}
            });
            return;
        }

        std::string lerr;
        const auto rows = deps.dropzone_index->list_owner(actor_fp, false, 200, &lerr);

        if (!lerr.empty()) {
            audit_local(deps, "v4.dropzones_list_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "list_owner_failed"},
                {"detail", lerr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list drop zones"}
            });
            return;
        }

        json zones = json::array();
        for (const auto& row : rows) {
            zones.push_back(dropzone_to_json_local(row));
        }

        audit_local(deps, "v4.dropzones_list_ok", "ok", {
            {"actor_fp", actor_fp},
            {"count", std::to_string(zones.size())}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"drop_zones", zones}
        });
    });
        srv.Post("/api/v4/dropzones/create", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.users || !deps.cookie_key || !deps.require_user_auth_users_actor ||
            !deps.dropzone_index || !deps.random_b64url || !deps.now_epoch ||
            !deps.origin) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) {
            return;
        }

        json in = json::object();
        try {
            if (!req.body.empty()) in = json::parse(req.body);
        } catch (...) {
            audit_local(deps, "v4.dropzones_create_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "bad_json"}
            });

            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            });
            return;
        }

        std::string name = in.value("name", "");
        std::string destination_path = in.value("destination_path", "");
        std::string password = in.value("password", "");

        auto trim = [](std::string s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
            return s;
        };

        name = trim(name);
        destination_path = trim(destination_path);

        if (name.empty()) name = "Drop Zone";

        if (name.size() > 120) {
            name.resize(120);
        }

        if (destination_path.empty()) {
            destination_path = "Incoming/Drop Zones/" + name;
        }

        std::string dest_norm;
        std::string norm_err;

        if (!normalize_user_rel_path_strict(destination_path, &dest_norm, &norm_err)) {
            audit_local(deps, "v4.dropzones_create_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "invalid_destination_path"},
                {"detail", norm_err}
            });

            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid destination path"}
            });
            return;
        }

        constexpr std::int64_t kDefaultExpirySec = 7LL * 24LL * 60LL * 60LL;
        constexpr std::int64_t kMinExpirySec = 60;
        constexpr std::int64_t kMaxExpirySec = 90LL * 24LL * 60LL * 60LL;

        std::int64_t expires_in = kDefaultExpirySec;
        try {
            if (in.contains("expires_in_seconds")) {
                expires_in = in["expires_in_seconds"].get<std::int64_t>();
            }
        } catch (...) {
            expires_in = kDefaultExpirySec;
        }

        if (expires_in < kMinExpirySec) expires_in = kMinExpirySec;
        if (expires_in > kMaxExpirySec) expires_in = kMaxExpirySec;

        constexpr std::uint64_t kMaxConfiguredFileBytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL;      // 1 TiB
        constexpr std::uint64_t kMaxConfiguredTotalBytes = 10ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; // 10 TiB

        const std::uint64_t max_file_bytes =
            json_u64_local(in, "max_file_bytes", 0, kMaxConfiguredFileBytes);

        const std::uint64_t max_total_bytes =
            json_u64_local(in, "max_total_bytes", 0, kMaxConfiguredTotalBytes);

        const std::int64_t now = deps.now_epoch();

        const std::string id = "dz_" + deps.random_b64url(18);
        const std::string token = deps.random_b64url(32);

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            audit_local(deps, "v4.dropzones_create_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "token_hash_failed"},
                {"detail", herr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create token"}
            });
            return;
        }

        std::string password_hash;
        if (!password.empty()) {
            const std::string salt = deps.random_b64url(18);
            password_hash = pbkdf2_sha256_hash_password_local(password, salt, &herr);

            if (password_hash.empty()) {
                audit_local(deps, "v4.dropzones_create_fail", "fail", {
                    {"actor_fp", actor_fp},
                    {"reason", "password_hash_failed"},
                    {"detail", herr}
                });

                reply_json_local(deps, res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to hash password"}
                });
                return;
            }
        }

        DropZoneRec rec;
        rec.id = id;
        rec.token_hash = token_hash;
        rec.owner_fp = actor_fp;
        rec.name = name;
        rec.destination_path = dest_norm;
        rec.password_hash = password_hash;
        rec.created_epoch = now;
        rec.expires_epoch = now + expires_in;
        rec.last_used_epoch = 0;
        rec.max_file_bytes = max_file_bytes;
        rec.max_total_bytes = max_total_bytes;
        rec.bytes_uploaded = 0;
        rec.upload_count = 0;
        rec.disabled = false;

        std::string ierr;
        if (!deps.dropzone_index->insert(rec, &ierr)) {
            audit_local(deps, "v4.dropzones_create_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "insert_failed"},
                {"detail", ierr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create drop zone"}
            });
            return;
        }

        const std::string url = "/dz/" + token;
        const std::string full_url = *deps.origin + url;

        audit_local(deps, "v4.dropzones_create_ok", "ok", {
            {"actor_fp", actor_fp},
            {"dropzone_id", id},
            {"destination_path", dest_norm}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"id", id},
            {"url", url},
            {"full_url", full_url},
            {"expires_epoch", rec.expires_epoch},
            {"destination_path", rec.destination_path}
        });
    });
        srv.Post("/api/v4/dropzones/disable", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.users || !deps.cookie_key || !deps.require_user_auth_users_actor ||
            !deps.dropzone_index) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        std::string actor_fp;
        std::string actor_role;

        if (!deps.require_user_auth_users_actor(req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        if (!require_same_origin_for_cookie_mutation_local(req, res, deps)) {
            return;
        }

        json in = json::object();
        try {
            if (!req.body.empty()) in = json::parse(req.body);
        } catch (...) {
            audit_local(deps, "v4.dropzones_disable_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "bad_json"}
            });

            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            });
            return;
        }

        const std::string id = in.value("id", "");
        const bool disabled = in.contains("disabled") ? in.value("disabled", true) : true;

        if (id.empty()) {
            audit_local(deps, "v4.dropzones_disable_fail", "fail", {
                {"actor_fp", actor_fp},
                {"reason", "missing_id"}
            });

            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing id"}
            });
            return;
        }

        std::string err;
        if (!deps.dropzone_index->set_disabled(id, actor_fp, disabled, &err)) {
            audit_local(deps, "v4.dropzones_disable_fail", "fail", {
                {"actor_fp", actor_fp},
                {"dropzone_id", id},
                {"reason", "set_disabled_failed"},
                {"detail", err}
            });

            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        audit_local(deps, "v4.dropzones_disable_ok", "ok", {
            {"actor_fp", actor_fp},
            {"dropzone_id", id},
            {"disabled", disabled ? "true" : "false"}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"id", id},
            {"disabled", disabled}
        });
    });
        srv.Get(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/info)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.now_epoch) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            audit_local(deps, "public.dropzones_info_fail", "fail", {
                {"reason", "lookup_failed"},
                {"detail", gerr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec& rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        const std::int64_t seconds_remaining =
            rec.expires_epoch > now ? (rec.expires_epoch - now) : 0;

        res.set_header("Cache-Control", "no-store");

        // Public-safe metadata only.
        // Do NOT expose owner_fp, token_hash, password_hash, or destination_path.
        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"name", rec.name},
            {"expires_epoch", rec.expires_epoch},
            {"seconds_remaining", seconds_remaining},
            {"max_file_bytes", rec.max_file_bytes},
            {"max_total_bytes", rec.max_total_bytes},
            {"bytes_uploaded", rec.bytes_uploaded},
            {"upload_count", rec.upload_count},
            {"password_required", !rec.password_hash.empty()}
        });
    });
        srv.Get(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/uploads/list)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.now_epoch) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);

        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            audit_local(deps, "public.dropzones_uploads_list_fail", "fail", {
                {"reason", "lookup_failed"},
                {"detail", gerr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        std::string lerr;
        const auto rows = deps.dropzone_index->list_uploads(rec.id, 200, &lerr);

        if (!lerr.empty()) {
            audit_local(deps, "public.dropzones_uploads_list_fail", "fail", {
                {"dropzone_id", rec.id},
                {"reason", "list_uploads_failed"},
                {"detail", lerr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list uploads"}
            });
            return;
        }

        json uploads = json::array();

        for (const auto& row : rows) {
            uploads.push_back(json{
                {"stored_filename", row.stored_filename},
                {"size_bytes", row.size_bytes},
                {"created_epoch", row.created_epoch},
                {"uploader_name", row.uploader_name}
            });
        }

        res.set_header("Cache-Control", "no-store");

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"uploads", uploads}
        });
    });
    
        srv.Post(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/uploads/start)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.now_epoch || !deps.users ||
            !deps.user_dir_for_fp || !deps.random_b64url) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        if (!rec.password_hash.empty()) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "password_required"},
                {"message", "password-protected uploads are not wired yet"}
            });
            return;
        }

        auto owner_opt = deps.users->get(rec.owner_fp);
        if (!owner_opt.has_value()) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_unavailable"},
                {"message", "drop zone owner is unavailable"}
            });
            return;
        }

        if (owner_opt->status != "enabled" || owner_opt->storage_state != "allocated") {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_storage_unavailable"},
                {"message", "drop zone owner storage is unavailable"}
            });
            return;
        }

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            });
            return;
        }

        const std::string original_filename = body.value("filename", "upload.bin");
        const std::string safe_filename = safe_upload_filename_local(original_filename);

        std::uint64_t size_bytes = 0;
        if (!dz_json_u64_local(body, "size_bytes", &size_bytes) || size_bytes == 0) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "size_bytes required"}
            });
            return;
        }

        if (size_bytes > k_dropzone_max_session_bytes) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "upload_too_large"},
                {"message", "Drop Zone chunked upload exceeds maximum session size"},
                {"size_bytes", size_bytes},
                {"max_bytes", k_dropzone_max_session_bytes}
            });
            return;
        }

        if (rec.max_file_bytes > 0 && size_bytes > rec.max_file_bytes) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "file_too_large"},
                {"message", "file exceeds Drop Zone file size limit"},
                {"max_file_bytes", rec.max_file_bytes}
            });
            return;
        }

        if (rec.max_total_bytes > 0) {
            if (size_bytes > rec.max_total_bytes ||
                rec.bytes_uploaded > rec.max_total_bytes - size_bytes) {
                reply_json_local(deps, res, 413, json{
                    {"ok", false},
                    {"error", "dropzone_total_limit_exceeded"},
                    {"message", "upload would exceed Drop Zone total size limit"},
                    {"max_total_bytes", rec.max_total_bytes},
                    {"bytes_uploaded", rec.bytes_uploaded}
                });
                return;
            }
        }

        std::filesystem::path owner_root = deps.user_dir_for_fp(*deps.users, rec.owner_fp);
        owner_root = owner_root.lexically_normal();

        const std::filesystem::path dest_dir =
            (owner_root / std::filesystem::path(rec.destination_path)).lexically_normal();

        if (!path_has_prefix_components_local(owner_root, dest_dir)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "drop zone destination escaped owner root"}
            });
            return;
        }

        const std::uint64_t chunks_total =
            (size_bytes + k_dropzone_chunk_bytes - 1) / k_dropzone_chunk_bytes;

        const std::string upload_id = deps.random_b64url(24);
        const std::filesystem::path dir = dz_upload_session_dir_local(owner_root, rec.id, upload_id);

        std::error_code ec;
        std::filesystem::create_directories(dir / "chunks", ec);
        if (ec) {
            audit_local(deps, "public.dropzones_uploads_start_fail", "fail", {
                {"dropzone_id", rec.id},
                {"reason", "mkdir_failed"},
                {"detail", ec.message()}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create upload session"}
            });
            return;
        }

        const std::string uploader_name = body.value("uploader_name", "");
        const std::string uploader_message = body.value("uploader_message", "");

        json meta = json{
            {"ok", true},
            {"upload_id", upload_id},
            {"dropzone_id", rec.id},
            {"token_hash", token_hash},
            {"owner_fp", rec.owner_fp},
            {"destination_path", rec.destination_path},
            {"original_filename", original_filename},
            {"safe_filename", safe_filename},
            {"size_bytes", size_bytes},
            {"chunk_size", k_dropzone_chunk_bytes},
            {"chunks_total", chunks_total},
            {"uploader_name", uploader_name},
            {"uploader_message", uploader_message},
            {"created_epoch", now}
        };

        std::string werr;
        if (!dz_write_json_file_local(dir / "meta.json", meta, deps.random_b64url, &werr)) {
            std::filesystem::remove_all(dir, ec);

            audit_local(deps, "public.dropzones_uploads_start_fail", "fail", {
                {"dropzone_id", rec.id},
                {"reason", "write_meta_failed"},
                {"detail", werr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save upload session"}
            });
            return;
        }

        audit_local(deps, "public.dropzones_uploads_start_ok", "ok", {
            {"dropzone_id", rec.id},
            {"upload_id", upload_id},
            {"size_bytes", std::to_string(size_bytes)},
            {"chunks_total", std::to_string(chunks_total)}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"upload_id", upload_id},
            {"filename", safe_filename},
            {"size_bytes", size_bytes},
            {"chunk_size", k_dropzone_chunk_bytes},
            {"chunks_total", chunks_total}
        });
    });
            srv.Put(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/uploads/chunk)",
        [&](const httplib::Request& req,
            httplib::Response& res,
            const httplib::ContentReader& content_reader) {
        if (!deps.dropzone_index || !deps.now_epoch || !deps.users ||
            !deps.user_dir_for_fp || !deps.random_b64url) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        if (!rec.password_hash.empty()) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "password_required"},
                {"message", "password-protected uploads are not wired yet"}
            });
            return;
        }

        const std::string upload_id =
            req.has_param("upload_id") ? req.get_param_value("upload_id") : "";

        if (!dz_upload_id_ok_local(upload_id)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid upload_id"}
            });
            return;
        }

        if (!req.has_param("index")) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing index"}
            });
            return;
        }

        std::uint64_t chunk_index = 0;
        try {
            const std::string sidx = req.get_param_value("index");
            size_t pos = 0;
            unsigned long long v = std::stoull(sidx, &pos, 10);
            if (pos != sidx.size()) throw std::runtime_error("bad index");
            chunk_index = static_cast<std::uint64_t>(v);
        } catch (...) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid index"}
            });
            return;
        }

        auto owner_opt = deps.users->get(rec.owner_fp);
        if (!owner_opt.has_value() ||
            owner_opt->status != "enabled" ||
            owner_opt->storage_state != "allocated") {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_storage_unavailable"},
                {"message", "drop zone owner storage is unavailable"}
            });
            return;
        }

        std::filesystem::path owner_root = deps.user_dir_for_fp(*deps.users, rec.owner_fp);
        owner_root = owner_root.lexically_normal();

        const std::filesystem::path dir =
            dz_upload_session_dir_local(owner_root, rec.id, upload_id);

        json meta;
        std::string rerr;
        if (!dz_read_json_file_local(dir / "meta.json", &meta, &rerr)) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "upload session not found"}
            });
            return;
        }

        if (meta.value("dropzone_id", "") != rec.id ||
            meta.value("token_hash", "") != token_hash ||
            meta.value("owner_fp", "") != rec.owner_fp) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "upload session does not match this Drop Zone"}
            });
            return;
        }

        std::uint64_t size_bytes = 0;
        std::uint64_t chunk_size = 0;
        std::uint64_t chunks_total = 0;

        if (!dz_json_u64_local(meta, "size_bytes", &size_bytes) ||
            !dz_json_u64_local(meta, "chunk_size", &chunk_size) ||
            !dz_json_u64_local(meta, "chunks_total", &chunks_total) ||
            chunk_size == 0 ||
            chunks_total == 0 ||
            chunk_index >= chunks_total) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "bad upload session metadata"}
            });
            return;
        }

        const std::uint64_t expected_bytes =
            dz_expected_chunk_bytes_local(size_bytes, chunk_size, chunks_total, chunk_index);

        std::uint64_t content_length = 0;
        if (!dz_header_u64_local(req, "Content-Length", &content_length)) {
            reply_json_local(deps, res, 411, json{
                {"ok", false},
                {"error", "length_required"},
                {"message", "Content-Length required"}
            });
            return;
        }

        if (content_length != expected_bytes || content_length > chunk_size) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "chunk size mismatch"},
                {"content_length", content_length},
                {"expected_bytes", expected_bytes},
                {"chunk_size", chunk_size}
            });
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(dir / "chunks", ec);
        if (ec) {
            audit_local(deps, "public.dropzones_uploads_chunk_fail", "fail", {
                {"dropzone_id", rec.id},
                {"upload_id", upload_id},
                {"reason", "mkdir_failed"},
                {"detail", ec.message()}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to prepare chunk directory"}
            });
            return;
        }

        const std::filesystem::path final_chunk =
            dir / "chunks" / dz_chunk_name_local(chunk_index);

        const std::filesystem::path tmp_chunk =
            dir / "chunks" / (dz_chunk_name_local(chunk_index) + ".tmp." + deps.random_b64url(8));

        std::uint64_t bytes_written = 0;
        bool stream_ok = true;
        std::string stream_err;

        try {
            std::ofstream f(tmp_chunk, std::ios::binary | std::ios::trunc);
            if (!f.good()) throw std::runtime_error("open chunk tmp failed");

            content_reader([&](const char* data, size_t len) {
                if (!stream_ok) return false;
                if (len == 0) return true;

                const std::uint64_t next =
                    bytes_written + static_cast<std::uint64_t>(len);

                if (next < bytes_written || next > expected_bytes) {
                    stream_ok = false;
                    stream_err = "chunk_length_exceeded";
                    return false;
                }

                f.write(data, static_cast<std::streamsize>(len));
                if (!f.good()) {
                    stream_ok = false;
                    stream_err = "write_chunk_failed";
                    return false;
                }

                bytes_written = next;
                return true;
            });

            f.flush();
            if (!f.good()) throw std::runtime_error("flush chunk tmp failed");
            f.close();

            if (!stream_ok || bytes_written != expected_bytes) {
                std::filesystem::remove(tmp_chunk, ec);

                reply_json_local(deps, res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", stream_ok ? "chunk length mismatch" : stream_err},
                    {"bytes_written", bytes_written},
                    {"expected_bytes", expected_bytes}
                });
                return;
            }

            std::filesystem::rename(tmp_chunk, final_chunk, ec);
            if (ec) throw std::runtime_error("rename chunk failed: " + ec.message());

        } catch (const std::exception& e) {
            std::filesystem::remove(tmp_chunk, ec);

            audit_local(deps, "public.dropzones_uploads_chunk_fail", "fail", {
                {"dropzone_id", rec.id},
                {"upload_id", upload_id},
                {"reason", "write_failed"},
                {"detail", e.what()}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to write upload chunk"}
            });
            return;
        }

        audit_local(deps, "public.dropzones_uploads_chunk_ok", "ok", {
            {"dropzone_id", rec.id},
            {"upload_id", upload_id},
            {"index", std::to_string(chunk_index)},
            {"bytes", std::to_string(bytes_written)}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"upload_id", upload_id},
            {"index", chunk_index},
            {"bytes", bytes_written}
        });
    });
            srv.Post(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/uploads/cancel)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.users || !deps.user_dir_for_fp) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;

        json body = json::parse(req.body, nullptr, false);
        const std::string upload_id =
            (!body.is_discarded() && body.is_object())
                ? body.value("upload_id", "")
                : "";

        if (!dz_upload_id_ok_local(upload_id)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid upload_id"}
            });
            return;
        }

        std::filesystem::path owner_root = deps.user_dir_for_fp(*deps.users, rec.owner_fp);
        owner_root = owner_root.lexically_normal();

        const auto dir = dz_upload_session_dir_local(owner_root, rec.id, upload_id);

        std::error_code ec;
        const auto removed = std::filesystem::remove_all(dir, ec);

        if (ec) {
            audit_local(deps, "public.dropzones_uploads_cancel_fail", "fail", {
                {"dropzone_id", rec.id},
                {"upload_id", upload_id},
                {"reason", "remove_failed"},
                {"detail", ec.message()}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to cancel upload"}
            });
            return;
        }

        audit_local(deps, "public.dropzones_uploads_cancel_ok", "ok", {
            {"dropzone_id", rec.id},
            {"upload_id", upload_id},
            {"removed_entries", std::to_string(static_cast<unsigned long long>(removed))}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"upload_id", upload_id},
            {"removed_entries", removed}
        });
    });
            srv.Post(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/uploads/finish)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.now_epoch || !deps.users ||
            !deps.user_dir_for_fp || !deps.random_b64url) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        if (!rec.password_hash.empty()) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "password_required"},
                {"message", "password-protected uploads are not wired yet"}
            });
            return;
        }

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            });
            return;
        }

        const std::string upload_id = body.value("upload_id", "");
        if (!dz_upload_id_ok_local(upload_id)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid upload_id"}
            });
            return;
        }

        auto owner_opt = deps.users->get(rec.owner_fp);
        if (!owner_opt.has_value() ||
            owner_opt->status != "enabled" ||
            owner_opt->storage_state != "allocated") {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_storage_unavailable"},
                {"message", "drop zone owner storage is unavailable"}
            });
            return;
        }

        std::filesystem::path owner_root = deps.user_dir_for_fp(*deps.users, rec.owner_fp);
        owner_root = owner_root.lexically_normal();

        const std::filesystem::path dir =
            dz_upload_session_dir_local(owner_root, rec.id, upload_id);

        json meta;
        std::string rerr;
        if (!dz_read_json_file_local(dir / "meta.json", &meta, &rerr)) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "upload session not found"}
            });
            return;
        }

        if (meta.value("dropzone_id", "") != rec.id ||
            meta.value("token_hash", "") != token_hash ||
            meta.value("owner_fp", "") != rec.owner_fp) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "upload session does not match this Drop Zone"}
            });
            return;
        }

        std::uint64_t size_bytes = 0;
        std::uint64_t chunk_size = 0;
        std::uint64_t chunks_total = 0;

        if (!dz_json_u64_local(meta, "size_bytes", &size_bytes) ||
            !dz_json_u64_local(meta, "chunk_size", &chunk_size) ||
            !dz_json_u64_local(meta, "chunks_total", &chunks_total) ||
            size_bytes == 0 ||
            chunk_size == 0 ||
            chunks_total == 0) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "bad upload session metadata"}
            });
            return;
        }

        if (rec.max_file_bytes > 0 && size_bytes > rec.max_file_bytes) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "file_too_large"},
                {"message", "file exceeds Drop Zone file size limit"}
            });
            return;
        }

        if (rec.max_total_bytes > 0) {
            if (size_bytes > rec.max_total_bytes ||
                rec.bytes_uploaded > rec.max_total_bytes - size_bytes) {
                reply_json_local(deps, res, 413, json{
                    {"ok", false},
                    {"error", "dropzone_total_limit_exceeded"},
                    {"message", "upload would exceed Drop Zone total size limit"}
                });
                return;
            }
        }

        for (std::uint64_t i = 0; i < chunks_total; ++i) {
            const auto chunk_path = dir / "chunks" / dz_chunk_name_local(i);
            const std::uint64_t expected =
                dz_expected_chunk_bytes_local(size_bytes, chunk_size, chunks_total, i);

            std::error_code ec;
            auto st = std::filesystem::symlink_status(chunk_path, ec);

            if (ec || !std::filesystem::exists(st) ||
                std::filesystem::is_symlink(st) ||
                !std::filesystem::is_regular_file(st)) {
                reply_json_local(deps, res, 400, json{
                    {"ok", false},
                    {"error", "missing_chunk"},
                    {"message", "upload chunk missing"},
                    {"index", i}
                });
                return;
            }

            const std::uint64_t actual =
                static_cast<std::uint64_t>(std::filesystem::file_size(chunk_path, ec));

            if (ec || actual != expected) {
                reply_json_local(deps, res, 400, json{
                    {"ok", false},
                    {"error", "bad_chunk"},
                    {"message", "upload chunk has wrong size"},
                    {"index", i},
                    {"expected_bytes", expected},
                    {"actual_bytes", actual}
                });
                return;
            }
        }

        const std::filesystem::path dest_dir =
            (owner_root / std::filesystem::path(rec.destination_path)).lexically_normal();

        if (!path_has_prefix_components_local(owner_root, dest_dir)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "drop zone destination escaped owner root"}
            });
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(dest_dir, ec);
        if (ec) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create destination directory"}
            });
            return;
        }

        const std::string original_filename = meta.value("original_filename", "upload.bin");
        const std::string safe_filename =
            safe_upload_filename_local(meta.value("safe_filename", original_filename));

        const std::filesystem::path final_path =
            unique_child_path_local(dest_dir, safe_filename);

        const std::filesystem::path final_norm = final_path.lexically_normal();

        if (!path_has_prefix_components_local(owner_root, final_norm)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "upload path escaped owner root"}
            });
            return;
        }

        const std::filesystem::path tmp =
            final_norm.parent_path() /
            (final_norm.filename().string() + ".dropzone." + deps.random_b64url(8) + ".tmp");

        std::uint64_t assembled_bytes = 0;

        try {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out.good()) throw std::runtime_error("open assembled tmp failed");

            std::array<char, 1024 * 1024> buf{};

            for (std::uint64_t i = 0; i < chunks_total; ++i) {
                const auto chunk_path = dir / "chunks" / dz_chunk_name_local(i);
                std::ifstream in(chunk_path, std::ios::binary);
                if (!in.good()) {
                    throw std::runtime_error("open chunk failed index=" + std::to_string(static_cast<unsigned long long>(i)));
                }

                while (in.good()) {
                    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
                    const std::streamsize n = in.gcount();

                    if (n > 0) {
                        out.write(buf.data(), n);
                        if (!out.good()) throw std::runtime_error("write assembled tmp failed");
                        assembled_bytes += static_cast<std::uint64_t>(n);
                    }
                }

                if (!in.eof()) {
                    throw std::runtime_error("read chunk failed index=" + std::to_string(static_cast<unsigned long long>(i)));
                }
            }

            out.flush();
            if (!out.good()) throw std::runtime_error("flush assembled tmp failed");
            out.close();

            if (assembled_bytes != size_bytes) {
                throw std::runtime_error("assembled size mismatch");
            }

            std::filesystem::rename(tmp, final_norm, ec);
            if (ec) throw std::runtime_error("rename assembled file failed: " + ec.message());

        } catch (const std::exception& e) {
            std::filesystem::remove(tmp, ec);

            audit_local(deps, "public.dropzones_uploads_finish_fail", "fail", {
                {"dropzone_id", rec.id},
                {"upload_id", upload_id},
                {"reason", "finish_failed"},
                {"detail", e.what()}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "chunked upload finish failed"}
            });
            return;
        }

        std::string rel_path;
        {
            std::error_code rec_ec;
            rel_path = std::filesystem::relative(final_norm, owner_root, rec_ec).generic_string();

            if (rec_ec || rel_path.empty()) {
                rel_path = (std::filesystem::path(rec.destination_path) / final_norm.filename()).generic_string();
            }
        }

        std::string sha_err;
        const std::string sha256 = sha256_hex_file_local(final_norm, &sha_err);

        DropZoneUploadRec upload;
        upload.id = "dzu_" + deps.random_b64url(18);
        upload.drop_zone_id = rec.id;
        upload.original_filename = original_filename;
        upload.stored_filename = final_norm.filename().string();
        upload.stored_path = rel_path;
        upload.size_bytes = assembled_bytes;
        upload.sha256 = sha256;
        upload.uploader_name = meta.value("uploader_name", "");
        upload.uploader_message = meta.value("uploader_message", "");
        upload.remote_ip = req.remote_addr;
        upload.user_agent = header_value_local(req, "User-Agent");
        upload.created_epoch = now;
        upload.scan_status = "not_scanned";

        std::string db_err;
        if (!deps.dropzone_index->record_upload(upload, &db_err)) {
            std::filesystem::remove(final_norm, ec);

            audit_local(deps, "public.dropzones_uploads_finish_fail", "fail", {
                {"dropzone_id", rec.id},
                {"upload_id", upload_id},
                {"reason", "record_upload_failed"},
                {"detail", db_err}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to record upload"}
            });
            return;
        }

        std::filesystem::remove_all(dir, ec);

        audit_local(deps, "public.dropzones_uploads_finish_ok", "ok", {
            {"dropzone_id", rec.id},
            {"upload_id", upload_id},
            {"stored_path", rel_path},
            {"size_bytes", std::to_string(assembled_bytes)}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"chunked", true},
            {"dropzone_id", rec.id},
            {"stored_filename", upload.stored_filename},
            {"stored_path", upload.stored_path},
            {"size_bytes", upload.size_bytes},
            {"sha256", upload.sha256}
        });
    });
        srv.Post(R"(/api/public/dropzones/([A-Za-z0-9_-]{20,160})/upload)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!deps.dropzone_index || !deps.now_epoch || !deps.users || !deps.user_dir_for_fp) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "dropzone route dependencies missing"}
            });
            return;
        }

        const std::string token = req.matches[1];

        std::string herr;
        const std::string token_hash = sha256_hex_string_local(token, &herr);
        if (token_hash.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to check token"}
            });
            return;
        }

        std::string gerr;
        auto rec_opt = deps.dropzone_index->get_by_token_hash(token_hash, &gerr);

        if (!gerr.empty()) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read drop zone"}
            });
            return;
        }

        if (!rec_opt.has_value()) {
            reply_json_local(deps, res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "drop zone not found"}
            });
            return;
        }

        const DropZoneRec rec = *rec_opt;
        const std::int64_t now = deps.now_epoch();

        if (rec.disabled) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "disabled"},
                {"message", "drop zone is disabled"}
            });
            return;
        }

        if (rec.expires_epoch > 0 && rec.expires_epoch <= now) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "expired"},
                {"message", "drop zone has expired"}
            });
            return;
        }

        if (!rec.password_hash.empty()) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "password_required"},
                {"message", "password-protected uploads are not wired yet"}
            });
            return;
        }

        auto owner_opt = deps.users->get(rec.owner_fp);
        if (!owner_opt.has_value()) {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_unavailable"},
                {"message", "drop zone owner is unavailable"}
            });
            return;
        }

        if (owner_opt->status != "enabled" || owner_opt->storage_state != "allocated") {
            reply_json_local(deps, res, 410, json{
                {"ok", false},
                {"error", "owner_storage_unavailable"},
                {"message", "drop zone owner storage is unavailable"}
            });
            return;
        }

        const std::uint64_t upload_bytes = static_cast<std::uint64_t>(req.body.size());

        if (upload_bytes == 0) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "empty upload"}
            });
            return;
        }

        if (rec.max_file_bytes > 0 && upload_bytes > rec.max_file_bytes) {
            reply_json_local(deps, res, 413, json{
                {"ok", false},
                {"error", "file_too_large"},
                {"message", "file exceeds Drop Zone file size limit"},
                {"max_file_bytes", rec.max_file_bytes}
            });
            return;
        }

        if (rec.max_total_bytes > 0) {
            if (upload_bytes > rec.max_total_bytes ||
                rec.bytes_uploaded > rec.max_total_bytes - upload_bytes) {
                reply_json_local(deps, res, 413, json{
                    {"ok", false},
                    {"error", "dropzone_total_limit_exceeded"},
                    {"message", "upload would exceed Drop Zone total size limit"},
                    {"max_total_bytes", rec.max_total_bytes},
                    {"bytes_uploaded", rec.bytes_uploaded}
                });
                return;
            }
        }

        std::string filename = header_value_local(req, "X-DropZone-Filename");
        if (filename.empty()) filename = "upload.bin";
        const std::string original_filename = filename;
        const std::string safe_filename = safe_upload_filename_local(filename);

        std::filesystem::path owner_root = deps.user_dir_for_fp(*deps.users, rec.owner_fp);
        owner_root = owner_root.lexically_normal();

        const std::filesystem::path dest_dir =
            (owner_root / std::filesystem::path(rec.destination_path)).lexically_normal();

        if (!path_has_prefix_components_local(owner_root, dest_dir)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "drop zone destination escaped owner root"}
            });
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(dest_dir, ec);
        if (ec) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create destination directory"}
            });
            return;
        }

        const std::filesystem::path final_path = unique_child_path_local(dest_dir, safe_filename);
        const std::filesystem::path final_norm = final_path.lexically_normal();

        if (!path_has_prefix_components_local(owner_root, final_norm)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "upload path escaped owner root"}
            });
            return;
        }

        std::string werr;
        if (!write_file_atomic_local(final_norm, req.body, deps.random_b64url, &werr)) {
            audit_local(deps, "public.dropzones_upload_fail", "fail", {
                {"dropzone_id", rec.id},
                {"reason", "write_failed"},
                {"detail", werr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to store uploaded file"}
            });
            return;
        }

        std::string rel_path;
        {
            std::error_code rec_ec;
            rel_path = std::filesystem::relative(final_norm, owner_root, rec_ec).generic_string();
            if (rec_ec || rel_path.empty()) {
                rel_path = (std::filesystem::path(rec.destination_path) / final_norm.filename()).generic_string();
            }
        }

        std::string sha_err;
        const std::string sha256 = sha256_hex_string_local(req.body, &sha_err);

        DropZoneUploadRec upload;
        upload.id = "dzu_" + deps.random_b64url(18);
        upload.drop_zone_id = rec.id;
        upload.original_filename = original_filename;
        upload.stored_filename = final_norm.filename().string();
        upload.stored_path = rel_path;
        upload.size_bytes = upload_bytes;
        upload.sha256 = sha256;
        upload.uploader_name = header_value_local(req, "X-DropZone-Uploader");
        upload.uploader_message = header_value_local(req, "X-DropZone-Message");
        upload.remote_ip = req.remote_addr;
        upload.user_agent = header_value_local(req, "User-Agent");
        upload.created_epoch = now;
        upload.scan_status = "not_scanned";

        std::string rerr;
        if (!deps.dropzone_index->record_upload(upload, &rerr)) {
            std::filesystem::remove(final_norm, ec);

            audit_local(deps, "public.dropzones_upload_fail", "fail", {
                {"dropzone_id", rec.id},
                {"reason", "record_upload_failed"},
                {"detail", rerr}
            });

            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to record upload"}
            });
            return;
        }

        audit_local(deps, "public.dropzones_upload_ok", "ok", {
            {"dropzone_id", rec.id},
            {"stored_path", rel_path},
            {"size_bytes", std::to_string(upload_bytes)}
        });

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"dropzone_id", rec.id},
            {"stored_filename", upload.stored_filename},
            {"stored_path", upload.stored_path},
            {"size_bytes", upload.size_bytes},
            {"sha256", upload.sha256}
        });
    });
        srv.Get(R"(/dz/([A-Za-z0-9_-]{20,160}))", [&](const httplib::Request& req, httplib::Response& res) {
        const std::string token = req.matches[1];

        res.status = 200;
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.set_header("X-Content-Type-Options", "nosniff");

        res.body = std::string(R"HTML(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DNA-Nexus • Drop Zone</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: dark;
      --bg: #080a0f;
      --panel: rgba(255,255,255,.07);
      --panel2: rgba(255,255,255,.10);
      --text: #f3f6ff;
      --muted: rgba(243,246,255,.68);
      --line: rgba(255,255,255,.14);
      --accent: #ff9f1c;
      --good: #50fa7b;
      --bad: #ff5555;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, rgba(255,159,28,.22), transparent 34rem),
        radial-gradient(circle at bottom right, rgba(80,250,123,.10), transparent 34rem),
        var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: grid;
      place-items: center;
      padding: 24px;
    }

    .shell {
      width: min(760px, 100%);
      border: 1px solid var(--line);
      border-radius: 28px;
      background: linear-gradient(135deg, rgba(255,255,255,.10), rgba(255,255,255,.04));
      box-shadow: 0 28px 90px rgba(0,0,0,.42);
      overflow: hidden;
    }

    .hero {
      padding: 30px;
      border-bottom: 1px solid var(--line);
    }

    .kicker {
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .14em;
      font-size: 12px;
      font-weight: 900;
    }

    h1 {
      margin: 8px 0 0;
      font-size: clamp(34px, 7vw, 62px);
      line-height: .95;
    }

    .sub {
      margin: 14px 0 0;
      color: var(--muted);
      line-height: 1.55;
    }

    .body {
      padding: 24px 30px 30px;
    }

    .status {
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 18px;
      background: rgba(0,0,0,.22);
    }

    .status.good { border-color: rgba(80,250,123,.38); }
    .status.bad { border-color: rgba(255,85,85,.42); }

    .title {
      font-size: 20px;
      font-weight: 900;
    }

    .meta {
      margin-top: 10px;
      color: var(--muted);
      display: grid;
      gap: 6px;
      line-height: 1.45;
    }

    .uploadBox {
      margin-top: 18px;
      border: 1px dashed rgba(255,255,255,.26);
      border-radius: 22px;
      padding: 22px;
      background: rgba(255,255,255,.045);
      text-align: center;
    }

    .uploadBox strong {
      display: block;
      font-size: 18px;
    }

    .uploadBox span {
      display: block;
      margin-top: 8px;
      color: var(--muted);
    }

    .fieldGrid {
      margin-top: 18px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      text-align: left;
    }

    label {
      display: grid;
      gap: 7px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 800;
    }

    label em {
      font-style: normal;
      font-weight: 600;
      opacity: .68;
    }

    input[type="text"],
    .fileInput {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 11px 12px;
      background: rgba(0,0,0,.25);
      color: var(--text);
    }

    .fileInput {
      margin-top: 16px;
    }

    button {
      margin-top: 16px;
      border: 0;
      border-radius: 14px;
      padding: 12px 16px;
      background: var(--accent);
      color: #160d00;
      font-weight: 900;
      cursor: pointer;
    }

    button:disabled {
      opacity: .55;
      cursor: wait;
    }

    .uploadLog {
      margin-top: 16px;
      display: grid;
      gap: 8px;
      text-align: left;
    }

    .uploadRow {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(0,0,0,.18);
      color: var(--muted);
      word-break: break-word;
    }

    .uploadRow.ok {
      border-color: rgba(80,250,123,.36);
      color: var(--text);
    }

    .uploadRow.fail {
      border-color: rgba(255,85,85,.42);
      color: var(--text);
    }

    .uploadedListBox {
      margin-top: 18px;
      border-top: 1px solid var(--line);
      padding-top: 16px;
      text-align: left;
    }

    .uploadedListTitle {
      font-size: 14px;
      font-weight: 900;
      color: var(--text);
      margin-bottom: 10px;
    }

    .uploadedList {
      display: grid;
      gap: 8px;
      color: var(--muted);
    }

    .uploadedItem {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(0,0,0,.16);
      display: grid;
      gap: 3px;
      word-break: break-word;
    }

    .uploadedItem strong {
      color: var(--text);
      font-size: 14px;
    }

    .uploadedItem span {
      color: var(--muted);
      font-size: 13px;
    }

    @media (max-width: 640px) {
      .fieldGrid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="kicker">DNA-Nexus Drop Zone</div>
      <h1>Secure upload area</h1>
      <p class="sub">
        You can upload files here. You cannot browse, download, rename,
        or delete anything on this server.
      </p>
    </section>

    <section class="body">
      <div id="status" class="status">
        <div class="title">Checking Drop Zone…</div>
        <div class="meta">Please wait.</div>
      </div>

      <div id="uploadBox" class="uploadBox" style="display:none">
        <strong>Select files to upload</strong>
        <span>Files are uploaded one-by-one into this Drop Zone.</span>

        <div class="fieldGrid">
          <label>
            Your name <em>optional</em>
            <input id="uploaderName" type="text" maxlength="80" placeholder="Name">
          </label>

          <label>
            Message <em>optional</em>
            <input id="uploaderMessage" type="text" maxlength="160" placeholder="Short note">
          </label>
        </div>

        <input id="fileInput" class="fileInput" type="file" multiple>
        <button id="uploadBtn" type="button">Upload selected files</button>

        <div id="uploadLog" class="uploadLog"></div>

        <div id="uploadedListBox" class="uploadedListBox">
          <div class="uploadedListTitle">Already uploaded</div>
          <div id="uploadedList" class="uploadedList muted">Loading…</div>
        </div>
      </div>
    </section>
  </main>

  <script>
    const TOKEN = ")HTML") + token + R"HTML(";
    let CURRENT_INFO = null;

    function fmtBytes(n) {
      n = Number(n || 0);
      if (!Number.isFinite(n) || n <= 0) return "No limit";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (n >= 1024 && i < units.length - 1) {
        n /= 1024;
        i++;
      }
      return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
    }

    function fmtRemaining(sec) {
      sec = Number(sec || 0);
      if (sec <= 0) return "Expired";
      const d = Math.floor(sec / 86400);
      const h = Math.floor((sec % 86400) / 3600);
      const m = Math.floor((sec % 3600) / 60);
      if (d > 0) return `${d}d ${h}h`;
      if (h > 0) return `${h}h ${m}m`;
      return `${m}m`;
    }

    function safeHeaderText(value, fallback, maxLen) {
      let s = String(value || fallback || "");
      s = s.replace(/[\r\n]/g, " ");
      s = s.replace(/[^\x20-\x7E]/g, "_");
      s = s.trim();
      if (!s) s = fallback || "";
      if (maxLen && s.length > maxLen) s = s.slice(0, maxLen);
      return s;
    }

    function appendUploadLog(kind, text) {
      const log = document.getElementById("uploadLog");
      if (!log) return null;

      const row = document.createElement("div");
      row.className = `uploadRow ${kind || ""}`;
      row.textContent = text;
      log.appendChild(row);
      return row;
    }


    function setUploadBusy(on) {
      const btn = document.getElementById("uploadBtn");
      const input = document.getElementById("fileInput");
      if (btn) btn.disabled = !!on;
      if (input) input.disabled = !!on;
    }

    async function postDropZoneUploadJson(url, body) {
      const res = await fetch(url, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify(body || {})
      });

      const text = await res.text().catch(() => "");
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch (_) {}

      if (!res.ok || !json || json.ok !== true) {
        const err = new Error(
          json && (json.message || json.error)
            ? `${json.error || ""} ${json.message || ""}`.trim()
            : (text ? text.replace(/\s+/g, " ").slice(0, 200) : `HTTP ${res.status}`)
        );
        err.http = res.status;
        err.details = json;
        throw err;
      }

      return json;
    }

    function xhrPutDropZoneBlob(url, blob, onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        xhr.open("PUT", url, true);
        xhr.setRequestHeader("Content-Type", "application/octet-stream");
        xhr.timeout = 60 * 60 * 1000;

        xhr.upload.onprogress = (e) => {
          if (!onProgress) return;
          if (e.lengthComputable) onProgress(e.loaded, e.total);
          else onProgress(e.loaded, blob.size || 0);
        };

        xhr.ontimeout = () => reject(new Error("upload chunk failed: timeout"));
        xhr.onerror = () => reject(new Error("upload chunk failed: network error"));
        xhr.onabort = () => reject(new Error("upload chunk aborted"));

        xhr.onload = () => {
          const status = xhr.status || 0;
          const raw = String(xhr.responseText || "").trim();

          let json = null;
          if (raw && (raw.startsWith("{") || raw.startsWith("["))) {
            try { json = JSON.parse(raw); } catch (_) {}
          }

          if (status >= 200 && status < 300 && json && json.ok) {
            resolve(json);
            return;
          }

          const err = new Error(
            json && (json.message || json.error)
              ? `${json.error || ""} ${json.message || ""}`.trim()
              : (raw ? raw.replace(/\s+/g, " ").slice(0, 200) : `HTTP ${status}`)
          );
          err.http = status;
          err.details = json;
          reject(err);
        };

        xhr.send(blob);
      });
    }

    async function cancelDropZoneUploadBestEffort(uploadId) {
      if (!uploadId) return;

      try {
        await postDropZoneUploadJson(
          `/api/public/dropzones/${encodeURIComponent(TOKEN)}/uploads/cancel`,
          { upload_id: uploadId }
        );
      } catch (_) {}
    }

    async function uploadFileChunkedToDropZone(file, uploader, message, onProgress) {
      const size = Number(file && file.size != null ? file.size : 0);
      let uploadId = "";
      let uploadedCommitted = 0;

      try {
        const start = await postDropZoneUploadJson(
          `/api/public/dropzones/${encodeURIComponent(TOKEN)}/uploads/start`,
          {
            filename: safeHeaderText(file.name, "upload.bin", 180),
            size_bytes: size,
            uploader_name: uploader || "",
            uploader_message: message || ""
          }
        );

        uploadId = String(start.upload_id || "");
        const chunkSize = Math.max(1, Number(start.chunk_size || (64 * 1024 * 1024)));
        const chunksTotal = Math.max(0, Number(start.chunks_total || Math.ceil(size / chunkSize)));

        if (!uploadId || chunksTotal < 1) {
          throw new Error("invalid chunked upload session");
        }

        for (let index = 0; index < chunksTotal; index++) {
          const begin = index * chunkSize;
          const end = Math.min(size, begin + chunkSize);
          const blob = file.slice(begin, end);

          const url =
            `/api/public/dropzones/${encodeURIComponent(TOKEN)}/uploads/chunk` +
            `?upload_id=${encodeURIComponent(uploadId)}` +
            `&index=${encodeURIComponent(String(index))}`;

          await xhrPutDropZoneBlob(url, blob, (loaded) => {
            const totalLoaded = uploadedCommitted + Math.max(0, Number(loaded || 0));
            if (onProgress) {
              onProgress(totalLoaded, size, {
                chunkIndex: index,
                chunksTotal,
                chunkLoaded: loaded,
                chunkSize: blob.size
              });
            }
          });

          uploadedCommitted += blob.size;

          if (onProgress) {
            onProgress(uploadedCommitted, size, {
              chunkIndex: index,
              chunksTotal,
              chunkLoaded: blob.size,
              chunkSize: blob.size
            });
          }
        }

        const finish = await postDropZoneUploadJson(
          `/api/public/dropzones/${encodeURIComponent(TOKEN)}/uploads/finish`,
          { upload_id: uploadId }
        );

        uploadId = "";
        return finish;
      } catch (e) {
        if (uploadId) await cancelDropZoneUploadBestEffort(uploadId);
        throw e;
      }
    }


    async function uploadSelectedFiles() {
      const input = document.getElementById("fileInput");
      const log = document.getElementById("uploadLog");

      if (!input || !input.files || input.files.length === 0) {
        appendUploadLog("fail", "Select one or more files first.");
        return;
      }

      if (!CURRENT_INFO || CURRENT_INFO.ok === false) {
        appendUploadLog("fail", "Drop Zone is not ready.");
        return;
      }

      if (log) log.innerHTML = "";
      setUploadBusy(true);

      const uploader = safeHeaderText(document.getElementById("uploaderName")?.value || "", "", 80);
      const message = safeHeaderText(document.getElementById("uploaderMessage")?.value || "", "", 160);

      const maxFile = Number(CURRENT_INFO.max_file_bytes || 0);
      const maxTotal = Number(CURRENT_INFO.max_total_bytes || 0);
      let localUploaded = Number(CURRENT_INFO.bytes_uploaded || 0);

      try {
        for (const file of Array.from(input.files)) {
          if (!file || Number(file.size || 0) <= 0) {
            appendUploadLog("fail", `${file && file.name ? file.name : "file"}: skipped, empty files are not supported.`);
            continue;
          }

          if (maxFile > 0 && file.size > maxFile) {
            appendUploadLog("fail", `${file.name}: skipped, file is larger than ${fmtBytes(maxFile)}.`);
            continue;
          }

          if (maxTotal > 0 && localUploaded + file.size > maxTotal) {
            appendUploadLog("fail", `${file.name}: skipped, total Drop Zone limit would be exceeded.`);
            continue;
          }

          const row = appendUploadLog("", `${file.name}: starting chunked upload…`);

          try {
            const result = await uploadFileChunkedToDropZone(file, uploader, message, (loaded, total, ctx) => {
              const pct = total > 0 ? Math.min(100, Math.max(0, (loaded / total) * 100)) : 0;
              const chunkText = ctx && ctx.chunksTotal
                ? `chunk ${(ctx.chunkIndex || 0) + 1}/${ctx.chunksTotal}`
                : "chunk";

              if (row) {
                row.className = "uploadRow";
                row.textContent = `${file.name}: ${pct.toFixed(1)}% (${fmtBytes(loaded)} / ${fmtBytes(total)}), ${chunkText}`;
              }
            });

            localUploaded += Number(result.size_bytes || file.size || 0);

            if (row) {
              row.className = "uploadRow ok";
              row.textContent = `${file.name}: uploaded as ${result.stored_filename || file.name} (${fmtBytes(result.size_bytes || file.size)})`;
            } else {
              appendUploadLog("ok", `${file.name}: uploaded (${fmtBytes(result.size_bytes || file.size)})`);
            }
          } catch (e) {
            if (row) {
              row.className = "uploadRow fail";
              row.textContent = `${file.name}: failed — ${e && e.message ? e.message : String(e)}`;
            } else {
              appendUploadLog("fail", `${file.name}: failed — ${e && e.message ? e.message : String(e)}`);
            }
          }
        }

        CURRENT_INFO.bytes_uploaded = localUploaded;

        const info = await fetch(`/api/public/dropzones/${encodeURIComponent(TOKEN)}/info`, {
          cache: "no-store"
        }).then(r => r.json()).catch(() => null);

        if (info && info.ok) {
          CURRENT_INFO = info;
          setStatus("good", info.name || "Drop Zone", [
            `Expires in: ${fmtRemaining(info.seconds_remaining)}`,
            `Max file size: ${fmtBytes(info.max_file_bytes)}`,
            `Total limit: ${fmtBytes(info.max_total_bytes)}`,
            `Uploaded so far: ${fmtBytes(info.bytes_uploaded)} in ${info.upload_count || 0} file(s)`,
            info.password_required ? "Password required" : "No password required"
          ]);
        }

        await refreshUploadedList();
      } finally {
        setUploadBusy(false);
      }
    }


    function fmtEpoch(epoch) {
      const n = Number(epoch || 0);
      if (!Number.isFinite(n) || n <= 0) return "";
      try {
        return new Date(n * 1000).toLocaleString();
      } catch (_) {
        return "";
      }
    }

    async function refreshUploadedList() {
      const box = document.getElementById("uploadedList");
      if (!box) return;

      try {
        const res = await fetch(`/api/public/dropzones/${encodeURIComponent(TOKEN)}/uploads/list`, {
          cache: "no-store"
        });

        const json = await res.json().catch(() => null);

        if (!res.ok || !json || json.ok === false) {
          box.textContent = "Could not load uploaded file list.";
          return;
        }

        const uploads = Array.isArray(json.uploads) ? json.uploads : [];
        box.innerHTML = "";

        if (!uploads.length) {
          box.textContent = "No files uploaded yet.";
          return;
        }

        for (const item of uploads) {
          const row = document.createElement("div");
          row.className = "uploadedItem";

          const name = document.createElement("strong");
          name.textContent = item.stored_filename || "uploaded file";

          const meta = document.createElement("span");
          const parts = [];
          parts.push(fmtBytes(item.size_bytes || 0));

          const when = fmtEpoch(item.created_epoch);
          if (when) parts.push(when);

          if (item.uploader_name) {
            parts.push(`from ${item.uploader_name}`);
          }

          meta.textContent = parts.join(" • ");

          row.appendChild(name);
          row.appendChild(meta);
          box.appendChild(row);
        }
      } catch (e) {
        box.textContent = "Could not load uploaded file list.";
      }
    }

    function setStatus(kind, title, lines) {
      const box = document.getElementById("status");
      box.className = `status ${kind || ""}`;
      box.innerHTML = `
        <div class="title"></div>
        <div class="meta"></div>
      `;
      box.querySelector(".title").textContent = title;
      const meta = box.querySelector(".meta");
      meta.innerHTML = "";
      for (const line of lines || []) {
        const div = document.createElement("div");
        div.textContent = line;
        meta.appendChild(div);
      }
    }

    async function main() {
      try {
        const res = await fetch(`/api/public/dropzones/${encodeURIComponent(TOKEN)}/info`, {
          cache: "no-store"
        });

        const json = await res.json().catch(() => null);

        if (!res.ok || !json || json.ok === false) {
          const msg = json && (json.message || json.error)
            ? (json.message || json.error)
            : `HTTP ${res.status}`;

          setStatus("bad", "Drop Zone unavailable", [msg]);
          return;
        }

        setStatus("good", json.name || "Drop Zone", [
          `Expires in: ${fmtRemaining(json.seconds_remaining)}`,
          `Max file size: ${fmtBytes(json.max_file_bytes)}`,
          `Total limit: ${fmtBytes(json.max_total_bytes)}`,
          `Uploaded so far: ${fmtBytes(json.bytes_uploaded)} in ${json.upload_count || 0} file(s)`,
          json.password_required ? "Password required" : "No password required"
        ]);

        CURRENT_INFO = json;
        document.getElementById("uploadBox").style.display = "";
        await refreshUploadedList();
      } catch (e) {
        setStatus("bad", "Could not load Drop Zone", [
          String(e && e.message ? e.message : e)
        ]);
      }
    }

    document.getElementById("uploadBtn")?.addEventListener("click", uploadSelectedFiles);

    main();
  </script>
</body>
</html>)HTML";
    });


}

static std::string sha256_hex_file_local(const std::filesystem::path& path, std::string* err) {
    if (err) err->clear();

    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "open file failed";
        return {};
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return {};
    }

    struct Guard {
        EVP_MD_CTX* p;
        ~Guard() { if (p) EVP_MD_CTX_free(p); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return {};
    }

    std::array<char, 1024 * 1024> buf{};

    while (f.good()) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();

        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) != 1) {
                if (err) *err = "EVP_DigestUpdate failed";
                return {};
            }
        }
    }

    if (!f.eof()) {
        if (err) *err = "read file failed";
        return {};
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return {};
    }

    return hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
}
} // namespace pqnas
