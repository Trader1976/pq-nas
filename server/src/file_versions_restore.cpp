#include "file_versions_restore.h"

#include "file_versions.h"
#include "users_registry.h"

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <random>
#include <system_error>

namespace pqnas {
namespace {

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

static bool sha256_file_local(const std::filesystem::path& p, std::string* out_hex, std::string* err) {
    if (out_hex) out_hex->clear();
    if (err) err->clear();

    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return false;
    }

    struct Guard {
        EVP_MD_CTX* p;
        ~Guard() { if (p) EVP_MD_CTX_free(p); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return false;
    }

    std::array<char, 64 * 1024> buf{};
    while (f.good()) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) != 1) {
                if (err) *err = "EVP_DigestUpdate failed";
                return false;
            }
        }
    }

    if (!f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return false;
    }

    if (out_hex) *out_hex = hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
    return true;
}

static std::uint64_t file_mtime_epoch_safe_local(const std::filesystem::path& p) {
    std::error_code ec;
    const auto ftime = std::filesystem::last_write_time(p, ec);
    if (ec) return 0;

    using namespace std::chrono;
    const auto sctp = time_point_cast<system_clock::duration>(
        ftime - std::filesystem::file_time_type::clock::now() + system_clock::now()
    );
    const auto sec = duration_cast<seconds>(sctp.time_since_epoch()).count();
    return sec > 0 ? static_cast<std::uint64_t>(sec) : 0;
}

static std::string now_iso_utc_local() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto tt = system_clock::to_time_t(now);

    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif

    char buf[32] = {0};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

static std::uint64_t now_epoch_sec_local() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count()
    );
}

static std::string random_hex_local(std::size_t n_bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    std::string out;
    out.resize(n_bytes * 2);
    for (std::size_t i = 0; i < n_bytes; ++i) {
        const unsigned int b = dist(gen);
        out[i * 2 + 0] = kHex[(b >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[b & 0x0F];
    }
    return out;
}

static bool copy_file_atomic_local(const std::filesystem::path& src_abs,
                                   const std::filesystem::path& dst_abs,
                                   std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    std::filesystem::create_directories(dst_abs.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    const std::filesystem::path tmp =
        dst_abs.parent_path() /
        (dst_abs.filename().string() + ".tmp." + random_hex_local(8));

    {
        std::ifstream in(src_abs, std::ios::binary);
        if (!in.good()) {
            if (err) *err = "open src failed";
            return false;
        }

        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.good()) {
            if (err) *err = "open tmp failed";
            return false;
        }

        std::array<char, 64 * 1024> buf{};
        while (in.good()) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize n = in.gcount();
            if (n > 0) {
                out.write(buf.data(), n);
                if (!out.good()) {
                    out.close();
                    std::filesystem::remove(tmp, ec);
                    if (err) *err = "write tmp failed";
                    return false;
                }
            }
        }

        if (!in.eof()) {
            out.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "read src failed";
            return false;
        }

        out.flush();
        if (!out.good()) {
            out.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "flush tmp failed";
            return false;
        }
    }

    std::filesystem::rename(tmp, dst_abs, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        if (err) *err = "rename failed: " + ec.message();
        return false;
    }

    return true;
}

static std::string version_blob_rel_path_local(const std::string& version_id) {
    const std::string shard = version_id.size() >= 2 ? version_id.substr(0, 2) : "00";
    return ".pqnas/versions/blobs/" + shard + "/" + version_id + ".bin";
}

static std::filesystem::path infer_scope_root_from_live_path_local(
        const std::filesystem::path& live_abs_path,
        const std::string& logical_rel_path) {

    std::filesystem::path root = live_abs_path;
    for (const auto& part : std::filesystem::path(logical_rel_path)) {
        if (!part.empty()) {
            root = root.parent_path();
        }
    }
    return root;
}
} // namespace

std::string version_actor_display(const std::string& actor_name_snapshot,
                                  const std::string& actor_fp) {
    if (!actor_name_snapshot.empty()) return actor_name_snapshot;
    if (actor_fp.size() <= 16) return actor_fp;
    return actor_fp.substr(0, 12) + "...";
}

bool preserve_current_file_version(const PreserveCurrentVersionParams& p,
                                   std::string* out_version_id,
                                   std::string* err) {
    if (out_version_id) out_version_id->clear();
    if (err) err->clear();

    if (!p.file_versions) {
        if (err) *err = "file_versions is null";
        return false;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(p.live_abs_path, ec);
    if (ec || !std::filesystem::exists(st) || std::filesystem::is_symlink(st) || !std::filesystem::is_regular_file(st)) {
        if (err) *err = "live file not found";
        return false;
    }

    std::string sha256_hex;
    if (!sha256_file_local(p.live_abs_path, &sha256_hex, err)) return false;

    const std::uint64_t bytes = static_cast<std::uint64_t>(std::filesystem::file_size(p.live_abs_path, ec));
    if (ec) {
        if (err) *err = "file_size failed: " + ec.message();
        return false;
    }

    const std::uint64_t now_epoch = now_epoch_sec_local();
    const std::string now_iso = now_iso_utc_local();

    std::string actor_name_snapshot;
    if (p.users) {
        auto u = p.users->get(p.actor_fp);
        if (u.has_value()) actor_name_snapshot = u->name;
    }

    std::string version_id =
    std::to_string(static_cast<unsigned long long>(now_epoch * 1000ull)) + "_" + random_hex_local(8);

    const std::string blob_rel_path = version_blob_rel_path_local(version_id);
    const std::filesystem::path blob_abs =
        FileVersionsIndex::version_blob_abs_path(p.scope_root, blob_rel_path);

    if (!copy_file_atomic_local(p.live_abs_path, blob_abs, err)) {
        return false;
    }

    FileVersionRec rec;
    rec.version_id = version_id;
    rec.scope_type = p.scope_type;
    rec.scope_id = p.scope_id;
    rec.logical_rel_path = p.logical_rel_path;
    rec.event_kind = p.event_kind;
    rec.created_at = now_iso;
    rec.created_epoch = static_cast<std::int64_t>(now_epoch);
    rec.actor_fp = p.actor_fp;
    rec.actor_name_snapshot = actor_name_snapshot;
    rec.bytes = bytes;
    rec.sha256_hex = sha256_hex;
    rec.source_physical_path = p.live_abs_path.string();
    rec.blob_rel_path = blob_rel_path;
    rec.is_deleted_event = (p.event_kind == "delete_preserve");

    if (!p.file_versions->insert(rec, err)) {
        std::error_code rm_ec;
        std::filesystem::remove(blob_abs, rm_ec);
        return false;
    }

    if (out_version_id) *out_version_id = version_id;
    return true;
}

RestoreVersionResult restore_version_blob_to_path(FileVersionsIndex* vix,
                                                  const std::string& scope_type,
                                                  const std::string& scope_id,
                                                  const std::string& logical_rel_path,
                                                  const std::string& version_id,
                                                  const std::filesystem::path& live_abs_path) {
    RestoreVersionResult rr;

    if (!vix) {
        rr.error = "server_error";
        rr.message = "file versions index unavailable";
        return rr;
    }

    std::string verr;
    auto row = vix->get_by_version_id(version_id, &verr);
    if (!row.has_value()) {
        rr.error = verr.empty() ? "not_found" : "server_error";
        rr.message = verr.empty() ? "version not found" : "failed to load version";
        rr.detail = verr;
        return rr;
    }

    if (row->scope_type != scope_type ||
        row->scope_id != scope_id ||
        row->logical_rel_path != logical_rel_path) {
        rr.error = "not_found";
        rr.message = "version not found";
        return rr;
    }

    const std::filesystem::path scope_root =
        infer_scope_root_from_live_path_local(live_abs_path, logical_rel_path);

    const std::filesystem::path blob_abs =
        FileVersionsIndex::version_blob_abs_path(scope_root, row->blob_rel_path);

    std::error_code ec;
    auto st = std::filesystem::symlink_status(blob_abs, ec);
    if (ec || !std::filesystem::exists(st) || std::filesystem::is_symlink(st) || !std::filesystem::is_regular_file(st)) {
        rr.error = "not_found";
        rr.message = "version blob not found";
        return rr;
    }

    if (!copy_file_atomic_local(blob_abs, live_abs_path, &verr)) {
        rr.error = "server_error";
        rr.message = "failed to restore version";
        rr.detail = verr;
        return rr;
    }

    rr.bytes = row->bytes;
    rr.mtime_epoch = file_mtime_epoch_safe_local(live_abs_path);

    std::string sha;
    if (!sha256_file_local(live_abs_path, &sha, &verr)) {
        rr.error = "server_error";
        rr.message = "restore succeeded but hash failed";
        rr.detail = verr;
        return rr;
    }

    rr.sha256_hex = sha;
    rr.ok = true;
    return rr;
}

} // namespace pqnas