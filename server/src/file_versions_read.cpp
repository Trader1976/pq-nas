#include "file_versions_read.h"

#include "file_versions.h"

#include <filesystem>
#include <fstream>
#include <system_error>

namespace pqnas {
namespace {

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

static bool read_file_bytes_all_local(const std::filesystem::path& p,
                                      std::string* out,
                                      std::string* err) {
    if (out) out->clear();
    if (err) err->clear();

    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());

    if (!f.good() && !f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    if (out) *out = std::move(data);
    return true;
}

static std::string strip_utf8_bom_local(const std::string& s, bool* had_bom) {
    const bool bom =
        s.size() >= 3 &&
        static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF;

    if (had_bom) *had_bom = bom;
    return bom ? s.substr(3) : s;
}

static bool is_valid_utf8_local(const std::string& s) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
    const std::size_t n = s.size();

    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];

        if (c <= 0x7F) {
            ++i;
            continue;
        }

        if ((c >> 5) == 0x6) {
            if (i + 1 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            const unsigned int cp = ((c & 0x1F) << 6) | (p[i + 1] & 0x3F);
            if (cp < 0x80) return false;
            i += 2;
            continue;
        }

        if ((c >> 4) == 0xE) {
            if (i + 2 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            if ((p[i + 2] & 0xC0) != 0x80) return false;

            const unsigned int cp =
                ((c & 0x0F) << 12) |
                ((p[i + 1] & 0x3F) << 6) |
                (p[i + 2] & 0x3F);

            if (cp < 0x800) return false;
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;

            i += 3;
            continue;
        }

        if ((c >> 3) == 0x1E) {
            if (i + 3 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            if ((p[i + 2] & 0xC0) != 0x80) return false;
            if ((p[i + 3] & 0xC0) != 0x80) return false;

            const unsigned int cp =
                ((c & 0x07) << 18) |
                ((p[i + 1] & 0x3F) << 12) |
                ((p[i + 2] & 0x3F) << 6) |
                (p[i + 3] & 0x3F);

            if (cp < 0x10000 || cp > 0x10FFFF) return false;

            i += 4;
            continue;
        }

        return false;
    }

    return true;
}

} // namespace

ReadVersionTextResult read_version_blob_as_text(
    FileVersionsIndex* vix,
    const std::string& scope_type,
    const std::string& scope_id,
    const std::string& logical_rel_path,
    const std::string& version_id,
    const std::filesystem::path& scope_root,
    std::uint64_t max_bytes
) {
    ReadVersionTextResult rr;

    if (!vix) {
        rr.error = "server_error";
        rr.message = "file versions index unavailable";
        return rr;
    }

    if (version_id.empty()) {
        rr.error = "bad_request";
        rr.message = "missing version_id";
        return rr;
    }

    std::string err;
    auto row = vix->get_by_version_id(version_id, &err);
    if (!row.has_value()) {
        rr.error = err.empty() ? "not_found" : "server_error";
        rr.message = err.empty() ? "version not found" : "failed to load version";
        rr.detail = err;
        return rr;
    }

    if (row->scope_type != scope_type ||
        row->scope_id != scope_id ||
        row->logical_rel_path != logical_rel_path) {
        rr.error = "not_found";
        rr.message = "version not found";
        return rr;
    }

    const auto scope_root_norm = scope_root.lexically_normal();
    const auto blob_root = (scope_root_norm / ".pqnas" / "versions" / "blobs").lexically_normal();
    const auto blob_abs =
        FileVersionsIndex::version_blob_abs_path(scope_root_norm, row->blob_rel_path).lexically_normal();

    if (!path_has_prefix_components_local(blob_root, blob_abs)) {
        rr.error = "server_error";
        rr.message = "version blob path escapes versions root";
        return rr;
    }

    std::error_code ec;
    const auto st = std::filesystem::symlink_status(blob_abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        rr.error = "not_found";
        rr.message = "version blob not found";
        rr.detail = ec ? ec.message() : "";
        return rr;
    }

    if (std::filesystem::is_symlink(st) || !std::filesystem::is_regular_file(st)) {
        rr.error = "unsupported";
        rr.message = "version blob is not a regular file";
        return rr;
    }

    const auto sz = std::filesystem::file_size(blob_abs, ec);
    if (ec) {
        rr.error = "server_error";
        rr.message = "failed to stat version blob";
        rr.detail = ec.message();
        return rr;
    }

    if (max_bytes > 0 && sz > max_bytes) {
        rr.error = "too_large";
        rr.message = "version is too large to compare as text";
        rr.bytes = static_cast<std::uint64_t>(sz);
        return rr;
    }

    std::string raw;
    if (!read_file_bytes_all_local(blob_abs, &raw, &err)) {
        rr.error = "server_error";
        rr.message = "failed to read version blob";
        rr.detail = err;
        return rr;
    }

    if (raw.find('\0') != std::string::npos) {
        rr.error = "unsupported";
        rr.message = "version appears to be binary";
        rr.bytes = static_cast<std::uint64_t>(raw.size());
        return rr;
    }

    bool had_bom = false;
    std::string text = strip_utf8_bom_local(raw, &had_bom);

    if (!is_valid_utf8_local(text)) {
        rr.error = "unsupported";
        rr.message = "version is not valid UTF-8 text";
        rr.bytes = static_cast<std::uint64_t>(raw.size());
        return rr;
    }

    rr.ok = true;
    rr.version_id = row->version_id;
    rr.path = row->logical_rel_path;
    rr.created_at = row->created_at;
    rr.bytes = static_cast<std::uint64_t>(raw.size());
    rr.sha256_hex = row->sha256_hex;
    rr.encoding = "utf-8";
    rr.had_utf8_bom = had_bom;
    rr.text = std::move(text);
    return rr;
}

} // namespace pqnas
