#include "storage_resolver.h"

#include "file_location_index.h"
#include "user_quota.h"

#include <filesystem>

namespace pqnas {

namespace {
FileLocationIndex* g_file_location_index = nullptr;
}

void set_file_location_index(FileLocationIndex* idx) {
    g_file_location_index = idx;
}

FileLocationIndex* get_file_location_index() {
    return g_file_location_index;
}

bool normalize_user_rel_path_strict(const std::string& rel_path,
                                    std::string* out_rel_norm,
                                    std::string* err) {
    if (err) err->clear();
    if (!out_rel_norm) {
        if (err) *err = "null out_rel_norm";
        return false;
    }

    if (rel_path.empty()) {
        if (err) *err = "empty path";
        return false;
    }

    if (rel_path.find('\0') != std::string::npos) {
        if (err) *err = "invalid path";
        return false;
    }

    std::filesystem::path rel(rel_path);

    if (rel.is_absolute() || rel.has_root_path()) {
        if (err) *err = "absolute path not allowed";
        return false;
    }

    rel = rel.lexically_normal();

    if (rel.empty()) {
        if (err) *err = "invalid path";
        return false;
    }

    for (const auto& part : rel) {
        const auto s = part.string();
        if (s.empty() || s == "." || s == "..") {
            if (err) *err = "invalid path";
            return false;
        }
    }

    *out_rel_norm = rel.generic_string();
    return true;
}

bool resolve_legacy_user_path(UsersRegistry& users,
                              const std::string& fp_hex,
                              const std::string& rel_path,
                              std::filesystem::path* out_abs,
                              std::string* err) {
    if (err) err->clear();
    if (!out_abs) {
        if (err) *err = "null out_abs";
        return false;
    }

    const std::filesystem::path user_dir = pqnas_user_dir_for_fp(users, fp_hex);
    return resolve_user_path_strict(user_dir, rel_path, out_abs, err);
}

bool resolve_existing_user_file_path(UsersRegistry& users,
                                     const std::string& fp_hex,
                                     const std::string& rel_path,
                                     ResolvedExistingPath* out,
                                     std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    std::string rel_norm;
    if (!normalize_user_rel_path_strict(rel_path, &rel_norm, err)) {
        return false;
    }

    if (g_file_location_index) {
        std::string lookup_err;
        auto rec = g_file_location_index->get(fp_hex, rel_norm, &lookup_err);
        if (rec.has_value()) {
            out->normalized_rel_path = std::move(rel_norm);
            out->abs_path = std::filesystem::path(rec->physical_path);
            out->from_metadata = true;
            return true;
        }
        // For this transitional phase, ignore lookup errors and fall back to legacy path.
    }

    std::filesystem::path abs;
    if (!resolve_legacy_user_path(users, fp_hex, rel_norm, &abs, err)) {
        return false;
    }

    out->normalized_rel_path = std::move(rel_norm);
    out->abs_path = std::move(abs);
    out->from_metadata = false;
    return true;
}

} // namespace pqnas