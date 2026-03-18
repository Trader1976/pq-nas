#include "storage_resolver.h"
#include <iostream>

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
        const std::string s = part.string();

        if (s.empty() || s == "." || s == "..") {
            if (err) *err = "invalid path";
            return false;
        }

        // Reserved system namespace must never be user-accessible.
        if (s == ".pqnas") {
            if (err) *err = "reserved path";
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

    ResolvedLogicalItem item;
    if (!resolve_existing_user_item(users, fp_hex, rel_path, &item, err)) {
        return false;
    }

    if (!item.exists) {
        if (err) *err = "not found";
        return false;
    }

    // Preserve old behavior as much as possible:
    // files always resolve; dirs resolve only if they have a physical anchor.
    if (item.is_dir && !item.has_physical_anchor) {
        if (err) *err = "not found";
        return false;
    }

    out->normalized_rel_path = item.normalized_rel_path;
    out->abs_path = item.abs_path;
    out->from_metadata = item.from_metadata;
    return true;
}
bool resolve_existing_user_item(UsersRegistry& users,
                                const std::string& fp_hex,
                                const std::string& rel_path,
                                ResolvedLogicalItem* out,
                                std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    *out = ResolvedLogicalItem{};

    std::string rel_norm;
    if (!normalize_user_rel_path_strict(rel_path, &rel_norm, err)) {
        return false;
    }

    out->normalized_rel_path = rel_norm;

    if (g_file_location_index) {
        std::string lookup_err;
        auto rec = g_file_location_index->get(fp_hex, rel_norm, &lookup_err);

        if (!lookup_err.empty()) {
            if (err) *err = "file location index lookup failed: " + lookup_err;
            return false;
        }

        if (rec.has_value()) {
            std::cerr << "[resolver] metadata file hit"
                      << " fp=" << fp_hex
                      << " rel=" << rel_norm
                      << " phys=" << rec->physical_path
                      << " pool=" << rec->current_pool
                      << " state=" << rec->tier_state
                      << "\n";

            if (rec->physical_path.empty()) {
                if (err) *err = "metadata record has empty physical_path";
                return false;
            }

            out->exists = true;
            out->is_file = true;
            out->is_dir = false;
            out->from_metadata = true;
            out->abs_path = std::filesystem::path(rec->physical_path);
            out->has_physical_anchor = true;
            return true;
        }

        std::string derr;
        const bool metadata_dir_exists = g_file_location_index->logical_dir_exists(fp_hex, rel_norm, &derr);
        if (!derr.empty()) {
            if (err) *err = "file location index subtree lookup failed: " + derr;
            return false;
        }

        if (metadata_dir_exists) {
            std::cerr << "[resolver] metadata dir hit"
                      << " fp=" << fp_hex
                      << " rel=" << rel_norm
                      << "\n";

            out->exists = true;
            out->is_file = false;
            out->is_dir = true;
            out->from_metadata = true;
            out->has_physical_anchor = false;

            // Best-effort physical anchor only.
            std::filesystem::path abs;
            std::string legacy_err;
            if (resolve_legacy_user_path(users, fp_hex, rel_norm, &abs, &legacy_err)) {
                std::error_code ec;
                auto st = std::filesystem::symlink_status(abs, ec);
                if (!ec && std::filesystem::exists(st) && std::filesystem::is_directory(st)) {
                    out->abs_path = std::move(abs);
                    out->has_physical_anchor = true;
                }
            }

            return true;
        }
    }

    // Transitional legacy fallback: physical directories only.
    std::filesystem::path abs;
    std::string legacy_err;
    if (!resolve_legacy_user_path(users, fp_hex, rel_norm, &abs, &legacy_err)) {
        if (err) *err = legacy_err;
        return false;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs, ec);
    if (ec || !std::filesystem::exists(st)) {
        if (err) *err = "not found";
        return false;
    }

    if (!std::filesystem::is_directory(st)) {
        std::cerr << "[resolver] legacy file fallback refused"
                  << " fp=" << fp_hex
                  << " rel=" << rel_norm
                  << " abs=" << abs.string()
                  << "\n";
        if (err) *err = "not found";
        return false;
    }

    std::cerr << "[resolver] legacy dir fallback"
              << " fp=" << fp_hex
              << " rel=" << rel_norm
              << " abs=" << abs.string()
              << "\n";

    out->exists = true;
    out->is_file = false;
    out->is_dir = true;
    out->from_metadata = false;
    out->abs_path = std::move(abs);
    out->has_physical_anchor = true;
    return true;
}
bool any_file_ancestor_exists(UsersRegistry& users,
                              const std::string& fp_hex,
                              const std::string& rel_path,
                              std::string* found_ancestor,
                              std::string* err) {
    (void)users; // currently unused, kept for signature consistency
    if (err) err->clear();
    if (found_ancestor) found_ancestor->clear();

    std::string rel_norm;
    if (!normalize_user_rel_path_strict(rel_path, &rel_norm, err)) {
        return false;
    }

    auto* idx = get_file_location_index();
    if (!idx) {
        if (err) *err = "metadata index missing";
        return false;
    }

    std::filesystem::path p(rel_norm);
    std::filesystem::path cur = p.parent_path();

    while (!cur.empty()) {
        const std::string anc = cur.generic_string();
        std::string e;
        const bool exists = idx->logical_file_exists_exact(fp_hex, anc, &e);
        if (!e.empty()) {
            if (err) *err = e;
            return false;
        }
        if (exists) {
            if (found_ancestor) *found_ancestor = anc;
            return true;
        }
        cur = cur.parent_path();
    }

    return false;
}
} // namespace pqnas