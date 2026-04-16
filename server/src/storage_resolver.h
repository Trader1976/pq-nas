#pragma once

#include "users_registry.h"

#include <filesystem>
#include <string>

namespace pqnas {

class FileLocationIndex;
void set_file_location_index(FileLocationIndex* idx);
FileLocationIndex* get_file_location_index();

class GalleryMetaIndex;

void set_gallery_meta_index(GalleryMetaIndex* idx);
GalleryMetaIndex* get_gallery_meta_index();

struct ResolvedExistingPath {
    std::string normalized_rel_path;
    std::filesystem::path abs_path;
    bool from_metadata = false; // reserved for future tiering metadata lookup
};

struct ResolvedLogicalItem {
    std::string normalized_rel_path;
    std::filesystem::path abs_path;   // meaningful for files; best-effort anchor for dirs
    bool exists = false;
    bool is_file = false;
    bool is_dir = false;
    bool from_metadata = false;
    bool has_physical_anchor = false;
};

// Normalize a user relative path using the same strict policy as current file APIs.
// Output is a normalized relative path string such as "movies/video.mkv".
bool normalize_user_rel_path_strict(const std::string& rel_path,
                                    std::string* out_rel_norm,
                                    std::string* err);

// Legacy fallback resolver: resolve under the user's currently allocated root.
bool resolve_legacy_user_path(UsersRegistry& users,
                              const std::string& fp_hex,
                              const std::string& rel_path,
                              std::filesystem::path* out_abs,
                              std::string* err);

// Unified resolver for existing file/path lookups.
// Phase 1 implementation = normalize + legacy fallback.
// Later this becomes metadata-first, legacy-fallback-second.
bool resolve_existing_user_file_path(UsersRegistry& users,
                                     const std::string& fp_hex,
                                     const std::string& rel_path,
                                     ResolvedExistingPath* out,
                                     std::string* err);

bool resolve_existing_user_item(UsersRegistry& users,
                                const std::string& fp_hex,
                                const std::string& rel_path,
                                ResolvedLogicalItem* out,
                                std::string* err);

bool any_file_ancestor_exists(UsersRegistry& users,
                              const std::string& fp_hex,
                              const std::string& rel_path,
                              std::string* found_ancestor,
                              std::string* err);
} // namespace pqnas

// Bridge provided by main.cpp for now.
// This avoids moving current pool/root logic in the first patch.
std::filesystem::path pqnas_user_dir_for_fp(pqnas::UsersRegistry& users,
                                            const std::string& fp_hex);