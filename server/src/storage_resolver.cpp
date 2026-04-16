#include "storage_resolver.h"
#include <iostream>

#include "file_location_index.h"
#include "user_quota.h"
#include "gallery_meta.h"

#include <filesystem>

namespace pqnas {

/*
Architecture notes
==================

Purpose
-------
storage_resolver.cpp is the namespace resolution layer between API request paths
and the current PQ-NAS storage model.

It answers questions like:
- is this user path syntactically valid?
- is this path reserved/internal and therefore forbidden?
- does this logical path currently exist as a file?
- does this logical path currently exist as a directory?
- if it exists, where is its current physical anchor, if any?

This file is one of the key transition points from a legacy "filesystem-is-truth"
model to the newer metadata-first logical namespace model.

Why this layer exists
---------------------
PQ-NAS now supports:
- logical paths decoupled from physical storage paths
- metadata-backed files
- implicit logical directories formed by descendant file rows
- landing/capacity tiering
- directory operations that may not map 1:1 to a single legacy directory path

That means callers must not directly assume:
- "if the path exists on disk, it exists logically"
- "if the path does not exist on disk, it does not exist logically"

This resolver centralizes those rules so request handlers do not each invent
their own partial interpretation of the namespace.

Resolver model
--------------
There are now two main resolution shapes:

1. resolve_existing_user_file_path()
   Older / compatibility-oriented helper.
   Best for:
   - exact file resolution
   - operations that expect a concrete physical anchor

   It preserves older behavior by refusing metadata-only logical dirs that do
   not have a concrete physical anchor.

2. resolve_existing_user_item()
   Newer / logical model helper.
   Best for:
   - handlers that need to reason about either files or dirs
   - metadata-backed logical directories
   - modern move/delete/stat/list behavior

Path normalization policy
-------------------------
normalize_user_rel_path_strict() is the canonical gate for user-visible paths.

It enforces:
- non-empty path
- no embedded NUL
- no absolute paths
- lexical normalization
- no "." or ".." path segments
- no reserved ".pqnas" segments anywhere

This function is intentionally strict because it is the first barrier protecting:
- filesystem traversal safety
- hidden internal namespaces
- stable logical path semantics for locks and metadata lookups

Reserved namespace
------------------
".pqnas" is a reserved internal namespace and must never be user-accessible.
This file enforces that centrally in normalization, so all higher-level callers
inherit the same rule automatically.

Metadata-first philosophy
-------------------------
For files:
- exact metadata row hit is authoritative

For directories:
- a logical directory exists if descendant file rows exist beneath it
- the directory may or may not also have a concrete physical anchor on disk

That distinction is why ResolvedLogicalItem includes:
- exists
- is_file
- is_dir
- from_metadata
- abs_path
- has_physical_anchor

Legacy fallback
---------------
This file still contains transitional legacy fallback behavior for physical
directories. That exists so older layouts continue to work while PQ-NAS moves
toward full metadata-first operation.

Important nuance:
- legacy fallback is allowed only for directories
- legacy file fallback is intentionally refused

That prevents raw physical files outside metadata from reappearing as logical
user files and undermining file_locations as the source of truth.

Global file location index pointer
----------------------------------
g_file_location_index is process-global and injected at startup.

This is simple and acceptable in the current single-process server model.
If architecture later moves toward stronger dependency injection or multiple
resolver contexts, this could become an explicit service reference instead.

Debug logging
-------------
The std::cerr resolver logs here are deliberately low-level and useful during
the current migration phase. They help distinguish:
- metadata file hit
- metadata dir hit
- legacy dir fallback
- legacy file fallback refusal

These logs may later be reduced or moved behind a debug flag.

Important semantic note
-----------------------
For metadata-backed logical dirs, a "physical anchor" is only best-effort.
Handlers that need a real subtree root should derive it from metadata subtree
rows first, and only use abs_path as a fallback when appropriate.

That rule already became important for:
- delete
- move
- stat
and is why resolve_existing_user_item() exposes has_physical_anchor separately.
*/

namespace {
FileLocationIndex* g_file_location_index = nullptr;
}

void set_file_location_index(FileLocationIndex* idx) {
    g_file_location_index = idx;
}

FileLocationIndex* get_file_location_index() {
    return g_file_location_index;
}

GalleryMetaIndex* g_gallery_meta_index = nullptr;

void set_gallery_meta_index(GalleryMetaIndex* idx) {
    g_gallery_meta_index = idx;
}

GalleryMetaIndex* get_gallery_meta_index() {
    return g_gallery_meta_index;
}

/*
normalize_user_rel_path_strict()
--------------------------------
Canonical validation + normalization for user-supplied relative paths.

This is the primary path hygiene barrier used by the Files API. It guarantees:
- relative-only paths
- no traversal segments
- no empty path parts
- reserved namespace rejection
- normalized generic-string output suitable for metadata keys and locks
*/
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

/*
resolve_legacy_user_path()
--------------------------
Resolve a normalized relative path against the legacy physical user root.

This is a helper for transitional fallback only. It should not be treated as
authoritative for file existence; metadata remains authoritative for files.
*/
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

/*
resolve_existing_user_file_path()
---------------------------------
Compatibility-oriented resolver that maps to the older "existing file path"
expectation used by some handlers.

Behavior:
- exact metadata-backed files resolve
- metadata-backed dirs resolve only if they have a physical anchor
- metadata-only dirs without anchor are reported as not found here

This preserves older assumptions while newer handlers migrate to
resolve_existing_user_item().
*/
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

/*
resolve_existing_user_item()
----------------------------
The main logical resolver for the modern Files API.

Resolution order:
1. normalize path
2. exact metadata file lookup
3. metadata logical-directory existence via descendant rows
4. transitional legacy physical-directory fallback
5. reject legacy file fallback

Outputs include both logical classification and best-effort physical anchor.

This split is important because:
- a logical dir may exist even if there is no direct physical directory anchor
- callers must be able to distinguish "logical dir exists" from
  "logical dir has concrete on-disk anchor"
*/
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

/*
any_file_ancestor_exists()
--------------------------
Check whether any parent segment of rel_path already exists as an exact logical
file row.

Example:
- file "a" exists
- query "a/b.txt"
=> returns true with found_ancestor = "a"

Used by PUT / MOVE path-conflict enforcement to prevent file/dir namespace
collisions in the logical tree.

Note:
- this consults metadata only
- that is intentional, because files are metadata-authoritative
*/
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