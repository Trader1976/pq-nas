// user_storage_migration.cpp
//
// User storage migration business logic.
//
// Architectural role
// - This file contains the storage-migration domain logic used by both the
//   legacy synchronous path and the newer async worker/job path.
// - It is intentionally kept free of queueing, locking, durable job-record
//   management, HTTP concerns, and audit orchestration.
// - The worker in main.cpp owns lifecycle management (queued/running/done/failed),
//   lockfiles, status records, and audits.
// - This module owns the migration plan and the concrete migration steps:
//
//     1) resolve source/destination paths from current users.json metadata
//     2) ensure destination directory hierarchy exists
//     3) copy data from source to destination
//     4) verify destination after copy
//     5) switch users.json metadata last
//
// Safety model
// - Migration is intentionally non-destructive in v1:
//     * no source deletion
//     * no rsync --delete
//     * no destination cleanup on failure
// - Metadata is switched only after copy + verification succeed.
// - The metadata switch includes a compare-before-commit guard:
//     * the user's current storage_pool_id must still match the source pool
//       resolved earlier in the job
//     * this prevents stale workers from silently overwriting a newer admin
//       decision or another migration outcome
//
// Pool model
// - users.json stores the default pool as storage_pool_id == "".
// - This module normalizes that to the logical id "default" while planning.
// - Explicit managed pools are resolved through pools.json.
// - root_rel is preserved across migration; migration changes the active data
//   root, not the logical per-user relative path.
//
// Verification model
// - v1 verification is intentionally coarse and low-risk:
//     * destination user dir must exist after copy
//     * total byte count of source and destination trees must match
// - This is not a cryptographic verification pass; it is a practical first-pass
//   integrity gate suitable for async worker-driven migration.
//
// Execution model
// - rsync is executed via fork + execvp rather than std::system().
// - This avoids shell interpretation and keeps argument passing explicit.
//
// Compatibility note
// - migrate_user_storage_sync() remains as a compatibility wrapper around the
//   phase-friendly helper functions.
// - The async worker should call the phase-friendly helpers directly so it can
//   report progress phase-by-phase and persist durable job state between phases.

#include "user_storage_migration.h"
#include "pqnas_util.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <system_error>
#include <sys/wait.h>
#include <unistd.h>

using json = nlohmann::json;

namespace pqnas {
namespace {

// Returns true only for strictly local relative paths that are safe to append
// below a chosen data root.
//
// Security / correctness intent
// - reject absolute paths and rooted paths
// - reject "." and ".." path traversal
// - reject embedded NUL
//
// This keeps root_rel constrained to a logical subtree such as:
//   users/<fingerprint>
//
// If stored metadata is missing or unsafe, callers fall back to the canonical
// default_root_rel_for_fp() value.
static bool is_safe_rel_path_local(const std::string& rel) {
    if (rel.empty()) return false;
    if (rel.find('\0') != std::string::npos) return false;
    std::filesystem::path p(rel);
    if (p.is_absolute() || p.has_root_path()) return false;
    for (const auto& part : p) {
        const auto s = part.string();
        if (s.empty() || s == "." || s == "..") return false;
    }
    return true;
}

// Canonical logical per-user subtree when users.json does not already provide
// a valid root_rel.
//
// Important: migration preserves the logical subtree. The pool/root changes,
// but the relative path remains stable, which keeps path-based semantics such
// as share resolution predictable across migration.
static std::string default_root_rel_for_fp(const std::string& fp_hex) {
    return std::string("users/") + fp_hex;
}

// Derive the default data root from users.json location.
//
// Current installed layout assumption:
//   users_path = /srv/pqnas/config/users.json
//   default data root = /srv/pqnas/data
//
// This keeps the default-pool resolution independent from explicit pools.json
// entries, because the default pool is represented implicitly in metadata.
static std::filesystem::path default_data_root_from_users_path(const std::string& users_path) {
    const std::filesystem::path p(users_path);
    return p.parent_path().parent_path() / "data";
}

// Resolve an explicit managed pool_id to its mount path via pools.json.
//
// pools.json model used here:
// - top-level object with "pools" object
// - keys under "pools" are mount paths
// - each value has metadata including "pool_id"
//
// This is intentionally a read-only lookup helper. Higher-level policy such as
// "is this pool a valid migration destination?" lives in the caller.
static bool load_pool_mount_from_pools_json(const std::string& users_path,
                                            const std::string& pool_id,
                                            std::filesystem::path* out_mount,
                                            std::string* err) {
    if (err) err->clear();
    if (!out_mount) {
        if (err) *err = "null out_mount";
        return false;
    }

    const std::filesystem::path pools_path =
        std::filesystem::path(users_path).parent_path() / "pools.json";

    std::ifstream f(pools_path);
    if (!f.good()) {
        if (err) *err = "failed to open pools.json: " + pools_path.string();
        return false;
    }

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        if (err) *err = std::string("failed to parse pools.json: ") + e.what();
        return false;
    }

    if (!j.is_object() || !j.contains("pools") || !j["pools"].is_object()) {
        if (err) *err = "invalid pools.json format";
        return false;
    }

    for (auto it = j["pools"].begin(); it != j["pools"].end(); ++it) {
        const std::string mount = it.key();
        const auto& meta = it.value();
        if (!meta.is_object()) continue;
        if (meta.value("pool_id", "") == pool_id) {
            *out_mount = std::filesystem::path(mount);
            return true;
        }
    }

    if (err) *err = "pool_id not found in pools.json: " + pool_id;
    return false;
}

// Resolve a logical pool id to the concrete data root used for user data.
//
// Logical ids accepted here:
// - "" or "default" -> implicit default data root
// - explicit pool id -> resolved via pools.json, then "<mount>/data"
//
// The returned root is the pool data root, not the final per-user directory.
// Callers append root_rel after planning.
static bool resolve_data_root_for_pool_id(const std::string& users_path,
                                          const std::string& pool_id,
                                          std::filesystem::path* out_root,
                                          std::string* err) {
    if (err) err->clear();
    if (!out_root) {
        if (err) *err = "null out_root";
        return false;
    }

    if (pool_id.empty() || pool_id == "default") {
        *out_root = default_data_root_from_users_path(users_path);
        return true;
    }

    std::filesystem::path mount;
    if (!load_pool_mount_from_pools_json(users_path, pool_id, &mount, err)) {
        return false;
    }

    *out_root = mount / "data";
    return true;
}

// Create a directory hierarchy if missing.
//
// The helper is intentionally strict:
// - create_directories() is attempted
// - filesystem error is returned to caller
//
// This is used for destination preparation before copy begins.
static bool ensure_dir_exists_strict(const std::filesystem::path& p, std::string* err) {
    if (err) err->clear();
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }
    return true;
}

// Safe best-effort regular-file size helper used by tree byte summation.
//
// Non-regular files and error cases contribute zero bytes.
// This is intentionally simple because v1 verification is coarse, not forensic.
static std::uint64_t file_size_safe(const std::filesystem::path& p) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) return 0;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return 0;
    return static_cast<std::uint64_t>(sz);
}

// Compute total bytes of regular files under a subtree.
//
// Verification note
// - this is a pragmatic integrity signal, not a full content hash walk
// - symlink semantics and metadata fidelity are delegated to rsync
// - this check is meant to catch obvious incomplete copies before metadata
//   switches to the new root
static std::uint64_t compute_tree_bytes(const std::filesystem::path& root) {
    std::uint64_t total = 0;
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return 0;

    for (std::filesystem::recursive_directory_iterator it(root, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        std::error_code ec2;
        if (it->is_regular_file(ec2) && !ec2) {
            total += file_size_safe(it->path());
        }
    }
    return total;
}

// Execute rsync copy from source user dir to destination user dir.
//
// Command intent
// - -aHAX preserves directory tree, hardlinks, ACLs, xattrs, etc. as available
// - --numeric-ids avoids uid/gid name-resolution surprises
// - no --delete by design in v1
//
// Security / robustness intent
// - uses fork + execvp rather than std::system()
// - no shell expansion/interpolation
// - source and destination are passed as explicit argv items
//
// Trailing slash semantics
// - "<dir>/" -> copy contents of directory into destination directory
//
// Failure model
// - child exec failure exits 127
// - non-zero rsync exit code becomes copy failure
static bool run_rsync_copy(const std::filesystem::path& src,
                           const std::filesystem::path& dst,
                           std::string* err) {
    if (err) err->clear();

    const std::string src_s = src.string() + "/";
    const std::string dst_s = dst.string() + "/";

    pid_t pid = fork();
    if (pid < 0) {
        if (err) *err = "fork failed";
        return false;
    }

    if (pid == 0) {
        const char* argv[] = {
            "rsync",
            "-aHAX",
            "--numeric-ids",
            "--",
            src_s.c_str(),
            dst_s.c_str(),
            nullptr
        };

        execvp("rsync", const_cast<char* const*>(argv));
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        if (err) *err = "waitpid failed";
        return false;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (err) *err = "rsync failed rc=" + std::to_string(WEXITSTATUS(status));
        return false;
    }

    return true;
}

} // namespace

// Build a migration plan from current registry metadata and the requested
// destination pool.
//
// Responsibilities
// - verify that the user exists
// - verify that storage is currently allocated
// - normalize source pool and target pool into logical ids
// - choose a safe/stable root_rel
// - resolve both concrete data roots
// - derive concrete source/destination user directories
//
// Non-responsibilities
// - does not create directories
// - does not copy data
// - does not verify copy
// - does not mutate users.json
//
// This split is important for the async worker model: planning can happen as
// its own phase and be reflected in durable job records before any mutation.
bool resolve_user_storage_migration(const UsersRegistry& users,
                                    const std::string& users_path,
                                    const std::string& fp_hex,
                                    const std::string& target_pool_id,
                                    UserStorageMigrationPlan* out,
                                    std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    auto uopt = users.get(fp_hex);
    if (!uopt.has_value()) {
        if (err) *err = "user_missing";
        return false;
    }
    const auto& u = *uopt;

    if (u.storage_state != "allocated") {
        if (err) *err = "storage_unallocated";
        return false;
    }

    UserStorageMigrationPlan p;
    p.fingerprint = fp_hex;
    p.from_pool_id = u.storage_pool_id.empty() ? "default" : u.storage_pool_id;
    p.to_pool_id = target_pool_id.empty() ? "default" : target_pool_id;
    p.root_rel = (!u.root_rel.empty() && is_safe_rel_path_local(u.root_rel))
        ? u.root_rel
        : default_root_rel_for_fp(fp_hex);

    if (!resolve_data_root_for_pool_id(users_path, p.from_pool_id, &p.src_data_root, err)) {
        return false;
    }
    if (!resolve_data_root_for_pool_id(users_path, p.to_pool_id, &p.dst_data_root, err)) {
        return false;
    }

    p.src_user_dir = p.src_data_root / p.root_rel;
    p.dst_user_dir = p.dst_data_root / p.root_rel;

    *out = p;
    return true;
}

// Ensure the destination hierarchy exists before copy.
//
// We create both:
// - parent subtree for root_rel
// - final per-user destination directory
//
// This phase is intentionally separate so async jobs can report progress
// accurately and fail before copy begins if the destination pool/root is not
// writable or cannot be prepared.
bool ensure_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err) {
    if (!ensure_dir_exists_strict(plan.dst_user_dir.parent_path(), err)) return false;
    if (!ensure_dir_exists_strict(plan.dst_user_dir, err)) return false;
    return true;
}

// Perform the actual data copy for a planned migration.
//
// This function does not mutate metadata and does not verify the result.
// Those are distinct phases so the async worker can persist progress and
// fail-stop between them.
bool run_user_storage_migration_copy(const UserStorageMigrationPlan& plan,
                                     std::string* err) {
    return run_rsync_copy(plan.src_user_dir, plan.dst_user_dir, err);
}

// Verify the copied destination before metadata switch.
//
// v1 checks
// - destination directory must exist after rsync
// - source and destination regular-file byte totals must match
//
// This keeps the phase lightweight while still enforcing the central safety
// invariant: users.json must not switch to the new root unless the destination
// looks complete enough for normal operation.
bool verify_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err) {
    if (err) err->clear();

    {
        std::error_code ec;
        auto st = std::filesystem::status(plan.dst_user_dir, ec);
        if (ec || !std::filesystem::exists(st) || !std::filesystem::is_directory(st)) {
            if (err) *err = "destination user dir missing after copy: " + plan.dst_user_dir.string();
            return false;
        }
    }

    const auto src_bytes = compute_tree_bytes(plan.src_user_dir);
    const auto dst_bytes = compute_tree_bytes(plan.dst_user_dir);
    if (src_bytes != dst_bytes) {
        if (err) {
            *err = "byte totals differ: src=" + std::to_string(src_bytes) +
                   " dst=" + std::to_string(dst_bytes);
        }
        return false;
    }

    return true;
}

// Atomically switch the user's active storage mapping in users.json.
//
// This is the only mutating step in the migration pipeline.
//
// Compare-before-commit guard
// - the worker may have planned the migration earlier
// - before committing, we re-read current metadata and require that the user's
//   current source pool still matches the source resolved in the plan
// - if an admin changed the pool selection in the meantime, this commit is
//   aborted rather than silently overriding newer intent
//
// Default pool representation
// - logical "default" is written back as storage_pool_id == ""
//
// On success, this function updates:
// - storage_pool_id
// - root_rel
// - storage_set_by
// - storage_set_at
//
// It does not delete old source data; cleanup remains outside v1 migration.
bool switch_user_storage_migration_metadata(UsersRegistry& users,
                                            const std::string& users_path,
                                            const std::string& actor_fp,
                                            const UserStorageMigrationPlan& plan,
                                            std::string* err) {
    if (err) err->clear();

    auto uopt = users.get(plan.fingerprint);
    if (!uopt.has_value()) {
        if (err) *err = "user_missing_after_copy";
        return false;
    }

    auto u = *uopt;
    const std::string current_pool_id = u.storage_pool_id.empty() ? "default" : u.storage_pool_id;

    // Compare-before-commit guard:
    // only switch if metadata still matches the source pool resolved when worker started.
    if (current_pool_id != plan.from_pool_id) {
        if (err) {
            *err = "source pool changed before metadata switch: expected=" +
                   plan.from_pool_id + " actual=" + current_pool_id;
        }
        return false;
    }

    u.storage_pool_id = (plan.to_pool_id == "default") ? "" : plan.to_pool_id;
    u.root_rel = plan.root_rel;
    u.storage_set_by = actor_fp;
    u.storage_set_at = pqnas::now_iso_utc();

    if (!users.upsert(u)) {
        if (err) *err = "users.upsert failed";
        return false;
    }
    if (!users.save(users_path)) {
        if (err) *err = "users.save failed";
        return false;
    }

    return true;
}

// Legacy synchronous wrapper around the phase-friendly migration helpers.
//
// Why this still exists
// - preserves compatibility with the original synchronous route/tests
// - provides a compact end-to-end implementation for reuse in small contexts
// - acts as a reference composition of the migration phases
//
// The async worker should prefer calling the individual phase helpers directly
// so it can emit durable progress records and audits at each boundary.
bool migrate_user_storage_sync(UsersRegistry& users,
                               const std::string& users_path,
                               const std::string& actor_fp,
                               const std::string& fp_hex,
                               const std::string& target_pool_id,
                               UserStorageMigrationResult* out) {
    UserStorageMigrationResult r;

    std::string err;
    if (!resolve_user_storage_migration(users, users_path, fp_hex, target_pool_id, &r.plan, &err)) {
        r.ok = false;
        r.error = "resolve_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    if (r.plan.from_pool_id == r.plan.to_pool_id) {
        r.ok = false;
        r.error = "same_pool";
        r.detail = "source and destination pool are the same";
        if (out) *out = r;
        return false;
    }

    if (!ensure_user_storage_migration_destination(r.plan, &err)) {
        r.ok = false;
        r.error = "mkdir_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    if (!run_user_storage_migration_copy(r.plan, &err)) {
        r.ok = false;
        r.error = "copy_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }
    r.copied = true;

    if (!verify_user_storage_migration_destination(r.plan, &err)) {
        r.ok = false;
        r.error = "verify_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }
    r.verified = true;

    if (!switch_user_storage_migration_metadata(users, users_path, actor_fp, r.plan, &err)) {
        r.ok = false;
        r.error = "metadata_switch_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    r.metadata_updated = true;
    r.ok = true;
    if (out) *out = r;
    return true;
}

} // namespace pqnas