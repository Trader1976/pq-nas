#pragma once

#include "users_registry.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace pqnas {

// user_storage_migration.h
//
// Public migration-planning and migration-step interfaces for per-user storage
// relocation between the implicit default pool and explicit managed pools.
//
// Architectural intent
// - This header exposes the business-logic layer for user storage migration.
// - It is intentionally independent from HTTP routing, async job queues,
//   lockfiles, durable worker records, and audit orchestration.
// - The async worker in main.cpp should call these functions phase-by-phase.
// - The legacy synchronous path may still compose them through the compatibility
//   wrapper migrate_user_storage_sync().
//
// Migration model
// - A migration preserves the user's logical relative subtree (root_rel) and
//   changes only the active data root / pool mapping.
// - The default pool is represented logically as "default" while planning, but
//   is persisted in users.json as storage_pool_id == "".
// - Migration is intentionally non-destructive in v1:
//     * no source deletion
//     * no destination cleanup on failure
//     * no rsync --delete
//
// Safety model
// - Metadata is switched only after copy + verification succeed.
// - switch_user_storage_migration_metadata() performs a compare-before-commit
//   guard so a stale worker cannot silently overwrite a newer storage decision.
//
// Typical async worker phase order
//   resolve_user_storage_migration()
//   ensure_user_storage_migration_destination()
//   run_user_storage_migration_copy()
//   verify_user_storage_migration_destination()
//   switch_user_storage_migration_metadata()

// Fully resolved migration plan.
//
// This structure captures both the logical migration intent and the concrete
// filesystem locations derived from current registry metadata and pools.json.
//
// Field semantics
// - fingerprint:
//     user being migrated
// - from_pool_id / to_pool_id:
//     logical pool ids used during planning; "default" means the implicit
//     default pool
// - root_rel:
//     stable logical subtree under the chosen data root, typically
//     "users/<fingerprint>"
// - src_data_root / dst_data_root:
//     concrete pool data roots
// - src_user_dir / dst_user_dir:
//     fully resolved per-user directories used by copy/verify phases
struct UserStorageMigrationPlan {
    std::string fingerprint;
    std::string from_pool_id;
    std::string to_pool_id;
    std::string root_rel;

    std::filesystem::path src_data_root;
    std::filesystem::path dst_data_root;
    std::filesystem::path src_user_dir;
    std::filesystem::path dst_user_dir;
};

// End-to-end migration result used by the legacy synchronous wrapper.
//
// The async worker usually persists equivalent information in its durable job
// record instead of returning this structure directly.
//
// Field semantics
// - ok:
//     final overall success/failure
// - error / detail:
//     stable error category plus human-readable detail
// - plan:
//     resolved plan used for the attempt
// - copied / verified / metadata_updated:
//     coarse milestone flags indicating how far the migration progressed
struct UserStorageMigrationResult {
    bool ok = false;
    std::string error;
    std::string detail;

    UserStorageMigrationPlan plan;

    bool copied = false;
    bool verified = false;
    bool metadata_updated = false;
};

struct UserStorageCleanupPlan {
    std::string fingerprint;
    std::string active_pool_id;
    std::string old_pool_id;
    std::string root_rel;

    std::filesystem::path active_data_root;
    std::filesystem::path old_data_root;
    std::filesystem::path active_user_dir;
    std::filesystem::path old_user_dir;
};

// Resolve a migration plan from current users.json metadata and a requested
// destination pool.
//
// Responsibilities
// - validate that the user exists
// - validate that storage is currently allocated
// - normalize source/destination pool ids
// - choose a safe/stable root_rel
// - resolve concrete source and destination data roots
// - derive concrete source and destination user directories
//
// Non-responsibilities
// - does not create directories
// - does not copy data
// - does not verify data
// - does not mutate metadata
//
// Returns false on validation/planning failure and sets err.
bool resolve_user_storage_migration(const UsersRegistry& users,
                                    const std::string& users_path,
                                    const std::string& fp_hex,
                                    const std::string& target_pool_id,
                                    UserStorageMigrationPlan* out,
                                    std::string* err);

// Ensure the destination directory hierarchy exists for a resolved plan.
//
// This is a distinct phase so async workers can fail before copy begins if
// the target pool/root is unavailable or not writable.
bool ensure_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err);

// Execute the data-copy phase for a resolved plan.
//
// Current implementation uses rsync via fork + execvp.
// This phase does not verify results and does not mutate users.json.
bool run_user_storage_migration_copy(const UserStorageMigrationPlan& plan,
                                     std::string* err);

// Verify destination completeness after copy and before metadata switch.
//
// v1 verification is intentionally coarse:
// - destination user dir must exist
// - regular-file byte totals between source and destination must match
//
// Returns false if the destination does not look complete enough for metadata
// cutover.
bool verify_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err);

// Commit the migration by updating users.json metadata.
//
// Safety invariant
// - this is the only mutating migration phase
// - the function performs a compare-before-commit guard: the current user
//   metadata must still point at the source pool resolved earlier in the plan
//
// On success, this updates:
// - storage_pool_id
// - root_rel
// - storage_set_by
// - storage_set_at
//
// The logical "default" pool is persisted back as storage_pool_id == "".
bool switch_user_storage_migration_metadata(UsersRegistry& users,
                                            const std::string& users_path,
                                            const std::string& actor_fp,
                                            const UserStorageMigrationPlan& plan,
                                            std::string* err);

bool resolve_user_storage_cleanup(const UsersRegistry& users,
                                  const std::string& users_path,
                                  const std::string& fp_hex,
                                  const std::string& expected_active_pool_id,
                                  const std::string& old_pool_id,
                                  UserStorageCleanupPlan* out,
                                  std::string* err);

bool validate_user_storage_cleanup(const UserStorageCleanupPlan& plan,
                                  std::string* err);

bool delete_user_storage_old_copy(const UserStorageCleanupPlan& plan,
                                  std::uint64_t* removed_entries,
                                  std::string* err);
// Legacy synchronous compatibility wrapper.
//
// Why it exists
// - preserves older call sites/tests while async migration is being adopted
// - provides a compact reference composition of the migration phases
//
// Preferred use
// - new async worker code should call the phase-friendly helpers directly so it
//   can emit progress, persist job state, and stop cleanly between phases.
//
// It can be removed later after the async path fully replaces the synchronous
// flow.
bool migrate_user_storage_sync(UsersRegistry& users,
                               const std::string& users_path,
                               const std::string& actor_fp,
                               const std::string& fp_hex,
                               const std::string& target_pool_id,
                               UserStorageMigrationResult* out);

} // namespace pqnas