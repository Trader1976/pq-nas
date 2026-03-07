#pragma once

#include "users_registry.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace pqnas {

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

struct UserStorageMigrationResult {
    bool ok = false;
    std::string error;
    std::string detail;

    UserStorageMigrationPlan plan;

    bool copied = false;
    bool verified = false;
    bool metadata_updated = false;
};

bool resolve_user_storage_migration(const UsersRegistry& users,
                                    const std::string& users_path,
                                    const std::string& fp_hex,
                                    const std::string& target_pool_id,
                                    UserStorageMigrationPlan* out,
                                    std::string* err);

bool ensure_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err);

bool run_user_storage_migration_copy(const UserStorageMigrationPlan& plan,
                                     std::string* err);

bool verify_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err);

bool switch_user_storage_migration_metadata(UsersRegistry& users,
                                           const std::string& users_path,
                                           const std::string& actor_fp,
                                           const UserStorageMigrationPlan& plan,
                                           std::string* err);

// Keep old sync helper temporarily as a compatibility wrapper.
// It can be removed later after async path is fully adopted.
bool migrate_user_storage_sync(UsersRegistry& users,
                               const std::string& users_path,
                               const std::string& actor_fp,
                               const std::string& fp_hex,
                               const std::string& target_pool_id,
                               UserStorageMigrationResult* out);

} // namespace pqnas