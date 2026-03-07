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

    bool resolve_user_storage_plan(const UsersRegistry& users,
                                   const std::string& users_path,
                                   const std::string& fp_hex,
                                   const std::string& target_pool_id,
                                   UserStorageMigrationPlan* out,
                                   std::string* err);

    bool migrate_user_storage_sync(UsersRegistry& users,
                                   const std::string& users_path,
                                   const std::string& actor_fp,
                                   const std::string& fp_hex,
                                   const std::string& target_pool_id,
                                   UserStorageMigrationResult* out);

} // namespace pqnas