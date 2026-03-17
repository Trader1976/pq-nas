#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "users_registry.h"
#include <nlohmann/json.hpp>

namespace pqnas {

    struct FavoriteItem {
        std::string path;      // normalized relative path
        std::string type;      // "file" or "dir"
        std::string added_at;  // ISO UTC
    };

    std::filesystem::path favorites_meta_dir_for_user(const std::filesystem::path& user_dir);
    std::filesystem::path favorites_json_path_for_user(const std::filesystem::path& user_dir);

    bool favorites_load(const std::filesystem::path& user_dir,
                        nlohmann::json* out,
                        std::string* err);

    bool favorites_save_atomic(const std::filesystem::path& user_dir,
                               const nlohmann::json& doc,
                               std::string* err);

    bool favorites_list_items(const std::filesystem::path& user_dir,
                              std::vector<FavoriteItem>* out_items,
                              std::string* err);

    bool favorites_add(const std::filesystem::path& user_dir,
                       const std::string& rel_path_norm,
                       const std::string& type,
                       std::string* err);

    bool favorites_remove(const std::filesystem::path& user_dir,
                          const std::string& rel_path_norm,
                          const std::string& type,
                          std::string* err);

    bool favorites_move_path(const std::filesystem::path& user_dir,
                             const std::string& from_rel_norm,
                             const std::string& to_rel_norm,
                             const std::string& type,
                             std::string* err);

    bool favorites_remove_under_prefix(const std::filesystem::path& user_dir,
                                       const std::string& rel_path_norm,
                                       const std::string& type,
                                       std::string* err);

} // namespace pqnas