#pragma once

#include <filesystem>
#include <string>

namespace pqnas {

    std::string data_root_dir();
    std::filesystem::path data_root_path();
    std::filesystem::path pqnas_hidden_root_for_storage_root(const std::filesystem::path& storage_root);
    std::filesystem::path pqnas_trash_root_for_storage_root(const std::filesystem::path& storage_root);

} // namespace pqnas