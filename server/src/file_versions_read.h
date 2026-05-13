#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace pqnas {

class FileVersionsIndex;

struct ReadVersionTextResult {
    bool ok = false;
    std::string error;
    std::string message;
    std::string detail;

    std::string version_id;
    std::string path;
    std::string created_at;
    std::uint64_t bytes = 0;
    std::string sha256_hex;
    std::string encoding = "utf-8";
    bool had_utf8_bom = false;
    std::string text;
};

ReadVersionTextResult read_version_blob_as_text(
    FileVersionsIndex* vix,
    const std::string& scope_type,
    const std::string& scope_id,
    const std::string& logical_rel_path,
    const std::string& version_id,
    const std::filesystem::path& scope_root,
    std::uint64_t max_bytes
);

} // namespace pqnas
