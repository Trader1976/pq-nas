#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace pqnas {

struct EchoStackTextExtractResult {
    bool ok = false;
    std::string title;
    std::string text;
    std::string source_file;
    std::string error;
    std::uint64_t source_bytes = 0;
};

EchoStackTextExtractResult extract_echo_stack_archive_text(
    const std::filesystem::path& archive_path,
    std::size_t max_text_bytes = 1024 * 1024
);

} // namespace pqnas
