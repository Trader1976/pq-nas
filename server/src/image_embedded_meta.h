#pragma once

#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace pqnas {

    using json = nlohmann::json;

    // Reads embedded metadata from an image file using exiftool.
    // On success:
    //   - out_summary gets a compact/friendly subset
    //   - out_embedded gets grouped raw-ish metadata:
    //       { "exif": {...}, "iptc": {...}, "xmp": {...} }
    //
    // Returns false on failure.
    // Typical err values:
    //   - "tool_unavailable"
    //   - "bad_output"
    //   - "bad_json"
    //   - "tool_failed"
    bool read_embedded_image_metadata_exiftool(const std::filesystem::path& abs_path,
                                               json* out_summary,
                                               json* out_embedded,
                                               std::string* err);

} // namespace pqnas