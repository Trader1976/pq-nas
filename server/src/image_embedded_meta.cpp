#include "image_embedded_meta.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace pqnas {
namespace {

static std::string trim_ws_local(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static std::string upper_ascii_local(std::string s) {
    for (char& c : s) c = (char)std::toupper((unsigned char)c);
    return s;
}

static std::string snake_case_local(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);

    bool prev_us = false;
    for (char ch : s) {
        const unsigned char u = (unsigned char)ch;

        if (std::isalnum(u)) {
            if (std::isupper(u)) {
                if (!out.empty() && !prev_us) out.push_back('_');
                out.push_back((char)std::tolower(u));
                prev_us = false;
            } else {
                out.push_back((char)std::tolower(u));
                prev_us = false;
            }
        } else {
            if (!out.empty() && !prev_us) {
                out.push_back('_');
                prev_us = true;
            }
        }
    }

    while (!out.empty() && out.front() == '_') out.erase(out.begin());
    while (!out.empty() && out.back() == '_') out.pop_back();
    return out;
}

static std::string shell_quote_single_local(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

static bool run_command_capture_stdout_local(const std::string& cmd,
                                             std::string* out,
                                             int* exit_code,
                                             std::string* err) {
    if (out) out->clear();
    if (exit_code) *exit_code = -1;
    if (err) err->clear();

    FILE* fp = ::popen(cmd.c_str(), "r");
    if (!fp) {
        if (err) *err = "tool_unavailable";
        return false;
    }

    std::string buf;
    std::array<char, 8192> tmp{};

    while (true) {
        const std::size_t n = std::fread(tmp.data(), 1, tmp.size(), fp);
        if (n > 0) buf.append(tmp.data(), n);
        if (n < tmp.size()) break;
    }

    const int rc = ::pclose(fp);

    if (out) *out = std::move(buf);
    if (exit_code) *exit_code = rc;
    return true;
}

static bool classify_group_local(const std::string& group, std::string* bucket) {
    if (!bucket) return false;

    const std::string g = upper_ascii_local(group);

    if (g.rfind("XMP", 0) == 0) {
        *bucket = "xmp";
        return true;
    }

    if (g.rfind("IPTC", 0) == 0) {
        *bucket = "iptc";
        return true;
    }

    if (g == "EXIF" ||
        g == "GPS" ||
        g == "IFD0" ||
        g == "IFD1" ||
        g == "EXIFIFD" ||
        g == "INTEROPIFD" ||
        g == "MAKERNOTES" ||
        g.find("EXIF") != std::string::npos) {
        *bucket = "exif";
        return true;
    }

    return false;
}

static std::string tag_name_only_local(const std::string& key) {
    const auto pos = key.find(':');
    if (pos == std::string::npos) return key;
    return key.substr(pos + 1);
}

static std::string group_name_only_local(const std::string& key) {
    const auto pos = key.find(':');
    if (pos == std::string::npos) return "";
    return key.substr(0, pos);
}

static const json* find_first_tag_value_local(const json& obj,
                                              const std::vector<std::string>& candidate_tags_upper) {
    if (!obj.is_object()) return nullptr;

    for (auto it = obj.begin(); it != obj.end(); ++it) {
        const std::string tag_upper = upper_ascii_local(tag_name_only_local(it.key()));
        for (const auto& want : candidate_tags_upper) {
            if (tag_upper == want) return &it.value();
        }
    }
    return nullptr;
}

static void summary_set_if_found_local(json& summary,
                                       const std::string& out_key,
                                       const json& flat,
                                       const std::vector<std::string>& candidate_tags_upper) {
    const json* v = find_first_tag_value_local(flat, candidate_tags_upper);
    if (v) summary[out_key] = *v;
}

} // namespace

bool read_embedded_image_metadata_exiftool(const std::filesystem::path& abs_path,
                                           json* out_summary,
                                           json* out_embedded,
                                           std::string* err) {
    if (out_summary) *out_summary = json::object();
    if (out_embedded) {
        *out_embedded = json{
            {"exif", json::object()},
            {"iptc", json::object()},
            {"xmp", json::object()}
        };
    }
    if (err) err->clear();

    const std::string quoted = shell_quote_single_local(abs_path.string());

    // -j   => JSON
    // -n   => numeric/raw values where possible
    // -G1  => include family-1 group in the key, e.g. EXIF:Make, IPTC:Keywords, XMP-dc:Subject
    const std::string cmd =
        "exiftool -j -n -G1 "
        "-EXIF:all -IPTC:all -XMP:all "
        "-File:ImageWidth -File:ImageHeight -File:MIMEType "
        "-- " + quoted + " 2>/dev/null";

    std::string raw;
    int rc = -1;
    std::string run_err;
    if (!run_command_capture_stdout_local(cmd, &raw, &rc, &run_err)) {
        if (err) *err = run_err.empty() ? "tool_unavailable" : run_err;
        return false;
    }

    raw = trim_ws_local(raw);
    if (raw.empty()) {
        if (err) *err = "tool_failed_empty_output";
        return false;
    }

    json root = json::parse(raw, nullptr, false);
    if (root.is_discarded() || !root.is_array() || root.empty() || !root[0].is_object()) {
        if (raw.find("not found") != std::string::npos ||
            raw.find("command not found") != std::string::npos ||
            raw.find("exiftool:") != std::string::npos) {
            if (err) *err = "tool_unavailable";
            return false;
            }

        if (err) *err = "bad_json: " + trim_ws_local(raw);
        return false;
    }

    if (rc != 0) {
        if (raw.find("not found") != std::string::npos ||
            raw.find("command not found") != std::string::npos ||
            raw.find("exiftool:") != std::string::npos) {
            if (err) *err = "tool_unavailable";
            return false;
            }

        if (err) *err = "tool_failed: " + trim_ws_local(raw);
        return false;
    }

    const json& flat = root[0];

    json exif = json::object();
    json iptc = json::object();
    json xmp = json::object();

    for (auto it = flat.begin(); it != flat.end(); ++it) {
        const std::string group = group_name_only_local(it.key());
        const std::string tag = tag_name_only_local(it.key());
        const std::string out_key = snake_case_local(tag);

        std::string bucket;
        if (!classify_group_local(group, &bucket)) continue;
        if (out_key.empty()) continue;

        if (bucket == "exif") exif[out_key] = it.value();
        else if (bucket == "iptc") iptc[out_key] = it.value();
        else if (bucket == "xmp") xmp[out_key] = it.value();
    }

    json summary = json::object();
    summary_set_if_found_local(summary, "camera_make", flat, {"MAKE"});
    summary_set_if_found_local(summary, "camera_model", flat, {"MODEL"});
    summary_set_if_found_local(summary, "lens", flat, {"LENSMODEL", "LENSID", "LENSINFO"});
    summary_set_if_found_local(summary, "taken_at", flat, {"DATETIMEORIGINAL", "CREATEDATE", "DATECREATED"});
    summary_set_if_found_local(summary, "iso", flat, {"ISO", "ISOSPEED", "ISOSPEEDRATINGS"});
    summary_set_if_found_local(summary, "exposure_time", flat, {"EXPOSURETIME"});
    summary_set_if_found_local(summary, "f_number", flat, {"FNUMBER", "APERTUREVALUE"});
    summary_set_if_found_local(summary, "focal_length", flat, {"FOCALLENGTH"});
    summary_set_if_found_local(summary, "image_width", flat, {"IMAGEWIDTH", "EXIFIMAGEWIDTH", "PIXELXDIMENSION"});
    summary_set_if_found_local(summary, "image_height", flat, {"IMAGEHEIGHT", "EXIFIMAGEHEIGHT", "PIXELYDIMENSION"});
    summary_set_if_found_local(summary, "mime_type", flat, {"MIMETYPE"});
    summary_set_if_found_local(summary, "gps_latitude", flat, {"GPSLATITUDE"});
    summary_set_if_found_local(summary, "gps_longitude", flat, {"GPSLONGITUDE"});

    if (out_summary) *out_summary = std::move(summary);
    if (out_embedded) {
        *out_embedded = json{
            {"exif", std::move(exif)},
            {"iptc", std::move(iptc)},
            {"xmp", std::move(xmp)}
        };
    }

    return true;
}

} // namespace pqnas