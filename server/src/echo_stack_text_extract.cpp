#include "echo_stack_text_extract.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace pqnas {
namespace {

static std::string lower_ascii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static std::string trim_copy(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

static std::string collapse_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());

    bool ws = false;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!ws) out.push_back(' ');
            ws = true;
        } else {
            out.push_back(c);
            ws = false;
        }
    }

    return trim_copy(out);
}

static void replace_all(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;

    std::size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::string html_entity_decode_min(std::string s) {
    replace_all(s, "&nbsp;", " ");
    replace_all(s, "&#160;", " ");
    replace_all(s, "&amp;", "&");
    replace_all(s, "&quot;", "\"");
    replace_all(s, "&#34;", "\"");
    replace_all(s, "&#x22;", "\"");
    replace_all(s, "&#39;", "'");
    replace_all(s, "&#x27;", "'");
    replace_all(s, "&lt;", "<");
    replace_all(s, "&gt;", ">");
    return s;
}

static void remove_html_block(std::string& html, const std::string& tag_name) {
    const std::string open_pat = "<" + tag_name;
    const std::string close_pat = "</" + tag_name + ">";

    while (true) {
        std::string low = lower_ascii(html);
        const std::size_t a = low.find(open_pat);
        if (a == std::string::npos) break;

        const std::size_t b = low.find(close_pat, a);
        if (b == std::string::npos) {
            html.erase(a);
            break;
        }

        html.erase(a, b + close_pat.size() - a);
    }
}

static std::string find_title(const std::string& html) {
    const std::string low = lower_ascii(html);

    const std::size_t a = low.find("<title");
    if (a == std::string::npos) return "";

    const std::size_t gt = low.find('>', a);
    if (gt == std::string::npos) return "";

    const std::size_t b = low.find("</title>", gt + 1);
    if (b == std::string::npos || b <= gt) return "";

    return collapse_ws(html_entity_decode_min(html.substr(gt + 1, b - gt - 1)));
}

static std::string strip_html_to_text(std::string html, std::size_t max_text_bytes) {
    remove_html_block(html, "script");
    remove_html_block(html, "style");
    remove_html_block(html, "noscript");
    remove_html_block(html, "svg");
    remove_html_block(html, "canvas");

    std::string out;
    out.reserve(std::min<std::size_t>(html.size(), max_text_bytes + 4096));

    bool in_tag = false;
    for (char c : html) {
        if (c == '<') {
            in_tag = true;
            out.push_back(' ');
            continue;
        }

        if (c == '>') {
            in_tag = false;
            out.push_back(' ');
            continue;
        }

        if (!in_tag) {
            out.push_back(c);
            if (out.size() >= max_text_bytes * 2) break;
        }
    }

    out = collapse_ws(html_entity_decode_min(out));
    if (out.size() > max_text_bytes) {
        out.resize(max_text_bytes);
        out = trim_copy(out);
    }

    return out;
}

static bool read_file_limited(const std::filesystem::path& p,
                              std::size_t max_bytes,
                              std::string* out,
                              std::uint64_t* read_bytes) {
    if (out) out->clear();
    if (read_bytes) *read_bytes = 0;

    std::ifstream f(p, std::ios::binary);
    if (!f) return false;

    std::ostringstream ss;
    constexpr std::size_t kBufSize = 64 * 1024;
    std::vector<char> buf(kBufSize);

    std::size_t total = 0;
    while (f && total < max_bytes) {
        const std::size_t want = std::min<std::size_t>(buf.size(), max_bytes - total);
        f.read(buf.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = f.gcount();
        if (got <= 0) break;

        ss.write(buf.data(), got);
        total += static_cast<std::size_t>(got);
    }

    if (out) *out = ss.str();
    if (read_bytes) *read_bytes = static_cast<std::uint64_t>(total);
    return true;
}

static bool ext_is_text_like(const std::filesystem::path& p) {
    const std::string e = lower_ascii(p.extension().string());
    return e == ".html" || e == ".htm" || e == ".txt" || e == ".md";
}

static bool ext_is_html_like(const std::filesystem::path& p) {
    const std::string e = lower_ascii(p.extension().string());
    return e == ".html" || e == ".htm";
}

static std::filesystem::path choose_archive_text_file(const std::filesystem::path& archive_path) {
    std::error_code ec;

    if (std::filesystem::is_regular_file(archive_path, ec) && ext_is_text_like(archive_path)) {
        return archive_path;
    }

    if (!std::filesystem::is_directory(archive_path, ec)) {
        return {};
    }

    const std::vector<std::string> preferred = {
        "index.html",
        "index.htm",
        "page.html",
        "page.htm",
        "archive.html",
        "original.html"
    };

    for (const std::string& name : preferred) {
        const auto p = archive_path / name;
        if (std::filesystem::is_regular_file(p, ec)) return p;
    }

    std::filesystem::path first_text;
    std::size_t seen = 0;

    for (std::filesystem::recursive_directory_iterator it(
             archive_path,
             std::filesystem::directory_options::skip_permission_denied,
             ec
         );
         !ec && it != std::filesystem::recursive_directory_iterator();
         it.increment(ec)) {
        if (seen++ > 512) break;
        if (!it->is_regular_file(ec)) continue;

        const auto p = it->path();

        if (ext_is_html_like(p)) return p;
        if (first_text.empty() && ext_is_text_like(p)) first_text = p;
    }

    return first_text;
}

} // namespace

EchoStackTextExtractResult extract_echo_stack_archive_text(
    const std::filesystem::path& archive_path,
    std::size_t max_text_bytes
) {
    EchoStackTextExtractResult out;

    const auto file = choose_archive_text_file(archive_path);
    if (file.empty()) {
        out.error = "no_text_file_found";
        return out;
    }

    std::string raw;
    std::uint64_t bytes = 0;

    const std::size_t max_source_bytes =
        std::max<std::size_t>(max_text_bytes * 3, 2 * 1024 * 1024);

    if (!read_file_limited(file, max_source_bytes, &raw, &bytes)) {
        out.error = "read_failed";
        return out;
    }

    out.source_file = file.filename().string();
    out.source_bytes = bytes;

    if (ext_is_html_like(file)) {
        out.title = find_title(raw);
        out.text = strip_html_to_text(std::move(raw), max_text_bytes);
    } else {
        out.text = collapse_ws(html_entity_decode_min(raw));
        if (out.text.size() > max_text_bytes) {
            out.text.resize(max_text_bytes);
            out.text = trim_copy(out.text);
        }
    }

    if (out.text.empty()) {
        out.error = "empty_text";
        return out;
    }

    out.ok = true;
    return out;
}

} // namespace pqnas
