#include "echo_stack_routes.h"
#include "user_quota.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <sys/socket.h>
#include <vector>
#include <fstream>

#include "echo_stack_routes.h"
using json = nlohmann::json;

namespace pqnas {
namespace {

static std::string lower_ascii_local(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool starts_with_local(const std::string& s, const std::string& pfx) {
    return s.rfind(pfx, 0) == 0;
}

static bool is_http_url_local(const std::string& url) {
    const std::string low = lower_ascii_local(url);
    return starts_with_local(low, "https://") || starts_with_local(low, "http://");
}

static std::string cap_string_local(std::string s, std::size_t max_bytes) {
    if (s.size() > max_bytes) s.resize(max_bytes);
    return s;
}

static std::string json_string_local(const json& j,
                                     const char* key,
                                     const std::string& defv,
                                     std::size_t cap_bytes) {
    if (!j.contains(key) || !j[key].is_string()) return defv;
    return cap_string_local(j[key].get<std::string>(), cap_bytes);
}

static bool json_bool_local(const json& j, const char* key, bool defv) {
    if (!j.contains(key)) return defv;
    if (j[key].is_boolean()) return j[key].get<bool>();
    if (j[key].is_number_integer()) return j[key].get<int>() != 0;
    return defv;
}

static std::size_t parse_limit_local(const httplib::Request& req,
                                     std::size_t defv,
                                     std::size_t maxv) {
    std::size_t v = defv;
    if (req.has_param("limit")) {
        try {
            long long n = std::stoll(req.get_param_value("limit"));
            if (n > 0) v = static_cast<std::size_t>(n);
        } catch (...) {}
    }
    if (v < 1) v = 1;
    if (v > maxv) v = maxv;
    return v;
}

static bool origin_allowed_local(const EchoStackRoutesDeps& deps,
                                 const httplib::Request& req) {
    if (!deps.origin || deps.origin->empty()) return true;
    const std::string origin = *deps.origin;

    if (req.has_header("Origin")) {
        return req.get_header_value("Origin") == origin;
    }

    if (req.has_header("Referer")) {
        const std::string ref = req.get_header_value("Referer");
        return ref == origin || starts_with_local(ref, origin + "/");
    }

    // Preserve compatibility with same-origin tools/curl. Browser requests
    // normally carry Origin/Referer on mutating calls.
    return true;
}

static json item_json_local(const EchoStackItemRec& r) {
    return json{
        {"id", r.id},
        {"url", r.url},
        {"final_url", r.final_url},
        {"title", r.title},
        {"description", r.description},
        {"site_name", r.site_name},
        {"favicon_url", r.favicon_url},
        {"preview_image_url", r.preview_image_url},
        {"tags_text", r.tags_text},
        {"collection", r.collection},
        {"notes", r.notes},
        {"read_state", r.read_state},
        {"favorite", r.favorite},
        {"archive_status", r.archive_status},
        {"archive_error", r.archive_error},
        {"archive_rel_dir", r.archive_rel_dir},
        {"archive_bytes", r.archive_bytes},
        {"created_epoch", r.created_epoch},
        {"updated_epoch", r.updated_epoch},
        {"archived_epoch", r.archived_epoch}
    };
}

static void audit_local(const EchoStackRoutesDeps& deps,
                        const std::string& event,
                        const std::string& outcome,
                        const std::map<std::string, std::string>& f) {
    if (deps.audit_emit) deps.audit_emit(event, outcome, f);
}

static bool require_actor_local(const EchoStackRoutesDeps& deps,
                                const httplib::Request& req,
                                httplib::Response& res,
                                std::string* fp,
                                std::string* role) {
    if (!deps.require_user_auth_users_actor ||
        !deps.users ||
        !deps.cookie_key ||
        !deps.echo_index ||
        !deps.reply_json) {
        if (deps.reply_json) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "Echo Stack route dependencies not configured"}
            }.dump());
        }
        return false;
    }

    return deps.require_user_auth_users_actor(
        req, res, deps.cookie_key, deps.users, fp, role
    );
}

static json parse_body_json_local(const httplib::Request& req) {
    try {
        return json::parse(req.body);
    } catch (...) {
        return json();
    }
}

    struct PreviewUrlParts {
    std::string scheme;
    std::string host;
    int port = 0;
    std::string target;
    std::string origin;
};

static bool ends_with_local(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool parse_preview_url_local(const std::string& url,
                                    PreviewUrlParts* out,
                                    std::string* err) {
    if (out) *out = PreviewUrlParts{};

    const std::string low = lower_ascii_local(url);
    std::size_t p = low.find("://");
    if (p == std::string::npos) {
        if (err) *err = "missing_scheme";
        return false;
    }

    const std::string scheme = low.substr(0, p);
    if (scheme != "http" && scheme != "https") {
        if (err) *err = "unsupported_scheme";
        return false;
    }

    std::string rest = url.substr(p + 3);
    std::size_t hash = rest.find('#');
    if (hash != std::string::npos) rest.resize(hash);

    std::size_t slash = rest.find_first_of("/?");
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    std::string target = slash == std::string::npos ? "/" : rest.substr(slash);
    if (!target.empty() && target[0] == '?') target = "/" + target;

    if (authority.empty()) {
        if (err) *err = "missing_host";
        return false;
    }

    // Reject userinfo. It complicates logging and is unnecessary for previews.
    if (authority.find('@') != std::string::npos) {
        if (err) *err = "userinfo_not_allowed";
        return false;
    }

    std::string host;
    int port = scheme == "https" ? 443 : 80;

    if (!authority.empty() && authority[0] == '[') {
        const std::size_t rb = authority.find(']');
        if (rb == std::string::npos) {
            if (err) *err = "bad_ipv6_host";
            return false;
        }
        host = authority.substr(1, rb - 1);
        if (rb + 1 < authority.size()) {
            if (authority[rb + 1] != ':') {
                if (err) *err = "bad_host_port";
                return false;
            }
            try {
                port = std::stoi(authority.substr(rb + 2));
            } catch (...) {
                if (err) *err = "bad_port";
                return false;
            }
        }
    } else {
        const std::size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            try {
                port = std::stoi(authority.substr(colon + 1));
            } catch (...) {
                if (err) *err = "bad_port";
                return false;
            }
        } else {
            host = authority;
        }
    }

    host = lower_ascii_local(host);
    if (host.empty() || port < 1 || port > 65535) {
        if (err) *err = "bad_host_or_port";
        return false;
    }

    if (out) {
        out->scheme = scheme;
        out->host = host;
        out->port = port;
        out->target = target.empty() ? "/" : target;
        out->origin =
            scheme + "://" + host +
            (((scheme == "https" && port == 443) || (scheme == "http" && port == 80))
                 ? std::string()
                 : ":" + std::to_string(port));
    }

    return true;
}

static bool ipv4_private_or_special_local(const in_addr& a) {
    const std::uint32_t ip = ntohl(a.s_addr);

    if ((ip >> 24) == 10) return true;                         // 10.0.0.0/8
    if ((ip >> 24) == 127) return true;                        // loopback
    if ((ip >> 16) == ((169u << 8) | 254u)) return true;       // link-local
    if ((ip >> 20) == ((172u << 4) | 1u)) return true;         // 172.16.0.0/12
    if ((ip >> 16) == ((192u << 8) | 168u)) return true;       // 192.168.0.0/16
    if ((ip >> 24) == 0) return true;                          // 0.0.0.0/8
    if ((ip >> 24) >= 224) return true;                        // multicast/reserved
    if ((ip >> 24) == 100 && ((ip >> 16) & 0xff) >= 64 &&
        ((ip >> 16) & 0xff) <= 127) return true;               // CGNAT
    return false;
}

static bool ipv6_private_or_special_local(const in6_addr& a) {
    const unsigned char* b = a.s6_addr;

    bool all_zero = true;
    for (int i = 0; i < 16; ++i) {
        if (b[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return true;

    bool loopback = true;
    for (int i = 0; i < 15; ++i) {
        if (b[i] != 0) {
            loopback = false;
            break;
        }
    }
    if (loopback && b[15] == 1) return true;

    if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7 unique local
    if (b[0] == 0xfe && ((b[1] & 0xc0) == 0x80)) return true; // fe80::/10 link-local
    if (b[0] == 0xff) return true; // multicast

    return false;
}

static bool preview_host_allowed_local(const std::string& host,
                                       std::string* err) {
    const std::string h = lower_ascii_local(host);

    if (h == "localhost" ||
        ends_with_local(h, ".localhost") ||
        ends_with_local(h, ".local") ||
        ends_with_local(h, ".lan") ||
        ends_with_local(h, ".internal") ||
        ends_with_local(h, ".home") ||
        ends_with_local(h, ".home.arpa")) {
        if (err) *err = "internal_hostname_blocked";
        return false;
    }

    // Block single-label hostnames. Public web pages should use DNS names with dots.
    if (h.find('.') == std::string::npos && h.find(':') == std::string::npos) {
        if (err) *err = "single_label_hostname_blocked";
        return false;
    }

    in_addr v4{};
    if (inet_pton(AF_INET, h.c_str(), &v4) == 1) {
        if (ipv4_private_or_special_local(v4)) {
            if (err) *err = "private_ip_blocked";
            return false;
        }
        return true;
    }

    in6_addr v6{};
    if (inet_pton(AF_INET6, h.c_str(), &v6) == 1) {
        if (ipv6_private_or_special_local(v6)) {
            if (err) *err = "private_ip_blocked";
            return false;
        }
        return true;
    }

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* result = nullptr;
    const int gai = getaddrinfo(h.c_str(), nullptr, &hints, &result);
    if (gai != 0 || !result) {
        if (err) *err = "dns_resolution_failed";
        return false;
    }

    bool saw_addr = false;
    for (addrinfo* it = result; it; it = it->ai_next) {
        if (!it->ai_addr) continue;
        saw_addr = true;

        if (it->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
            if (ipv4_private_or_special_local(sa->sin_addr)) {
                freeaddrinfo(result);
                if (err) *err = "private_dns_result_blocked";
                return false;
            }
        } else if (it->ai_family == AF_INET6) {
            auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
            if (ipv6_private_or_special_local(sa->sin6_addr)) {
                freeaddrinfo(result);
                if (err) *err = "private_dns_result_blocked";
                return false;
            }
        }
    }

    freeaddrinfo(result);

    if (!saw_addr) {
        if (err) *err = "dns_no_addresses";
        return false;
    }

    return true;
}

static std::string html_entity_decode_min_local(std::string s) {
    auto repl = [&](const std::string& a, const std::string& b) {
        std::size_t pos = 0;
        while ((pos = s.find(a, pos)) != std::string::npos) {
            s.replace(pos, a.size(), b);
            pos += b.size();
        }
    };

    repl("&amp;", "&");
    repl("&quot;", "\"");
    repl("&#34;", "\"");
    repl("&#x22;", "\"");
    repl("&#39;", "'");
    repl("&#x27;", "'");
    repl("&lt;", "<");
    repl("&gt;", ">");
    repl("&nbsp;", " ");
    return s;
}

static std::string trim_copy_local(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

static std::string collapse_ws_local(const std::string& s) {
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
    return trim_copy_local(out);
}

static std::string tag_attr_local(const std::string& tag,
                                  const std::string& attr_name) {
    const std::string low = lower_ascii_local(tag);
    const std::string name = lower_ascii_local(attr_name);

    std::size_t pos = 0;
    while ((pos = low.find(name, pos)) != std::string::npos) {
        const bool left_ok =
            pos == 0 ||
            std::isspace(static_cast<unsigned char>(low[pos - 1])) ||
            low[pos - 1] == '<';

        std::size_t p = pos + name.size();
        while (p < low.size() && std::isspace(static_cast<unsigned char>(low[p]))) ++p;

        if (!left_ok || p >= low.size() || low[p] != '=') {
            ++pos;
            continue;
        }

        ++p;
        while (p < tag.size() && std::isspace(static_cast<unsigned char>(tag[p]))) ++p;
        if (p >= tag.size()) return "";

        char quote = 0;
        if (tag[p] == '"' || tag[p] == '\'') {
            quote = tag[p++];
        }

        std::size_t start = p;
        std::size_t end = start;

        if (quote) {
            end = tag.find(quote, start);
            if (end == std::string::npos) return "";
        } else {
            while (end < tag.size() &&
                   !std::isspace(static_cast<unsigned char>(tag[end])) &&
                   tag[end] != '>') {
                ++end;
            }
        }

        return html_entity_decode_min_local(tag.substr(start, end - start));
    }

    return "";
}

static std::string find_title_local(const std::string& html) {
    const std::string low = lower_ascii_local(html);
    const std::size_t a = low.find("<title");
    if (a == std::string::npos) return "";

    const std::size_t gt = low.find('>', a);
    if (gt == std::string::npos) return "";

    const std::size_t b = low.find("</title>", gt + 1);
    if (b == std::string::npos || b <= gt) return "";

    return collapse_ws_local(html_entity_decode_min_local(html.substr(gt + 1, b - gt - 1)));
}

static std::string find_meta_content_local(const std::string& html,
                                           const std::string& key_attr,
                                           const std::string& key_value) {
    const std::string low = lower_ascii_local(html);
    const std::string wanted = lower_ascii_local(key_value);

    std::size_t pos = 0;
    while ((pos = low.find("<meta", pos)) != std::string::npos) {
        const std::size_t end = low.find('>', pos);
        if (end == std::string::npos) break;

        const std::string tag = html.substr(pos, end - pos + 1);
        const std::string v = lower_ascii_local(tag_attr_local(tag, key_attr));
        if (v == wanted) {
            return collapse_ws_local(tag_attr_local(tag, "content"));
        }

        pos = end + 1;
    }

    return "";
}

static std::string find_icon_href_local(const std::string& html) {
    const std::string low = lower_ascii_local(html);

    std::size_t pos = 0;
    while ((pos = low.find("<link", pos)) != std::string::npos) {
        const std::size_t end = low.find('>', pos);
        if (end == std::string::npos) break;

        const std::string tag = html.substr(pos, end - pos + 1);
        const std::string rel = lower_ascii_local(tag_attr_local(tag, "rel"));
        const std::string href = tag_attr_local(tag, "href");

        if (!href.empty() &&
            (rel.find("icon") != std::string::npos ||
             rel.find("shortcut icon") != std::string::npos ||
             rel.find("apple-touch-icon") != std::string::npos)) {
            return href;
        }

        pos = end + 1;
    }

    return "";
}

static std::string make_absolute_url_local(const PreviewUrlParts& base,
                                           const std::string& maybe_url) {
    const std::string u = trim_copy_local(maybe_url);
    if (u.empty()) return "";

    const std::string low = lower_ascii_local(u);
    if (starts_with_local(low, "https://") || starts_with_local(low, "http://")) {
        return u;
    }

    if (starts_with_local(u, "//")) {
        return base.scheme + ":" + u;
    }

    if (starts_with_local(u, "/")) {
        return base.origin + u;
    }

    std::string dir = base.target;
    const std::size_t q = dir.find('?');
    if (q != std::string::npos) dir.resize(q);

    const std::size_t slash = dir.rfind('/');
    if (slash == std::string::npos) dir = "/";
    else dir.resize(slash + 1);

    return base.origin + dir + u;
}

struct PreviewFetchResult {
    bool ok = false;
    int http_status = 0;
    std::string error;
    std::string final_url;
    std::string html;
};

static std::optional<std::string> redirect_location_local(const httplib::Result& r) {
    if (!r || !r->headers.size()) return std::nullopt;

    auto it = r->headers.find("Location");
    if (it != r->headers.end()) return it->second;

    it = r->headers.find("location");
    if (it != r->headers.end()) return it->second;

    return std::nullopt;
}

static PreviewFetchResult fetch_preview_html_local(const std::string& input_url) {
    static constexpr std::size_t kMaxPreviewBytes = 192 * 1024;
    static constexpr int kMaxRedirects = 4;

    PreviewFetchResult out;

    std::string cur_url = input_url;

    for (int hop = 0; hop <= kMaxRedirects; ++hop) {
        PreviewUrlParts p;
        std::string perr;
        if (!parse_preview_url_local(cur_url, &p, &perr)) {
            out.error = perr;
            return out;
        }

        std::string herr;
        if (!preview_host_allowed_local(p.host, &herr)) {
            out.error = herr;
            return out;
        }

        httplib::Headers headers{
            {"User-Agent", "DNA-Nexus-EchoStack/0.1"},
            {"Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
            {"Range", "bytes=0-196607"}
        };

        std::string body;
        body.reserve(64 * 1024);

        httplib::Result r;

        if (p.scheme == "https") {
            httplib::SSLClient cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(8, 0);
            cli.enable_server_certificate_verification(true);

            r = cli.Get(p.target.c_str(), headers, [&](const char* data, size_t len) {
                if (body.size() + len > kMaxPreviewBytes) {
                    body.append(data, kMaxPreviewBytes - body.size());
                    return false;
                }
                body.append(data, len);
                return true;
            });
        } else {
            httplib::Client cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(8, 0);

            r = cli.Get(p.target.c_str(), headers, [&](const char* data, size_t len) {
                if (body.size() + len > kMaxPreviewBytes) {
                    body.append(data, kMaxPreviewBytes - body.size());
                    return false;
                }
                body.append(data, len);
                return true;
            });
        }

        if (!r) {
            out.error = "fetch_failed";
            return out;
        }

        out.http_status = r->status;

        if (r->status >= 300 && r->status < 400) {
            auto loc = redirect_location_local(r);
            if (!loc.has_value() || loc->empty()) {
                out.error = "redirect_without_location";
                return out;
            }
            cur_url = make_absolute_url_local(p, *loc);
            continue;
        }

        if (r->status < 200 || r->status >= 300) {
            out.error = "http_" + std::to_string(r->status);
            return out;
        }

        out.ok = true;
        out.final_url = cur_url;
        out.html = std::move(body);
        return out;
    }

    out.error = "too_many_redirects";
    return out;
}
struct EchoAssetFetchResult {
    bool ok = false;
    int http_status = 0;
    std::string error;
    std::string final_url;
    std::string bytes;
    std::string mime;
};

static std::string detect_image_mime_local(const std::string& b) {
    if (b.size() >= 8 &&
        static_cast<unsigned char>(b[0]) == 0x89 &&
        b[1] == 'P' && b[2] == 'N' && b[3] == 'G') {
        return "image/png";
    }

    if (b.size() >= 3 &&
        static_cast<unsigned char>(b[0]) == 0xff &&
        static_cast<unsigned char>(b[1]) == 0xd8 &&
        static_cast<unsigned char>(b[2]) == 0xff) {
        return "image/jpeg";
    }

    if (b.size() >= 6 &&
        (b.rfind("GIF87a", 0) == 0 || b.rfind("GIF89a", 0) == 0)) {
        return "image/gif";
    }

    if (b.size() >= 12 &&
        b.rfind("RIFF", 0) == 0 &&
        b.substr(8, 4) == "WEBP") {
        return "image/webp";
    }

    if (b.size() >= 4 &&
        static_cast<unsigned char>(b[0]) == 0x00 &&
        static_cast<unsigned char>(b[1]) == 0x00 &&
        static_cast<unsigned char>(b[2]) == 0x01 &&
        static_cast<unsigned char>(b[3]) == 0x00) {
        return "image/x-icon";
    }

    return "";
}



static EchoAssetFetchResult fetch_small_image_asset_local(const std::string& input_url,
                                                          std::size_t max_bytes) {
    static constexpr int kMaxRedirects = 4;

    EchoAssetFetchResult out;
    std::string cur_url = input_url;

    if (max_bytes < 1) {
        out.error = "bad_asset_limit";
        return out;
    }

    for (int hop = 0; hop <= kMaxRedirects; ++hop) {
        PreviewUrlParts p;
        std::string perr;
        if (!parse_preview_url_local(cur_url, &p, &perr)) {
            out.error = perr;
            return out;
        }

        std::string herr;
        if (!preview_host_allowed_local(p.host, &herr)) {
            out.error = herr;
            return out;
        }

        httplib::Headers headers{
            {"User-Agent", "DNA-Nexus-EchoStack/0.1"},
            {"Accept", "image/avif,image/webp,image/apng,image/*,*/*;q=0.1"},
            {"Range", "bytes=0-" + std::to_string(max_bytes - 1)}
        };

        std::string body;
        body.reserve(std::min<std::size_t>(max_bytes, 256 * 1024));

        httplib::Result r;

        if (p.scheme == "https") {
            httplib::SSLClient cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(8, 0);
            cli.enable_server_certificate_verification(true);

            r = cli.Get(p.target.c_str(), headers, [&](const char* data, size_t len) {
                if (body.size() + len > max_bytes) {
                    body.append(data, max_bytes - body.size());
                    return false;
                }
                body.append(data, len);
                return true;
            });
        } else {
            httplib::Client cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(8, 0);

            r = cli.Get(p.target.c_str(), headers, [&](const char* data, size_t len) {
                if (body.size() + len > max_bytes) {
                    body.append(data, max_bytes - body.size());
                    return false;
                }
                body.append(data, len);
                return true;
            });
        }

        if (!r) {
            out.error = "asset_fetch_failed";
            return out;
        }

        out.http_status = r->status;

        if (r->status >= 300 && r->status < 400) {
            auto loc = redirect_location_local(r);
            if (!loc.has_value() || loc->empty()) {
                out.error = "asset_redirect_without_location";
                return out;
            }

            cur_url = make_absolute_url_local(p, *loc);
            continue;
        }

        if (r->status < 200 || r->status >= 300) {
            out.error = "asset_http_" + std::to_string(r->status);
            return out;
        }

        if (body.empty()) {
            out.error = "asset_empty";
            return out;
        }

        const std::string magic_mime = detect_image_mime_local(body);
        if (magic_mime.empty()) {
            out.error = "asset_not_supported_image";
            return out;
        }

        out.ok = true;
        out.final_url = cur_url;
        out.bytes = std::move(body);
        out.mime = magic_mime;
        return out;
    }

    out.error = "asset_too_many_redirects";
    return out;
}

static bool safe_echo_asset_kind_local(const std::string& kind) {
    return kind == "favicon" || kind == "preview";
}

static std::string echo_asset_rel_path_local(const std::string& item_id,
                                             const std::string& kind) {
    return ".pqnas_echostack/items/" + item_id + "/assets/" + kind + ".bin";
}

static std::string echo_asset_public_url_local(const std::string& item_id,
                                               const std::string& kind) {
    return "/api/v4/echostack/assets/get?id=" + item_id + "&kind=" + kind;
}

static bool write_bytes_atomic_local(const std::filesystem::path& final_abs,
                                     const std::string& bytes,
                                     const std::string& tmp_suffix,
                                     std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(final_abs.parent_path(), ec);
    if (ec) {
        if (err) *err = "mkdir_failed: " + ec.message();
        return false;
    }

    const std::filesystem::path tmp_abs =
        final_abs.parent_path() /
        (final_abs.filename().string() + ".tmp." + tmp_suffix);

    {
        std::ofstream o(tmp_abs, std::ios::binary | std::ios::trunc);
        if (!o) {
            if (err) *err = "open_tmp_failed";
            return false;
        }

        o.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!o.good()) {
            std::filesystem::remove(tmp_abs, ec);
            if (err) *err = "write_tmp_failed";
            return false;
        }
    }

    std::filesystem::remove(final_abs, ec);
    ec.clear();
    std::filesystem::rename(tmp_abs, final_abs, ec);
    if (ec) {
        std::filesystem::remove(tmp_abs, ec);
        if (err) *err = "rename_failed: " + ec.message();
        return false;
    }

    return true;
}

static bool post_write_quota_ok_local(const EchoStackRoutesDeps& deps,
                                      const std::string& fp,
                                      const std::filesystem::path& user_dir,
                                      std::string* err) {
    if (!deps.users) {
        if (err) *err = "users_missing";
        return false;
    }

    const auto uopt = deps.users->get(fp);
    if (!uopt.has_value()) {
        if (err) *err = "user_missing";
        return false;
    }

    const auto& u = *uopt;
    const std::uint64_t used = pqnas::compute_used_bytes_v1(user_dir);

    if (u.quota_bytes == 0) {
        if (used > 0) {
            if (err) *err = "quota_exceeded";
            return false;
        }
        return true;
    }

    if (used > u.quota_bytes) {
        if (err) *err = "quota_exceeded";
        return false;
    }

    return true;
}

static bool cache_echo_asset_local(const EchoStackRoutesDeps& deps,
                                   const std::string& fp,
                                   const std::filesystem::path& user_dir,
                                   const std::string& item_id,
                                   const std::string& kind,
                                   const std::string& source_url,
                                   std::size_t max_bytes,
                                   std::string* out_public_url,
                                   std::string* err) {
    if (out_public_url) *out_public_url = "";

    if (!safe_echo_asset_kind_local(kind)) {
        if (err) *err = "bad_asset_kind";
        return false;
    }

    if (source_url.empty()) {
        if (err) *err = "empty_asset_url";
        return false;
    }

    if (!is_http_url_local(source_url)) {
        if (err) *err = "bad_asset_url";
        return false;
    }

    const std::string rel = echo_asset_rel_path_local(item_id, kind);

    // Preflight with the maximum possible asset size. This keeps us from writing
    // a cache file that could exceed quota. The file is under user_dir, so the
    // existing recursive quota scanner naturally counts it.
    pqnas::QuotaCheckResult qc = pqnas::quota_check_for_upload_v1(
        *deps.users,
        fp,
        user_dir,
        rel,
        static_cast<std::uint64_t>(max_bytes)
    );

    if (!qc.ok) {
        if (err) *err = qc.error.empty() ? "quota_check_failed" : qc.error;
        return false;
    }

    EchoAssetFetchResult fetched = fetch_small_image_asset_local(source_url, max_bytes);
    if (!fetched.ok) {
        if (err) *err = fetched.error.empty() ? "asset_fetch_failed" : fetched.error;
        return false;
    }

    std::filesystem::path final_abs;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(user_dir, rel, &final_abs, &perr)) {
        if (err) *err = "asset_path_invalid";
        return false;
    }

    const std::string tmp_suffix =
        deps.random_b64url ? deps.random_b64url(8) : std::to_string(deps.now_epoch ? deps.now_epoch() : 0);

    std::string werr;
    if (!write_bytes_atomic_local(final_abs, fetched.bytes, tmp_suffix, &werr)) {
        if (err) *err = werr;
        return false;
    }

    std::string qerr;
    if (!post_write_quota_ok_local(deps, fp, user_dir, &qerr)) {
        std::error_code ec;
        std::filesystem::remove(final_abs, ec);
        if (err) *err = qerr.empty() ? "quota_exceeded" : qerr;
        return false;
    }

    if (out_public_url) {
        *out_public_url = echo_asset_public_url_local(item_id, kind);
    }

    return true;
}

static std::string read_file_bytes_small_local(const std::filesystem::path& p,
                                               std::uint64_t max_bytes,
                                               std::string* err) {
    std::error_code ec;
    const auto sz = std::filesystem::file_size(p, ec);
    if (ec) {
        if (err) *err = "stat_failed";
        return "";
    }

    if (sz > max_bytes) {
        if (err) *err = "file_too_large";
        return "";
    }

    std::ifstream in(p, std::ios::binary);
    if (!in) {
        if (err) *err = "open_failed";
        return "";
    }

    std::string out;
    out.resize(static_cast<std::size_t>(sz));
    if (sz > 0) {
        in.read(out.data(), static_cast<std::streamsize>(out.size()));
        if (!in.good()) {
            if (err) *err = "read_failed";
            return "";
        }
    }

    return out;
}

struct EchoArchiveFetchResult {
    bool ok = false;
    int http_status = 0;
    std::string error;
    std::string final_url;
    std::string html;
};

static bool looks_like_html_local(const std::string& b) {
    if (b.empty()) return false;

    const std::size_t scan_n = std::min<std::size_t>(b.size(), 4096);
    for (std::size_t i = 0; i < scan_n; ++i) {
        if (b[i] == '\0') return false;
    }

    const std::string low = lower_ascii_local(b.substr(0, scan_n));
    return low.find("<!doctype") != std::string::npos ||
           low.find("<html") != std::string::npos ||
           low.find("<head") != std::string::npos ||
           low.find("<body") != std::string::npos ||
           low.find("<title") != std::string::npos;
}

static EchoArchiveFetchResult fetch_archive_html_local(const std::string& input_url,
                                                       std::size_t max_bytes) {
    static constexpr int kMaxRedirects = 4;

    EchoArchiveFetchResult out;
    std::string cur_url = input_url;

    if (max_bytes < 1) {
        out.error = "bad_archive_limit";
        return out;
    }

    for (int hop = 0; hop <= kMaxRedirects; ++hop) {
        PreviewUrlParts p;
        std::string perr;
        if (!parse_preview_url_local(cur_url, &p, &perr)) {
            out.error = perr;
            return out;
        }

        std::string herr;
        if (!preview_host_allowed_local(p.host, &herr)) {
            out.error = herr;
            return out;
        }

        httplib::Headers headers{
            {"User-Agent", "DNA-Nexus-EchoStack/0.1"},
            {"Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"}
        };

        std::string body;
        body.reserve(std::min<std::size_t>(max_bytes, 512 * 1024));

        bool too_large = false;
        httplib::Result r;

        auto receiver = [&](const char* data, size_t len) {
            if (body.size() + len > max_bytes) {
                const std::size_t remain = max_bytes > body.size()
                    ? max_bytes - body.size()
                    : 0;
                if (remain > 0) body.append(data, remain);
                too_large = true;
                return false;
            }

            body.append(data, len);
            return true;
        };

        if (p.scheme == "https") {
            httplib::SSLClient cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(12, 0);
            cli.enable_server_certificate_verification(true);

            r = cli.Get(p.target.c_str(), headers, receiver);
        } else {
            httplib::Client cli(p.host, p.port);
            cli.set_follow_location(false);
            cli.set_connection_timeout(5, 0);
            cli.set_read_timeout(12, 0);

            r = cli.Get(p.target.c_str(), headers, receiver);
        }

        if (too_large) {
            out.error = "archive_too_large";
            return out;
        }

        if (!r) {
            out.error = "archive_fetch_failed";
            return out;
        }

        out.http_status = r->status;

        if (r->status >= 300 && r->status < 400) {
            auto loc = redirect_location_local(r);
            if (!loc.has_value() || loc->empty()) {
                out.error = "archive_redirect_without_location";
                return out;
            }

            cur_url = make_absolute_url_local(p, *loc);
            continue;
        }

        if (r->status < 200 || r->status >= 300) {
            out.error = "archive_http_" + std::to_string(r->status);
            return out;
        }

        if (!looks_like_html_local(body)) {
            out.error = "archive_not_html";
            return out;
        }

        out.ok = true;
        out.final_url = cur_url;
        out.html = std::move(body);
        return out;
    }

    out.error = "archive_too_many_redirects";
    return out;
}

static std::string echo_archive_staging_rel_dir_local(const std::string& job_id) {
    return ".pqnas_echostack/staging/" + job_id;
}

static std::string echo_archive_final_rel_dir_local(const std::string& item_id) {
    return ".pqnas_echostack/items/" + item_id + "/archive";
}

static std::string echo_archive_html_rel_path_local(const std::string& archive_rel_dir) {
    return archive_rel_dir + "/original.html";
}

static std::string echo_archive_meta_rel_path_local(const std::string& archive_rel_dir) {
    return archive_rel_dir + "/meta.json";
}

static std::uint64_t dir_size_bytes_local(const std::filesystem::path& root) {
    std::error_code ec;
    if (!std::filesystem::exists(root, ec) || ec) return 0;

    if (std::filesystem::is_regular_file(root, ec) && !ec) {
        const auto sz = std::filesystem::file_size(root, ec);
        return ec ? 0 : static_cast<std::uint64_t>(sz);
    }

    std::uint64_t total = 0;

    std::filesystem::recursive_directory_iterator it(
        root,
        std::filesystem::directory_options::skip_permission_denied,
        ec
    );

    std::filesystem::recursive_directory_iterator end;

    for (; !ec && it != end; it.increment(ec)) {
        std::error_code ec2;

        if (std::filesystem::is_symlink(it->path(), ec2) && !ec2) {
            it.disable_recursion_pending();
            continue;
        }

        if (!std::filesystem::is_regular_file(it->path(), ec2) || ec2) {
            continue;
        }

        const auto sz = std::filesystem::file_size(it->path(), ec2);
        if (ec2) continue;

        const std::uint64_t n = static_cast<std::uint64_t>(sz);
        if (UINT64_MAX - total < n) return UINT64_MAX;
        total += n;
    }

    return total;
}

static void remove_tree_best_effort_local(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
}

static std::string archive_view_url_local(const std::string& item_id) {
    return "/api/v4/echostack/archive/view?id=" + item_id;
}
static EchoStackItemRec mutable_from_json_local(const json& j,
                                                const EchoStackItemRec& base,
                                                std::int64_t now) {
    EchoStackItemRec r = base;

    if (j.contains("url")) r.url = json_string_local(j, "url", r.url, 4096);
    if (j.contains("final_url")) r.final_url = json_string_local(j, "final_url", r.final_url, 4096);
    if (j.contains("title")) r.title = json_string_local(j, "title", r.title, 512);
    if (j.contains("description")) r.description = json_string_local(j, "description", r.description, 2000);
    if (j.contains("site_name")) r.site_name = json_string_local(j, "site_name", r.site_name, 256);
    if (j.contains("favicon_url")) r.favicon_url = json_string_local(j, "favicon_url", r.favicon_url, 4096);
    if (j.contains("preview_image_url")) r.preview_image_url = json_string_local(j, "preview_image_url", r.preview_image_url, 4096);
    if (j.contains("tags_text")) r.tags_text = json_string_local(j, "tags_text", r.tags_text, 1000);
    if (j.contains("collection")) r.collection = json_string_local(j, "collection", r.collection, 256);
    if (j.contains("notes")) r.notes = json_string_local(j, "notes", r.notes, 8000);

    if (j.contains("read_state")) {
        std::string rs = lower_ascii_local(json_string_local(j, "read_state", r.read_state, 32));
        if (rs != "read" && rs != "unread") rs = "unread";
        r.read_state = rs;
    }

    if (j.contains("favorite")) r.favorite = json_bool_local(j, "favorite", r.favorite);

    r.updated_epoch = now;
    return r;
}

} // namespace

void register_echo_stack_routes(httplib::Server& srv, const EchoStackRoutesDeps& deps) {
    srv.Get("/api/v4/echostack/items", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::size_t limit = parse_limit_local(req, 200, 500);
        const std::string q = req.has_param("q")
            ? cap_string_local(req.get_param_value("q"), 256)
            : std::string();

        std::string err;
        const auto rows = deps.echo_index->list_owner(fp, q, limit, &err);
        if (!err.empty()) {
            audit_local(deps, "v4.echostack_list_fail", "fail", {
                {"actor_fp", fp},
                {"reason", err}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "list_failed"},
                {"message", "failed to list Echo Stack items"}
            }.dump());
            return;
        }

        json items = json::array();
        for (const auto& r : rows) items.push_back(item_json_local(r));

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"items", items}
        }.dump());
    });

    srv.Get("/api/v4/echostack/items/get", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || id.size() > 160) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string err;
        auto rec = deps.echo_index->get_owner_item(fp, id, &err);
        if (!rec.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(*rec)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/preview", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            audit_local(deps, "v4.echostack_preview_fail", "fail", {
                {"actor_fp", fp},
                {"reason", "origin_mismatch"}
            });
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string url = json_string_local(body, "url", "", 4096);
        if (url.empty() || !is_http_url_local(url)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_url"},
                {"message", "url must start with http:// or https://"}
            }.dump());
            return;
        }

        const PreviewFetchResult fetched = fetch_preview_html_local(url);
        if (!fetched.ok) {
            audit_local(deps, "v4.echostack_preview_fail", "fail", {
                {"actor_fp", fp},
                {"reason", fetched.error}
            });

            deps.reply_json(res, 502, json{
                {"ok", false},
                {"error", fetched.error.empty() ? "preview_failed" : fetched.error},
                {"message", "failed to fetch page preview"}
            }.dump());
            return;
        }

        PreviewUrlParts final_parts;
        std::string perr;
        parse_preview_url_local(fetched.final_url, &final_parts, &perr);

        std::string title = find_meta_content_local(fetched.html, "property", "og:title");
        if (title.empty()) title = find_meta_content_local(fetched.html, "name", "twitter:title");
        if (title.empty()) title = find_title_local(fetched.html);

        std::string description = find_meta_content_local(fetched.html, "name", "description");
        if (description.empty()) description = find_meta_content_local(fetched.html, "property", "og:description");
        if (description.empty()) description = find_meta_content_local(fetched.html, "name", "twitter:description");

        std::string site_name = find_meta_content_local(fetched.html, "property", "og:site_name");

        std::string image = find_meta_content_local(fetched.html, "property", "og:image");
        if (image.empty()) image = find_meta_content_local(fetched.html, "name", "twitter:image");

        std::string icon = find_icon_href_local(fetched.html);

        if (!final_parts.origin.empty()) {
            icon = make_absolute_url_local(final_parts, icon);
            image = make_absolute_url_local(final_parts, image);

            if (icon.empty()) {
                icon = final_parts.origin + "/favicon.ico";
            }
        }

        audit_local(deps, "v4.echostack_preview_ok", "ok", {
            {"actor_fp", fp},
            {"status", std::to_string(fetched.http_status)}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"url", url},
            {"final_url", fetched.final_url},
            {"title", cap_string_local(title, 512)},
            {"description", cap_string_local(description, 2000)},
            {"site_name", cap_string_local(site_name, 256)},
            {"favicon_url", cap_string_local(icon, 4096)},
            {"preview_image_url", cap_string_local(image, 4096)}
        }.dump());
    });
    srv.Get("/api/v4/echostack/assets/get", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";

        if (id.empty() || id.size() > 160 || !safe_echo_asset_kind_local(kind)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "valid id and kind required"}
            }.dump());
            return;
        }

        std::string ierr;
        auto rec = deps.echo_index->get_owner_item(fp, id, &ierr);
        if (!rec.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        if (!deps.user_dir_for_fp) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "user storage resolver not configured"}
            }.dump());
            return;
        }

        const std::filesystem::path user_dir = deps.user_dir_for_fp(*deps.users, fp);
        const std::string rel = echo_asset_rel_path_local(id, kind);

        std::filesystem::path abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(user_dir, rel, &abs, &perr)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "invalid_path"},
                {"message", "asset path invalid"}
            }.dump());
            return;
        }

        std::string rerr;
        std::string bytes = read_file_bytes_small_local(abs, 2 * 1024 * 1024, &rerr);
        if (!rerr.empty()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "asset not found"}
            }.dump());
            return;
        }

        const std::string mime = detect_image_mime_local(bytes);
        if (mime.empty()) {
            deps.reply_json(res, 415, json{
                {"ok", false},
                {"error", "unsupported_media_type"},
                {"message", "asset is not a supported cached image"}
            }.dump());
            return;
        }

        res.set_header("Cache-Control", "private, max-age=86400");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_content(std::move(bytes), mime.c_str());
    });

    srv.Post("/api/v4/echostack/items/create", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            audit_local(deps, "v4.echostack_create_fail", "fail", {
                {"actor_fp", fp},
                {"reason", "origin_mismatch"}
            });
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string url = json_string_local(body, "url", "", 4096);
        if (url.empty() || !is_http_url_local(url)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_url"},
                {"message", "url must start with http:// or https://"}
            }.dump());
            return;
        }

        const std::int64_t now = deps.now_epoch ? deps.now_epoch() : 0;

        EchoStackItemRec r;
        r.id = "es_" + (deps.random_b64url ? deps.random_b64url(18) : std::to_string(now));
        r.owner_fp = fp;
        r.url = url;
        r.final_url = json_string_local(body, "final_url", "", 4096);
        r.title = json_string_local(body, "title", url, 512);
        r.description = json_string_local(body, "description", "", 2000);
        r.site_name = json_string_local(body, "site_name", "", 256);
        const std::string source_favicon_url =
            json_string_local(body, "favicon_url", "", 4096);
        const std::string source_preview_image_url =
            json_string_local(body, "preview_image_url", "", 4096);

        // Do not store remote image URLs directly for new items. We will try to
        // cache small image assets locally after the DB row exists.
        r.favicon_url = "";
        r.preview_image_url = "";
        r.tags_text = json_string_local(body, "tags_text", "", 1000);
        r.collection = json_string_local(body, "collection", "", 256);
        r.notes = json_string_local(body, "notes", "", 8000);
        r.read_state = lower_ascii_local(json_string_local(body, "read_state", "unread", 32));
        if (r.read_state != "read" && r.read_state != "unread") r.read_state = "unread";
        r.favorite = json_bool_local(body, "favorite", false);
        r.archive_status = "none";
        r.created_epoch = now;
        r.updated_epoch = now;

        std::string err;
        if (!deps.echo_index->insert(r, &err)) {
            audit_local(deps, "v4.echostack_create_fail", "fail", {
                {"actor_fp", fp},
                {"reason", err}
            });
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "create_failed"},
                {"message", "failed to create Echo Stack item"}
            }.dump());
            return;
        }

        bool cached_any = false;

        if (deps.user_dir_for_fp) {
            const std::filesystem::path user_dir = deps.user_dir_for_fp(*deps.users, fp);

            std::string favicon_source = source_favicon_url;

            if (favicon_source.empty()) {
                PreviewUrlParts item_url_parts;
                std::string perr;
                const std::string base_url = !r.final_url.empty() ? r.final_url : r.url;
                if (parse_preview_url_local(base_url, &item_url_parts, &perr) &&
                    !item_url_parts.origin.empty()) {
                    favicon_source = item_url_parts.origin + "/favicon.ico";
                }
            }

            std::string cached_url;
            std::string cerr;

            if (!favicon_source.empty() &&
                cache_echo_asset_local(deps,
                                       fp,
                                       user_dir,
                                       r.id,
                                       "favicon",
                                       favicon_source,
                                       256 * 1024,
                                       &cached_url,
                                       &cerr)) {
                r.favicon_url = cached_url;
                cached_any = true;
            } else if (!favicon_source.empty()) {
                audit_local(deps, "v4.echostack_asset_cache_skip", "fail", {
                    {"actor_fp", fp},
                    {"item_id", r.id},
                    {"kind", "favicon"},
                    {"reason", cerr}
                });
            }

            cached_url.clear();
            cerr.clear();

            if (!source_preview_image_url.empty() &&
                cache_echo_asset_local(deps,
                                       fp,
                                       user_dir,
                                       r.id,
                                       "preview",
                                       source_preview_image_url,
                                       2 * 1024 * 1024,
                                       &cached_url,
                                       &cerr)) {
                r.preview_image_url = cached_url;
                cached_any = true;
            } else if (!source_preview_image_url.empty()) {
                audit_local(deps, "v4.echostack_asset_cache_skip", "fail", {
                    {"actor_fp", fp},
                    {"item_id", r.id},
                    {"kind", "preview"},
                    {"reason", cerr}
                });
            }

            if (cached_any) {
                r.updated_epoch = deps.now_epoch ? deps.now_epoch() : r.updated_epoch;

                std::string uerr;
                if (!deps.echo_index->update_mutable(r, &uerr)) {
                    audit_local(deps, "v4.echostack_asset_cache_update_fail", "fail", {
                        {"actor_fp", fp},
                        {"item_id", r.id},
                        {"reason", uerr}
                    });
                }
            }
        }

        audit_local(deps, "v4.echostack_create_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", r.id},
            {"cached_assets", cached_any ? "1" : "0"}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(r)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/update", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string id = json_string_local(body, "id", "", 160);
        if (id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string err;
        auto existing = deps.echo_index->get_owner_item(fp, id, &err);
        if (!existing.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        const std::int64_t now = deps.now_epoch ? deps.now_epoch() : existing->updated_epoch;
        EchoStackItemRec updated = mutable_from_json_local(body, *existing, now);

        if (updated.url.empty() || !is_http_url_local(updated.url)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_url"},
                {"message", "url must start with http:// or https://"}
            }.dump());
            return;
        }

        err.clear();
        if (!deps.echo_index->update_mutable(updated, &err)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "update_failed"},
                {"message", err.empty() ? "failed to update Echo Stack item" : err}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_update_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"item", item_json_local(updated)}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/delete", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        const std::string id = body.is_object() ? json_string_local(body, "id", "", 160) : "";

        if (id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }
        std::string get_err;
        auto existing = deps.echo_index->get_owner_item(fp, id, &get_err);
        std::string err;
        if (!deps.echo_index->delete_owner_item(fp, id, &err)) {
            deps.reply_json(res, err == "not_found" ? 404 : 500, json{
                {"ok", false},
                {"error", err == "not_found" ? "not_found" : "delete_failed"},
                {"message", err.empty() ? "failed to delete Echo Stack item" : err}
            }.dump());
            return;
        }
        if (existing.has_value() && deps.user_dir_for_fp && deps.users) {
            const std::filesystem::path user_dir = deps.user_dir_for_fp(*deps.users, fp);

            std::filesystem::path item_dir_abs;
            std::string perr;

            const std::string item_rel_dir =
                ".pqnas_echostack/items/" + existing->id;

            if (pqnas::resolve_user_path_strict(user_dir, item_rel_dir, &item_dir_abs, &perr)) {
                std::error_code ec;
                std::filesystem::remove_all(item_dir_abs, ec);

                if (ec) {
                    audit_local(deps, "v4.echostack_delete_files_fail", "fail", {
                        {"actor_fp", fp},
                        {"item_id", id},
                        {"reason", ec.message()}
                    });
                }
            } else {
                audit_local(deps, "v4.echostack_delete_files_fail", "fail", {
                    {"actor_fp", fp},
                    {"item_id", id},
                    {"reason", perr.empty() ? "invalid_item_dir" : perr}
                });
            }
        }
        audit_local(deps, "v4.echostack_delete_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true}
        }.dump());
    });
        srv.Get("/api/v4/echostack/archive/view", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty() || id.size() > 160) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string ierr;
        auto rec = deps.echo_index->get_owner_item(fp, id, &ierr);
        if (!rec.has_value() ||
            rec->archive_status != "archived" ||
            rec->archive_rel_dir.empty()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "archive not found"}
            }.dump());
            return;
        }

        if (!deps.user_dir_for_fp || !deps.users) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "user storage resolver not configured"}
            }.dump());
            return;
        }

        const std::filesystem::path user_dir = deps.user_dir_for_fp(*deps.users, fp);
        const std::string html_rel = echo_archive_html_rel_path_local(rec->archive_rel_dir);

        std::filesystem::path html_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(user_dir, html_rel, &html_abs, &perr)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "invalid_path"},
                {"message", "archive path invalid"}
            }.dump());
            return;
        }

        std::string rerr;
        std::string html = read_file_bytes_small_local(html_abs, 4ull * 1024ull * 1024ull, &rerr);
        if (!rerr.empty()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "archive HTML not found"}
            }.dump());
            return;
        }

        // Defense-in-depth:
        // - sandbox disables scripts/forms/popups/top-navigation unless explicitly allowed
        // - default-src none prevents the archived page from phoning home
        // - img-src only allows embedded data/blob images, not remote images
        res.set_header("Cache-Control", "private, no-store");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header(
            "Content-Security-Policy",
            "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; "
            "img-src data: blob:; media-src data: blob:; style-src 'unsafe-inline'; "
            "font-src data:; frame-ancestors 'self'"
        );

        res.set_content(html, "text/html; charset=utf-8");
    });

    srv.Post("/api/v4/echostack/items/archive", [deps](const httplib::Request& req, httplib::Response& res) {
        static constexpr std::uint64_t kMaxArchiveHtmlBytes = 3ull * 1024ull * 1024ull;
        static constexpr std::uint64_t kArchiveMetaReserveBytes = 16ull * 1024ull;

        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        if (!origin_allowed_local(deps, req)) {
            audit_local(deps, "v4.echostack_archive_fail", "fail", {
                {"actor_fp", fp},
                {"reason", "origin_mismatch"}
            });
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "origin_mismatch"},
                {"message", "same-origin request required"}
            }.dump());
            return;
        }

        const json body = parse_body_json_local(req);
        if (!body.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string id = json_string_local(body, "id", "", 160);
        if (id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "id required"}
            }.dump());
            return;
        }

        std::string ierr;
        auto rec_opt = deps.echo_index->get_owner_item(fp, id, &ierr);
        if (!rec_opt.has_value()) {
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "Echo Stack item not found"}
            }.dump());
            return;
        }

        EchoStackItemRec rec = *rec_opt;

        if (rec.archive_status == "archiving") {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "already_archiving"},
                {"message", "Archive is already in progress"}
            }.dump());
            return;
        }

        if (rec.archive_status == "archived" && !rec.archive_rel_dir.empty()) {
            deps.reply_json(res, 200, json{
                {"ok", true},
                {"already_archived", true},
                {"archive_view_url", archive_view_url_local(rec.id)},
                {"item", item_json_local(rec)}
            }.dump());
            return;
        }

        if (!deps.user_dir_for_fp || !deps.users) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "Echo Stack archive dependencies not configured"}
            }.dump());
            return;
        }

        const std::filesystem::path user_dir = deps.user_dir_for_fp(*deps.users, fp);

        const std::string job_id =
            "esa_" + (deps.random_b64url ? deps.random_b64url(18) : std::to_string(deps.now_epoch ? deps.now_epoch() : 0));

        const std::string staging_rel_dir = echo_archive_staging_rel_dir_local(job_id);
        const std::string staging_html_rel = echo_archive_html_rel_path_local(staging_rel_dir);
        const std::string staging_meta_rel = echo_archive_meta_rel_path_local(staging_rel_dir);

        std::filesystem::path staging_html_abs;
        std::filesystem::path staging_meta_abs;
        std::string perr;

        if (!pqnas::resolve_user_path_strict(user_dir, staging_html_rel, &staging_html_abs, &perr) ||
            !pqnas::resolve_user_path_strict(user_dir, staging_meta_rel, &staging_meta_abs, &perr)) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "invalid_path"},
                {"message", "archive staging path invalid"}
            }.dump());
            return;
        }

        const std::uint64_t quota_probe_bytes = kMaxArchiveHtmlBytes + kArchiveMetaReserveBytes;

        pqnas::QuotaCheckResult qc = pqnas::quota_check_for_upload_v1(
            *deps.users,
            fp,
            user_dir,
            staging_html_rel,
            quota_probe_bytes
        );

        if (!qc.ok) {
            const int http = qc.error == "quota_exceeded" ? 507 : 403;

            audit_local(deps, "v4.echostack_archive_fail", "fail", {
                {"actor_fp", fp},
                {"item_id", id},
                {"reason", qc.error.empty() ? "quota_check_failed" : qc.error},
                {"incoming_bytes", std::to_string(static_cast<unsigned long long>(quota_probe_bytes))},
                {"used_bytes", std::to_string(static_cast<unsigned long long>(qc.used_bytes))},
                {"quota_bytes", std::to_string(static_cast<unsigned long long>(qc.quota_bytes))}
            });

            deps.reply_json(res, http, json{
                {"ok", false},
                {"error", qc.error.empty() ? "quota_check_failed" : qc.error},
                {"message", qc.error == "quota_exceeded"
                    ? "Archive would exceed storage quota"
                    : "Archive quota check failed"},
                {"used_bytes", qc.used_bytes},
                {"quota_bytes", qc.quota_bytes},
                {"incoming_bytes", quota_probe_bytes},
                {"would_used_bytes", qc.would_used_bytes}
            }.dump());
            return;
        }

        const std::int64_t now1 = deps.now_epoch ? deps.now_epoch() : 0;

        rec.archive_status = "archiving";
        rec.archive_error.clear();
        rec.updated_epoch = now1;

        std::string uerr;
        (void)deps.echo_index->update_archive_fields(rec, &uerr);

        auto fail_archive = [&](int http,
                                const std::string& code,
                                const std::string& message,
                                const std::string& reason) {
            remove_tree_best_effort_local(staging_html_abs.parent_path());

            rec.archive_status = "failed";
            rec.archive_error = reason.empty() ? code : reason;
            rec.updated_epoch = deps.now_epoch ? deps.now_epoch() : now1;

            std::string ferr;
            (void)deps.echo_index->update_archive_fields(rec, &ferr);

            audit_local(deps, "v4.echostack_archive_fail", "fail", {
                {"actor_fp", fp},
                {"item_id", id},
                {"reason", rec.archive_error}
            });

            deps.reply_json(res, http, json{
                {"ok", false},
                {"error", code},
                {"message", message},
                {"archive_error", rec.archive_error}
            }.dump());
        };

        const std::string archive_source_url = !rec.final_url.empty() ? rec.final_url : rec.url;

        EchoArchiveFetchResult fetched = fetch_archive_html_local(
            archive_source_url,
            static_cast<std::size_t>(kMaxArchiveHtmlBytes)
        );

        if (!fetched.ok) {
            fail_archive(
                fetched.error == "archive_too_large" ? 413 : 502,
                fetched.error.empty() ? "archive_fetch_failed" : fetched.error,
                "failed to fetch page archive",
                fetched.error
            );
            return;
        }

        std::string werr;
        if (!write_bytes_atomic_local(staging_html_abs,
                                      fetched.html,
                                      deps.random_b64url ? deps.random_b64url(8) : "tmp",
                                      &werr)) {
            fail_archive(500, "archive_write_failed", "failed to write archive HTML", werr);
            return;
        }

        const std::int64_t archived_now = deps.now_epoch ? deps.now_epoch() : now1;

        const json meta = {
            {"item_id", rec.id},
            {"url", rec.url},
            {"final_url", fetched.final_url},
            {"title", rec.title},
            {"archived_epoch", archived_now},
            {"format", "html_snapshot_v1"},
            {"max_html_bytes", kMaxArchiveHtmlBytes}
        };

        if (!write_bytes_atomic_local(staging_meta_abs,
                                      meta.dump(2),
                                      deps.random_b64url ? deps.random_b64url(8) : "tmp",
                                      &werr)) {
            fail_archive(500, "archive_meta_write_failed", "failed to write archive metadata", werr);
            return;
        }

        const std::filesystem::path staging_dir_abs = staging_html_abs.parent_path();
        const std::uint64_t staged_bytes = dir_size_bytes_local(staging_dir_abs);

        std::string qerr;
        if (!post_write_quota_ok_local(deps, fp, user_dir, &qerr)) {
            fail_archive(507, "quota_exceeded", "Archive exceeded storage quota", qerr);
            return;
        }

        const std::string final_rel_dir = echo_archive_final_rel_dir_local(rec.id);
        std::filesystem::path final_html_abs;
        if (!pqnas::resolve_user_path_strict(user_dir,
                                             echo_archive_html_rel_path_local(final_rel_dir),
                                             &final_html_abs,
                                             &perr)) {
            fail_archive(400, "invalid_archive_path", "archive final path invalid", perr);
            return;
        }

        const std::filesystem::path final_dir_abs = final_html_abs.parent_path();

        std::error_code ec;
        std::filesystem::create_directories(final_dir_abs.parent_path(), ec);
        if (ec) {
            fail_archive(500, "archive_mkdir_failed", "failed to create archive directory", ec.message());
            return;
        }

        // If a stale failed archive directory exists, replace it only after staging
        // is fully written and quota-checked.
        std::filesystem::remove_all(final_dir_abs, ec);
        ec.clear();

        std::filesystem::rename(staging_dir_abs, final_dir_abs, ec);
        if (ec) {
            fail_archive(500, "archive_commit_failed", "failed to commit archive", ec.message());
            return;
        }

        rec.final_url = fetched.final_url;
        rec.archive_status = "archived";
        rec.archive_error.clear();
        rec.archive_rel_dir = final_rel_dir;
        rec.archive_bytes = staged_bytes;
        rec.archived_epoch = archived_now;
        rec.updated_epoch = archived_now;

        uerr.clear();
        if (!deps.echo_index->update_archive_fields(rec, &uerr)) {
            audit_local(deps, "v4.echostack_archive_db_update_fail", "fail", {
                {"actor_fp", fp},
                {"item_id", id},
                {"reason", uerr}
            });

            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "archive_db_update_failed"},
                {"message", "archive was written but database update failed"}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_archive_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id},
            {"bytes", std::to_string(static_cast<unsigned long long>(staged_bytes))}
        });

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"archive_view_url", archive_view_url_local(rec.id)},
            {"item", item_json_local(rec)}
        }.dump());
    });
}

} // namespace pqnas
