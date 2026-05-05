#include "echo_stack_routes.h"

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
        r.favicon_url = json_string_local(body, "favicon_url", "", 4096);
        r.preview_image_url = json_string_local(body, "preview_image_url", "", 4096);
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

        audit_local(deps, "v4.echostack_create_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", r.id}
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

        std::string err;
        if (!deps.echo_index->delete_owner_item(fp, id, &err)) {
            deps.reply_json(res, err == "not_found" ? 404 : 500, json{
                {"ok", false},
                {"error", err == "not_found" ? "not_found" : "delete_failed"},
                {"message", err.empty() ? "failed to delete Echo Stack item" : err}
            }.dump());
            return;
        }

        audit_local(deps, "v4.echostack_delete_ok", "ok", {
            {"actor_fp", fp},
            {"item_id", id}
        });

        deps.reply_json(res, 200, json{
            {"ok", true}
        }.dump());
    });

    srv.Post("/api/v4/echostack/items/archive", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp, role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        deps.reply_json(res, 501, json{
            {"ok", false},
            {"error", "not_implemented"},
            {"message", "Echo Stack archiving is reserved for the quota-safe archive patch"}
        }.dump());
    });
}

} // namespace pqnas
