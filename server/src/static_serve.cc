#include "static_serve.h"

#include <fstream>
#include <sstream>

static std::string slurp_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool serve_static_file(const httplib::Request& /*req*/,
                       httplib::Response& res,
                       const std::string& abs_path,
                       const std::string& content_type,
                       bool no_store) {
    std::string body = slurp_file(abs_path);
    if (body.empty()) {
        res.status = 404;
        res.set_content("not found", "text/plain; charset=utf-8");
        return false;
    }

    // Basic hardening
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Referrer-Policy", "no-referrer");

    if (no_store) {
        res.set_header("Cache-Control", "no-store");
        res.set_header("Pragma", "no-cache");
    } else {
        // light caching for static assets (we can tune later)
        res.set_header("Cache-Control", "public, max-age=300");
    }

    res.set_content(std::move(body), content_type);
    res.status = 200;
    return true;
}
