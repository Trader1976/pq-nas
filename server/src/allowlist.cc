#include "allowlist.h"
#include "pqnas_util.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

namespace pqnas {

static std::string trim_ws_local(std::string s) {
    auto is_ws = [](unsigned char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; };
    while (!s.empty() && is_ws((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && is_ws((unsigned char)s.back()))  s.pop_back();
    return s;
}

static std::string norm_fp(std::string fp) {
    fp = lower_ascii(fp);
    fp = trim_ws_local(fp);
    return fp;
}

bool Allowlist::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) {
        std::cerr << "[allowlist] file not found: " << path << std::endl;
        return false;
    }

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        std::cerr << "[allowlist] parse error: " << e.what() << std::endl;
        return false;
    }

    if (!j.is_object() || !j.contains("users") || !j["users"].is_array()) {
        std::cerr << "[allowlist] invalid format (expected {\"users\": [...]})" << std::endl;
        return false;
    }

    std::unordered_map<std::string, AllowEntry> tmp;

    for (const auto& u : j["users"]) {
        if (!u.is_object()) continue;

        std::string fp = norm_fp(u.value("fingerprint", ""));
        if (fp.empty()) continue;

        AllowEntry e;

        // Option A: role string (simple)
        //   { "fingerprint":"...", "role":"admin" } or "user"
        if (u.contains("role")) {
            std::string r = lower_ascii(u.value("role", ""));
            if (r == "admin") { e.admin = true; e.user = true; }
            else if (r == "user") { e.user = true; }
        }

        // Option B: tags array (future-proof)
        //   { "fingerprint":"...", "tags":["user","admin"] }
        if (u.contains("tags") && u["tags"].is_array()) {
            for (const auto& t : u["tags"]) {
                if (!t.is_string()) continue;
                std::string ts = lower_ascii(t.get<std::string>());
                if (ts == "admin") e.admin = true;
                if (ts == "user")  e.user  = true;
            }
            if (e.admin) e.user = true; // admin implies user
        }

        if (!e.user && !e.admin) continue;

        tmp[fp] = e;
    }

    m_.swap(tmp);
    std::cerr << "[allowlist] loaded " << m_.size() << " entries from " << path << std::endl;
    return true;
}

bool Allowlist::is_allowed(const std::string& fp_hex) const {
    auto it = m_.find(norm_fp(fp_hex));
    if (it == m_.end()) return false;
    return it->second.user || it->second.admin;
}

bool Allowlist::is_admin(const std::string& fp_hex) const {
    auto it = m_.find(norm_fp(fp_hex));
    if (it == m_.end()) return false;
    return it->second.admin;
}

} // namespace pqnas
