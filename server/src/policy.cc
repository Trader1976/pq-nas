#include "policy.h"
#include <fstream>
#include <unordered_set>
#include <string>

static std::unordered_set<std::string> g_allow;

static std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    size_t b = s.size();
    while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) b--;
    return s.substr(a, b - a);
}

bool policy_load_allowlist(const std::string& path) {
    g_allow.clear();
    if (path.empty()) return true;

    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        g_allow.insert(line);
    }
    return true;
}

bool policy_is_allowed(const std::string& fingerprint_b64) {
    if (g_allow.empty()) return true; // allow-all if no file or empty file
    return g_allow.find(fingerprint_b64) != g_allow.end();
}
