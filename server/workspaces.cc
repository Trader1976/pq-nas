// ============================================================================
// server/src/workspaces.cpp
// ============================================================================

#include "workspaces.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <set>
#include <system_error>

namespace pqnas {

namespace {

// -----------------------------------------------------------------------------
// local helpers
// -----------------------------------------------------------------------------

std::string trim_copy_safe(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::string lower_ascii_copy(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool read_text_file(const std::string& path, std::string* out) {
    if (out) out->clear();

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::string s((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
    if (!f.good() && !f.eof()) return false;

    if (out) *out = std::move(s);
    return true;
}

bool write_text_file_atomic_raw(const std::string& path, const std::string& content) {
    const std::string tmp = path + ".tmp";

    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;

    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    f.close();
    if (!f) return false;

    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp);
        return false;
    }
    return true;
}

std::string normalize_pool_id_copy(const std::string& s) {
    const std::string v = trim_copy_safe(s);
    if (v.empty()) return "";
    if (lower_ascii_copy(v) == "default") return "";
    return v;
}

bool is_nonempty_string(const json& j, const char* key) {
    return j.contains(key) && j[key].is_string() && !trim_copy_safe(j[key].get<std::string>()).empty();
}

std::string random_urlsafe_token(std::size_t n) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 63);

    std::string out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kAlphabet[dist(gen)]);
    }
    return out;
}

bool member_fingerprint_less(const WorkspaceMemberRec& a, const WorkspaceMemberRec& b) {
    return a.fingerprint < b.fingerprint;
}

} // namespace

// -----------------------------------------------------------------------------
// normalization helpers
// -----------------------------------------------------------------------------

std::string normalize_workspace_status_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));
    return (v == "disabled") ? "disabled" : "enabled";
}

std::string normalize_workspace_role_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));
    if (v == "owner") return "owner";
    if (v == "editor") return "editor";
    return "viewer";
}

std::string normalize_workspace_member_status_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));
    return (v == "disabled") ? "disabled" : "enabled";
}

std::string normalize_workspace_storage_state_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));
    return (v == "allocated") ? "allocated" : "unallocated";
}

void normalize_workspace_member_v1(WorkspaceMemberRec* m) {
    if (!m) return;

    m->fingerprint = trim_copy_safe(m->fingerprint);
    m->role = normalize_workspace_role_copy(m->role);
    m->status = normalize_workspace_member_status_copy(m->status);
    m->added_at = trim_copy_safe(m->added_at);
    m->added_by = trim_copy_safe(m->added_by);
}

bool is_valid_workspace_id(const std::string& workspace_id) {
    const std::string v = trim_copy_safe(workspace_id);
    if (v.size() < 6 || v.size() > 128) return false;
    if (v.rfind("ws_", 0) != 0) return false;

    for (char c : v) {
        const bool ok =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

std::string default_workspace_root_rel_for_id(const std::string& workspace_id) {
    if (!is_valid_workspace_id(workspace_id)) return "";
    return "workspaces/" + workspace_id;
}

void normalize_workspace_rec_v1(WorkspaceRec* w) {
    if (!w) return;

    w->workspace_id = trim_copy_safe(w->workspace_id);
    w->name = trim_copy_safe(w->name);
    w->status = normalize_workspace_status_copy(w->status);
    w->notes = trim_copy_safe(w->notes);

    w->created_at = trim_copy_safe(w->created_at);
    w->created_by = trim_copy_safe(w->created_by);

    w->storage_state = normalize_workspace_storage_state_copy(w->storage_state);
    w->storage_pool_id = normalize_pool_id_copy(w->storage_pool_id);
    w->root_rel = trim_copy_safe(w->root_rel);
    w->storage_set_at = trim_copy_safe(w->storage_set_at);
    w->storage_set_by = trim_copy_safe(w->storage_set_by);

    // If allocated but root_rel missing, derive canonical root_rel.
    if (w->storage_state == "allocated" && w->root_rel.empty() && is_valid_workspace_id(w->workspace_id)) {
        w->root_rel = default_workspace_root_rel_for_id(w->workspace_id);
    }

    // De-duplicate members by fingerprint, keep first non-empty occurrence.
    std::vector<WorkspaceMemberRec> out;
    std::set<std::string> seen;

    for (auto& m : w->members) {
        normalize_workspace_member_v1(&m);
        if (m.fingerprint.empty()) continue;
        if (!seen.insert(m.fingerprint).second) continue;
        out.push_back(m);
    }

    std::sort(out.begin(), out.end(), member_fingerprint_less);
    w->members = std::move(out);
}

WorkspaceMemberRec workspace_member_from_json_v1(const json& j) {
    WorkspaceMemberRec m;

    if (!j.is_object()) {
        normalize_workspace_member_v1(&m);
        return m;
    }

    m.fingerprint = j.value("fingerprint", "");
    m.role = j.value("role", "viewer");
    m.status = j.value("status", "enabled");
    m.added_at = j.value("added_at", "");
    m.added_by = j.value("added_by", "");

    normalize_workspace_member_v1(&m);
    return m;
}

json workspace_member_to_json_v1(const WorkspaceMemberRec& in_m) {
    WorkspaceMemberRec m = in_m;
    normalize_workspace_member_v1(&m);

    return json{
        {"fingerprint", m.fingerprint},
        {"role", m.role},
        {"status", m.status},
        {"added_at", m.added_at},
        {"added_by", m.added_by}
    };
}

WorkspaceRec workspace_from_json_v1(const json& j) {
    WorkspaceRec w;

    if (!j.is_object()) {
        normalize_workspace_rec_v1(&w);
        return w;
    }

    w.workspace_id = j.value("workspace_id", "");
    w.name = j.value("name", "");
    w.status = j.value("status", "enabled");
    w.notes = j.value("notes", "");

    w.created_at = j.value("created_at", "");
    w.created_by = j.value("created_by", "");

    w.storage_state = j.value("storage_state", "unallocated");
    w.storage_pool_id = j.value("storage_pool_id", "");
    w.root_rel = j.value("root_rel", "");
    w.storage_set_at = j.value("storage_set_at", "");
    w.storage_set_by = j.value("storage_set_by", "");

    try {
        if (j.contains("quota_bytes")) {
            if (j["quota_bytes"].is_number_unsigned()) {
                w.quota_bytes = j["quota_bytes"].get<std::uint64_t>();
            } else if (j["quota_bytes"].is_number_integer()) {
                const auto v = j["quota_bytes"].get<long long>();
                w.quota_bytes = (v < 0) ? 0 : static_cast<std::uint64_t>(v);
            }
        }
    } catch (...) {
        w.quota_bytes = 0;
    }

    if (j.contains("members") && j["members"].is_array()) {
        for (const auto& one : j["members"]) {
            w.members.push_back(workspace_member_from_json_v1(one));
        }
    }

    normalize_workspace_rec_v1(&w);
    return w;
}

json workspace_to_json_v1(const WorkspaceRec& in_w) {
    WorkspaceRec w = in_w;
    normalize_workspace_rec_v1(&w);

    json members = json::array();
    for (const auto& m : w.members) {
        members.push_back(workspace_member_to_json_v1(m));
    }

    return json{
        {"workspace_id", w.workspace_id},
        {"name", w.name},
        {"status", w.status},
        {"notes", w.notes},

        {"created_at", w.created_at},
        {"created_by", w.created_by},

        {"storage_state", w.storage_state},
        {"storage_pool_id", w.storage_pool_id},
        {"root_rel", w.root_rel},
        {"quota_bytes", w.quota_bytes},
        {"storage_set_at", w.storage_set_at},
        {"storage_set_by", w.storage_set_by},

        {"members", members}
    };
}

void ensure_workspaces_cfg_shape_v1(json* cfg) {
    if (!cfg || !cfg->is_object()) {
        if (cfg) *cfg = json::object();
        return;
    }

    if (!cfg->contains("workspaces") || !(*cfg)["workspaces"].is_array()) {
        (*cfg)["workspaces"] = json::array();
    }

    json out = json::array();
    std::set<std::string> seen_ids;

    for (const auto& one : (*cfg)["workspaces"]) {
        WorkspaceRec w = workspace_from_json_v1(one);
        if (!is_valid_workspace_id(w.workspace_id)) continue;
        if (!seen_ids.insert(w.workspace_id).second) continue;
        out.push_back(workspace_to_json_v1(w));
    }

    (*cfg)["workspaces"] = std::move(out);
    (*cfg)["version"] = 1;
}

// -----------------------------------------------------------------------------
// id helpers
// -----------------------------------------------------------------------------

std::string new_workspace_id() {
    // 12 chars is short enough for UI, large enough for practical uniqueness here.
    return "ws_" + random_urlsafe_token(12);
}

// -----------------------------------------------------------------------------
// quota accounting helper
// -----------------------------------------------------------------------------

std::uint64_t sum_allocated_workspace_quota_on_pool(const WorkspacesRegistry& workspaces,
                                                    const std::string& want_pool_id,
                                                    const std::string& exclude_workspace_id) {
    const std::string want_pool = normalize_pool_id_copy(want_pool_id);
    std::uint64_t total = 0;

    for (const auto& kv : workspaces.snapshot()) {
        const auto& w = kv.second;

        if (!exclude_workspace_id.empty() && w.workspace_id == exclude_workspace_id) continue;
        if (w.storage_state != "allocated") continue;

        if (normalize_pool_id_copy(w.storage_pool_id) != want_pool) continue;

        if (std::numeric_limits<std::uint64_t>::max() - total < w.quota_bytes) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        total += w.quota_bytes;
    }

    return total;
}

// -----------------------------------------------------------------------------
// registry
// -----------------------------------------------------------------------------

bool WorkspacesRegistry::load(const std::string& path) {
    by_id_.clear();

    std::string txt;
    json cfg = json::object();

    if (read_text_file(path, &txt)) {
        try {
            cfg = json::parse(txt);
        } catch (...) {
            cfg = json::object();
        }
    }

    if (!cfg.is_object()) cfg = json::object();
    ensure_workspaces_cfg_shape_v1(&cfg);

    if (cfg.contains("workspaces") && cfg["workspaces"].is_array()) {
        for (const auto& one : cfg["workspaces"]) {
            WorkspaceRec w = workspace_from_json_v1(one);
            if (!is_valid_workspace_id(w.workspace_id)) continue;
            by_id_[w.workspace_id] = std::move(w);
        }
    }

    return true;
}

bool WorkspacesRegistry::save(const std::string& path) const {
    json cfg = json::object();
    cfg["version"] = 1;
    cfg["workspaces"] = json::array();

    for (const auto& kv : by_id_) {
        cfg["workspaces"].push_back(workspace_to_json_v1(kv.second));
    }

    ensure_workspaces_cfg_shape_v1(&cfg);

    const std::filesystem::path p(path);
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    if (ec) return false;

    return write_text_file_atomic_raw(path, cfg.dump(2) + "\n");
}

bool WorkspacesRegistry::exists(const std::string& workspace_id) const {
    return by_id_.find(workspace_id) != by_id_.end();
}

std::optional<WorkspaceRec> WorkspacesRegistry::get(const std::string& workspace_id) const {
    auto it = by_id_.find(workspace_id);
    if (it == by_id_.end()) return std::nullopt;
    return it->second;
}

bool WorkspacesRegistry::upsert(const WorkspaceRec& rec) {
    WorkspaceRec w = rec;
    normalize_workspace_rec_v1(&w);

    if (!is_valid_workspace_id(w.workspace_id)) return false;

    by_id_[w.workspace_id] = std::move(w);
    return true;
}

bool WorkspacesRegistry::erase(const std::string& workspace_id) {
    return by_id_.erase(workspace_id) > 0;
}

const std::map<std::string, WorkspaceRec>& WorkspacesRegistry::snapshot() const {
    return by_id_;
}

std::vector<WorkspaceRec> WorkspacesRegistry::list_for_member(const std::string& fingerprint) const {
    std::vector<WorkspaceRec> out;
    const std::string fp = trim_copy_safe(fingerprint);
    if (fp.empty()) return out;

    for (const auto& kv : by_id_) {
        const auto& w = kv.second;
        for (const auto& m : w.members) {
            if (m.fingerprint == fp) {
                out.push_back(w);
                break;
            }
        }
    }

    return out;
}

std::optional<WorkspaceMemberRec> WorkspacesRegistry::get_member(const std::string& workspace_id,
                                                                 const std::string& fingerprint) const {
    auto wopt = get(workspace_id);
    if (!wopt.has_value()) return std::nullopt;

    const std::string fp = trim_copy_safe(fingerprint);
    for (const auto& m : wopt->members) {
        if (m.fingerprint == fp) return m;
    }

    return std::nullopt;
}

bool WorkspacesRegistry::add_or_update_member(const std::string& workspace_id,
                                              const WorkspaceMemberRec& in_member) {
    auto it = by_id_.find(workspace_id);
    if (it == by_id_.end()) return false;

    WorkspaceMemberRec m = in_member;
    normalize_workspace_member_v1(&m);
    if (m.fingerprint.empty()) return false;

    auto& members = it->second.members;
    for (auto& cur : members) {
        if (cur.fingerprint == m.fingerprint) {
            // Preserve original added_at/by if caller did not provide replacements.
            if (m.added_at.empty()) m.added_at = cur.added_at;
            if (m.added_by.empty()) m.added_by = cur.added_by;
            cur = std::move(m);
            std::sort(members.begin(), members.end(), member_fingerprint_less);
            return true;
        }
    }

    members.push_back(std::move(m));
    std::sort(members.begin(), members.end(), member_fingerprint_less);
    return true;
}

bool WorkspacesRegistry::remove_member(const std::string& workspace_id,
                                       const std::string& fingerprint) {
    auto it = by_id_.find(workspace_id);
    if (it == by_id_.end()) return false;

    auto& members = it->second.members;
    const std::string fp = trim_copy_safe(fingerprint);

    const auto old_size = members.size();
    members.erase(
        std::remove_if(members.begin(), members.end(),
                       [&](const WorkspaceMemberRec& m) { return m.fingerprint == fp; }),
        members.end());

    return members.size() != old_size;
}

bool WorkspacesRegistry::set_member_role(const std::string& workspace_id,
                                         const std::string& fingerprint,
                                         const std::string& role) {
    auto it = by_id_.find(workspace_id);
    if (it == by_id_.end()) return false;

    const std::string fp = trim_copy_safe(fingerprint);
    for (auto& m : it->second.members) {
        if (m.fingerprint == fp) {
            m.role = normalize_workspace_role_copy(role);
            return true;
        }
    }

    return false;
}

bool WorkspacesRegistry::has_enabled_owner(const std::string& workspace_id) const {
    auto wopt = get(workspace_id);
    if (!wopt.has_value()) return false;

    for (const auto& m : wopt->members) {
        if (m.status == "enabled" && m.role == "owner") return true;
    }

    return false;
}

std::size_t WorkspacesRegistry::enabled_member_count(const std::string& workspace_id) const {
    auto wopt = get(workspace_id);
    if (!wopt.has_value()) return 0;

    std::size_t n = 0;
    for (const auto& m : wopt->members) {
        if (m.status == "enabled") ++n;
    }
    return n;
}

} // namespace pqnas