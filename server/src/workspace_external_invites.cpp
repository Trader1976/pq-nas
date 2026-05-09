#include "workspace_external_invites.h"

#include "workspaces.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <random>
#include <set>
#include <system_error>

namespace pqnas {
namespace {

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
    const std::filesystem::path p(path);
    const std::filesystem::path dir = p.parent_path();

    std::error_code ec;
    if (!dir.empty()) {
        std::filesystem::create_directories(dir, ec);
        if (ec) return false;
    }

    const std::filesystem::path tmp = dir / (p.filename().string() + ".tmp.external_invites");

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;

        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.close();

        if (!f) {
            std::filesystem::remove(tmp, ec);
            return false;
        }
    }

    std::filesystem::rename(tmp, p, ec);
    if (!ec) return true;

    std::filesystem::remove(p, ec);
    ec.clear();

    std::filesystem::rename(tmp, p, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        return false;
    }

    return true;
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

void ensure_workspace_external_invites_cfg_shape_v1(nlohmann::json* cfg) {
    if (!cfg || !cfg->is_object()) {
        if (cfg) *cfg = nlohmann::json::object();
        return;
    }

    if (!cfg->contains("external_invites") || !(*cfg)["external_invites"].is_array()) {
        (*cfg)["external_invites"] = nlohmann::json::array();
    }

    nlohmann::json out = nlohmann::json::array();
    std::set<std::string> seen_ids;

    for (const auto& one : (*cfg)["external_invites"]) {
        WorkspaceExternalInviteRec r = workspace_external_invite_from_json_v1(one);

        if (!is_valid_workspace_external_invite_id(r.invite_id)) continue;
        if (!is_valid_workspace_id(r.workspace_id)) continue;
        if (!seen_ids.insert(r.invite_id).second) continue;

        out.push_back(workspace_external_invite_to_json_v1(r));
    }

    (*cfg)["version"] = 1;
    (*cfg)["external_invites"] = std::move(out);
}

} // namespace

std::string normalize_workspace_external_invite_role_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));
    if (v == "editor") return "editor";
    return "viewer";
}

std::string normalize_workspace_external_invite_status_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));

    if (v == "accepted") return "accepted";
    if (v == "revoked") return "revoked";
    if (v == "expired") return "expired";

    return "pending";
}

void normalize_workspace_external_invite_rec_v1(WorkspaceExternalInviteRec* r) {
    if (!r) return;

    r->invite_id = trim_copy_safe(r->invite_id);
    r->workspace_id = trim_copy_safe(r->workspace_id);
    r->st_hash_b64 = trim_copy_safe(r->st_hash_b64);
    r->st_token = trim_copy_safe(r->st_token);

    r->role = normalize_workspace_external_invite_role_copy(r->role);
    r->status = normalize_workspace_external_invite_status_copy(r->status);

    r->created_by = trim_copy_safe(r->created_by);
    r->created_at = trim_copy_safe(r->created_at);

    r->accepted_fingerprint = trim_copy_safe(r->accepted_fingerprint);
    r->accepted_at = trim_copy_safe(r->accepted_at);

    if (r->status == "pending") {
        r->accepted_fingerprint.clear();
        r->accepted_at.clear();
    }

    if (r->status == "accepted" && r->accepted_fingerprint.empty()) {
        r->status = "pending";
    }
}

WorkspaceExternalInviteRec workspace_external_invite_from_json_v1(const nlohmann::json& j) {
    WorkspaceExternalInviteRec r;

    if (!j.is_object()) {
        normalize_workspace_external_invite_rec_v1(&r);
        return r;
    }

    r.invite_id = j.value("invite_id", "");
    r.workspace_id = j.value("workspace_id", "");
    r.st_hash_b64 = j.value("st_hash_b64", "");
    r.st_token = j.value("st_token", "");

    r.role = j.value("role", "viewer");
    r.status = j.value("status", "pending");

    r.created_by = j.value("created_by", "");
    r.created_at = j.value("created_at", "");

    try {
        if (j.contains("expires_at_epoch")) {
            if (j["expires_at_epoch"].is_number_integer()) {
                r.expires_at_epoch = j["expires_at_epoch"].get<long>();
            } else if (j["expires_at_epoch"].is_number_unsigned()) {
                const auto v = j["expires_at_epoch"].get<unsigned long long>();
                r.expires_at_epoch = static_cast<long>(v);
            }
        }
    } catch (...) {
        r.expires_at_epoch = 0;
    }

    r.accepted_fingerprint = j.value("accepted_fingerprint", "");
    r.accepted_at = j.value("accepted_at", "");

    normalize_workspace_external_invite_rec_v1(&r);
    return r;
}

nlohmann::json workspace_external_invite_to_json_v1(const WorkspaceExternalInviteRec& in_r) {
    WorkspaceExternalInviteRec r = in_r;
    normalize_workspace_external_invite_rec_v1(&r);

    return nlohmann::json{
        {"invite_id", r.invite_id},
        {"workspace_id", r.workspace_id},
        {"st_hash_b64", r.st_hash_b64},
        {"st_token", r.st_token},
        {"role", r.role},
        {"status", r.status},
        {"created_by", r.created_by},
        {"created_at", r.created_at},
        {"expires_at_epoch", r.expires_at_epoch},
        {"accepted_fingerprint", r.accepted_fingerprint},
        {"accepted_at", r.accepted_at}
    };
}

bool is_valid_workspace_external_invite_id(const std::string& invite_id) {
    const std::string v = trim_copy_safe(invite_id);

    if (v.size() < 8 || v.size() > 128) return false;
    if (v.rfind("wsi_", 0) != 0) return false;

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

std::string new_workspace_external_invite_id() {
    return "wsi_" + random_urlsafe_token(18);
}

bool WorkspaceExternalInvitesRegistry::load(const std::string& path) {
    by_id_.clear();

    std::string txt;
    nlohmann::json cfg = nlohmann::json::object();

    if (read_text_file(path, &txt)) {
        try {
            cfg = nlohmann::json::parse(txt);
        } catch (...) {
            cfg = nlohmann::json::object();
        }
    }

    if (!cfg.is_object()) cfg = nlohmann::json::object();
    ensure_workspace_external_invites_cfg_shape_v1(&cfg);

    if (cfg.contains("external_invites") && cfg["external_invites"].is_array()) {
        for (const auto& one : cfg["external_invites"]) {
            WorkspaceExternalInviteRec r = workspace_external_invite_from_json_v1(one);

            if (!is_valid_workspace_external_invite_id(r.invite_id)) continue;
            if (!is_valid_workspace_id(r.workspace_id)) continue;

            by_id_[r.invite_id] = std::move(r);
        }
    }

    return true;
}

bool WorkspaceExternalInvitesRegistry::save(const std::string& path) const {
    nlohmann::json cfg = nlohmann::json::object();
    cfg["version"] = 1;
    cfg["external_invites"] = nlohmann::json::array();

    for (const auto& kv : by_id_) {
        cfg["external_invites"].push_back(workspace_external_invite_to_json_v1(kv.second));
    }

    ensure_workspace_external_invites_cfg_shape_v1(&cfg);
    return write_text_file_atomic_raw(path, cfg.dump(2) + "\n");
}

bool WorkspaceExternalInvitesRegistry::exists(const std::string& invite_id) const {
    return by_id_.find(trim_copy_safe(invite_id)) != by_id_.end();
}

std::optional<WorkspaceExternalInviteRec> WorkspaceExternalInvitesRegistry::get(
    const std::string& invite_id) const {

    auto it = by_id_.find(trim_copy_safe(invite_id));
    if (it == by_id_.end()) return std::nullopt;

    return it->second;
}

std::optional<WorkspaceExternalInviteRec> WorkspaceExternalInvitesRegistry::get_by_st_hash_b64(
    const std::string& st_hash_b64) const {

    const std::string want = trim_copy_safe(st_hash_b64);
    if (want.empty()) return std::nullopt;

    for (const auto& kv : by_id_) {
        if (kv.second.st_hash_b64 == want) return kv.second;
    }

    return std::nullopt;
}

bool WorkspaceExternalInvitesRegistry::upsert(const WorkspaceExternalInviteRec& rec) {
    WorkspaceExternalInviteRec r = rec;
    normalize_workspace_external_invite_rec_v1(&r);

    if (!is_valid_workspace_external_invite_id(r.invite_id)) return false;
    if (!is_valid_workspace_id(r.workspace_id)) return false;
    if (r.st_hash_b64.empty()) return false;

    by_id_[r.invite_id] = std::move(r);
    return true;
}

bool WorkspaceExternalInvitesRegistry::erase(const std::string& invite_id) {
    return by_id_.erase(trim_copy_safe(invite_id)) > 0;
}

bool WorkspaceExternalInvitesRegistry::mark_accepted(const std::string& invite_id,
                                                     const std::string& fingerprint,
                                                     const std::string& accepted_at) {
    auto it = by_id_.find(trim_copy_safe(invite_id));
    if (it == by_id_.end()) return false;

    WorkspaceExternalInviteRec& r = it->second;

    if (r.status != "pending") return false;

    const std::string fp = trim_copy_safe(fingerprint);
    if (fp.empty()) return false;

    r.status = "accepted";
    r.accepted_fingerprint = fp;
    r.accepted_at = trim_copy_safe(accepted_at);

    return true;
}

bool WorkspaceExternalInvitesRegistry::mark_revoked(const std::string& invite_id) {
    auto it = by_id_.find(trim_copy_safe(invite_id));
    if (it == by_id_.end()) return false;

    if (it->second.status == "accepted") return false;

    it->second.status = "revoked";
    return true;
}

std::size_t WorkspaceExternalInvitesRegistry::mark_expired_pending(long now_epoch) {
    std::size_t changed = 0;

    for (auto& kv : by_id_) {
        WorkspaceExternalInviteRec& r = kv.second;

        if (r.status != "pending") continue;
        if (r.expires_at_epoch <= 0) continue;
        if (now_epoch <= r.expires_at_epoch) continue;

        r.status = "expired";
        ++changed;
    }

    return changed;
}

const std::map<std::string, WorkspaceExternalInviteRec>&
WorkspaceExternalInvitesRegistry::snapshot() const {
    return by_id_;
}

} // namespace pqnas
