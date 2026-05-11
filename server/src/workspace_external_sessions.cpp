#include "workspace_external_sessions.h"

#include "workspaces.h"

#include <cctype>
#include <random>

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

} // namespace

bool is_valid_workspace_external_session_id(const std::string& session_id) {
    const std::string v = trim_copy_safe(session_id);

    if (v.size() < 8 || v.size() > 128) return false;
    if (v.rfind("wes_", 0) != 0) return false;

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

std::string new_workspace_external_session_id() {
    return "wes_" + random_urlsafe_token(18);
}

std::string normalize_workspace_external_session_status_copy(const std::string& s) {
    const std::string v = lower_ascii_copy(trim_copy_safe(s));

    if (v == "approved") return "approved";
    if (v == "denied") return "denied";
    if (v == "expired") return "expired";
    if (v == "consumed") return "consumed";

    return "pending";
}

void normalize_workspace_external_session_rec_v1(WorkspaceExternalSessionRec* r) {
    if (!r) return;

    r->session_id = trim_copy_safe(r->session_id);
    r->workspace_id = trim_copy_safe(r->workspace_id);
    r->st_hash_b64 = trim_copy_safe(r->st_hash_b64);
    r->st_token = trim_copy_safe(r->st_token);

    r->status = normalize_workspace_external_session_status_copy(r->status);
    r->reason = trim_copy_safe(r->reason);

    r->approved_fingerprint = trim_copy_safe(r->approved_fingerprint);
    r->workspace_role = normalize_workspace_role_copy(r->workspace_role);
    r->created_at = trim_copy_safe(r->created_at);
    r->approved_at = trim_copy_safe(r->approved_at);

    if (r->status == "pending") {
        r->reason.clear();
        r->approved_fingerprint.clear();
        r->approved_at.clear();
        r->workspace_role.clear();
    }

    if (r->status == "approved" && r->approved_fingerprint.empty()) {
        r->status = "pending";
        r->workspace_role.clear();
        r->approved_at.clear();
    }
}

bool WorkspaceExternalSessionsStore::upsert(const WorkspaceExternalSessionRec& rec) {
    WorkspaceExternalSessionRec r = rec;
    normalize_workspace_external_session_rec_v1(&r);

    if (!is_valid_workspace_external_session_id(r.session_id)) return false;
    if (!is_valid_workspace_id(r.workspace_id)) return false;
    if (r.st_hash_b64.empty()) return false;
    if (r.st_token.empty()) return false;

    std::lock_guard<std::mutex> lk(mu_);
    by_id_[r.session_id] = std::move(r);
    return true;
}

std::optional<WorkspaceExternalSessionRec> WorkspaceExternalSessionsStore::get(
    const std::string& session_id) const {

    const std::string id = trim_copy_safe(session_id);
    std::lock_guard<std::mutex> lk(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return std::nullopt;

    return it->second;
}

std::optional<WorkspaceExternalSessionRec> WorkspaceExternalSessionsStore::get_by_st_hash_b64(
    const std::string& st_hash_b64) const {

    const std::string want = trim_copy_safe(st_hash_b64);
    if (want.empty()) return std::nullopt;

    std::lock_guard<std::mutex> lk(mu_);

    for (const auto& kv : by_id_) {
        if (kv.second.st_hash_b64 == want) return kv.second;
    }

    return std::nullopt;
}

std::optional<WorkspaceExternalSessionRec> WorkspaceExternalSessionsStore::consume_approved(
    const std::string& session_id,
    long now_epoch) {

    const std::string id = trim_copy_safe(session_id);
    if (id.empty()) return std::nullopt;

    std::lock_guard<std::mutex> lk(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return std::nullopt;

    WorkspaceExternalSessionRec& r = it->second;

    if (r.status != "approved") return std::nullopt;

    if (r.expires_at_epoch > 0 && now_epoch > r.expires_at_epoch) {
        r.status = "expired";
        r.reason = "expired";
        return std::nullopt;
    }

    if (r.approved_fingerprint.empty() || r.workspace_role.empty()) {
        return std::nullopt;
    }

    r.status = "consumed";
    return r;
}

bool WorkspaceExternalSessionsStore::mark_approved(const std::string& session_id,
                                                   const std::string& fingerprint,
                                                   const std::string& workspace_role,
                                                   const std::string& approved_at) {
    const std::string id = trim_copy_safe(session_id);
    const std::string fp = trim_copy_safe(fingerprint);

    if (id.empty() || fp.empty()) return false;

    std::lock_guard<std::mutex> lk(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return false;

    WorkspaceExternalSessionRec& r = it->second;
    if (r.status != "pending") return false;

    r.status = "approved";
    r.reason.clear();
    r.approved_fingerprint = fp;
    r.workspace_role = normalize_workspace_role_copy(workspace_role);
    r.approved_at = trim_copy_safe(approved_at);

    return true;
}

bool WorkspaceExternalSessionsStore::mark_denied(const std::string& session_id,
                                                 const std::string& reason) {
    const std::string id = trim_copy_safe(session_id);
    if (id.empty()) return false;

    std::lock_guard<std::mutex> lk(mu_);

    auto it = by_id_.find(id);
    if (it == by_id_.end()) return false;

    WorkspaceExternalSessionRec& r = it->second;
    if (r.status != "pending") return false;

    r.status = "denied";
    r.reason = trim_copy_safe(reason);

    return true;
}

std::size_t WorkspaceExternalSessionsStore::mark_expired_pending(long now_epoch) {
    std::lock_guard<std::mutex> lk(mu_);

    std::size_t changed = 0;

    for (auto& kv : by_id_) {
        WorkspaceExternalSessionRec& r = kv.second;

        if (r.status != "pending") continue;
        if (r.expires_at_epoch <= 0) continue;
        if (now_epoch <= r.expires_at_epoch) continue;

        r.status = "expired";
        r.reason = "expired";
        ++changed;
    }

    return changed;
}

std::size_t WorkspaceExternalSessionsStore::evict_terminal_older_than(
    long now_epoch,
    long max_age_seconds) {

    if (now_epoch <= 0) return 0;
    if (max_age_seconds < 60) max_age_seconds = 60;

    std::lock_guard<std::mutex> lk(mu_);

    std::size_t removed = 0;

    for (auto it = by_id_.begin(); it != by_id_.end(); ) {
        const WorkspaceExternalSessionRec& r = it->second;

        const bool terminal =
            r.status == "consumed" ||
            r.status == "denied" ||
            r.status == "expired";

        if (!terminal || r.expires_at_epoch <= 0) {
            ++it;
            continue;
        }

        if (now_epoch > r.expires_at_epoch + max_age_seconds) {
            it = by_id_.erase(it);
            ++removed;
            continue;
        }

        ++it;
    }

    return removed;
}

} // namespace pqnas
