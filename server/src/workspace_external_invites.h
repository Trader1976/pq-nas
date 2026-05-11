#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace pqnas {

struct WorkspaceExternalInviteRec {
    std::string invite_id;            // wsi_xxx
    std::string workspace_id;         // ws_xxx
    std::string st_hash_b64;          // v5 auth correlation key
    std::string st_token;             // pending invite QR token; cleared after accept/revoke/expire if desired

    std::string role;                 // viewer | editor
    std::string status;               // pending | accepted | revoked | expired

    std::string created_by;           // workspace owner fingerprint
    std::string created_at;
    long expires_at_epoch = 0;

    std::string accepted_fingerprint; // verified DNA Connect fingerprint
    std::string accepted_at;
};

std::string normalize_workspace_external_invite_role_copy(const std::string& s);
std::string normalize_workspace_external_invite_status_copy(const std::string& s);

void normalize_workspace_external_invite_rec_v1(WorkspaceExternalInviteRec* r);

WorkspaceExternalInviteRec workspace_external_invite_from_json_v1(const nlohmann::json& j);
nlohmann::json workspace_external_invite_to_json_v1(const WorkspaceExternalInviteRec& r);

bool is_valid_workspace_external_invite_id(const std::string& invite_id);
std::string new_workspace_external_invite_id();

class WorkspaceExternalInvitesRegistry {
public:
    bool load(const std::string& path);
    bool save(const std::string& path) const;

    bool exists(const std::string& invite_id) const;
    std::optional<WorkspaceExternalInviteRec> get(const std::string& invite_id) const;
    std::optional<WorkspaceExternalInviteRec> get_by_st_hash_b64(const std::string& st_hash_b64) const;

    bool upsert(const WorkspaceExternalInviteRec& rec);
    bool erase(const std::string& invite_id);

    bool mark_accepted(const std::string& invite_id,
                       const std::string& fingerprint,
                       const std::string& accepted_at);

    bool mark_revoked(const std::string& invite_id);

    // Marks expired pending invites as expired. Returns number changed.
    std::size_t mark_expired_pending(long now_epoch);

    std::map<std::string, WorkspaceExternalInviteRec> snapshot() const;

private:
    mutable std::mutex mu_;
    std::map<std::string, WorkspaceExternalInviteRec> by_id_;
};

} // namespace pqnas
