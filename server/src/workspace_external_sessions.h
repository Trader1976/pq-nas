#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace pqnas {

struct WorkspaceExternalSessionRec {
    std::string session_id;            // wes_xxx
    std::string workspace_id;          // ws_xxx
    std::string st_hash_b64;           // v5 auth correlation key
    std::string st_token;              // QR token

    std::string status;                // pending | approved | consumed | denied | expired
    std::string reason;

    std::string approved_fingerprint;
    std::string workspace_role;
    std::string created_at;
    std::string approved_at;

    long expires_at_epoch = 0;
};

bool is_valid_workspace_external_session_id(const std::string& session_id);
std::string new_workspace_external_session_id();

std::string normalize_workspace_external_session_status_copy(const std::string& s);
void normalize_workspace_external_session_rec_v1(WorkspaceExternalSessionRec* r);

class WorkspaceExternalSessionsStore {
public:
    bool upsert(const WorkspaceExternalSessionRec& rec);

    std::optional<WorkspaceExternalSessionRec> get(const std::string& session_id) const;
    std::optional<WorkspaceExternalSessionRec> get_by_st_hash_b64(const std::string& st_hash_b64) const;

    std::optional<WorkspaceExternalSessionRec> consume_approved(
        const std::string& session_id,
        long now_epoch);

    bool mark_approved(const std::string& session_id,
                       const std::string& fingerprint,
                       const std::string& workspace_role,
                       const std::string& approved_at);

    bool mark_denied(const std::string& session_id,
                     const std::string& reason);

    std::size_t mark_expired_pending(long now_epoch);

private:
    mutable std::mutex mu_;
    std::map<std::string, WorkspaceExternalSessionRec> by_id_;
};

} // namespace pqnas
