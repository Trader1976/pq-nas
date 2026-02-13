#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <functional>
#include <map>
#include <string>

namespace pqnas {
class Allowlist;
class UsersRegistry;
}

struct VerifyLoginCommonContext {
    // Required config
    const std::string* origin = nullptr;  // ORIGIN
    const std::string* rp_id  = nullptr;  // RP_ID

    const unsigned char* server_pk = nullptr; // 32
    const unsigned char* server_sk = nullptr; // ed25519 secret (whatever your sign_token uses)
    const unsigned char* cookie_key = nullptr;

    const int* sess_ttl = nullptr;

    // policy + users
    pqnas::Allowlist* allowlist = nullptr;
    pqnas::UsersRegistry* users = nullptr;
    const std::string* allowlist_path = nullptr;
    const std::string* users_path = nullptr;

    // approvals/pending maps
    //
    // NOTE ABOUT KEYING:
    // - v4 legacy: key is usually vr.sid
    // - v5 stateless-ready: key should be vr.st_hash_b64 (derived from signed st)
    //
    // This handler will decide the key based on api_version and store/read under that key.
    struct ApprovalEntry { std::string cookie_val; std::string fingerprint; long expires_at = 0; };
    struct PendingEntry  { long expires_at = 0; std::string reason; };

    std::function<void(long)> approvals_prune;
    std::function<bool(const std::string& /*key*/, ApprovalEntry&)> approvals_get;
    std::function<void(const std::string& /*key*/, const ApprovalEntry&)> approvals_put;
    std::function<void(const std::string& /*key*/)> approvals_pop;

    std::function<void(long)> pending_prune;
    std::function<bool(const std::string& /*key*/, PendingEntry&)> pending_get;
    std::function<void(const std::string& /*key*/, const PendingEntry&)> pending_put;
    std::function<void(const std::string& /*key*/)> pending_pop;

    // time + helpers
    std::function<long()> now_epoch;
    std::function<std::string()> now_iso_utc;

    std::function<std::string(const httplib::Request&)> client_ip;
    std::function<std::string(const std::string&, size_t)> shorten;

    // crypto/minting hooks (you already have these)
    std::function<std::string(const nlohmann::json&, const unsigned char* /*SERVER_SK*/)> sign_token_v4_ed25519;

    std::function<bool(const unsigned char* key,
                       const std::string& fp_b64,
                       long iat,
                       long exp,
                       std::string& out_cookie)> session_cookie_mint;

    std::function<std::string(const unsigned char* data, size_t len)> b64_std;

    // audit (simple generic emitter)
    std::function<void(const std::string& event,
                       const std::string& outcome,
                       const std::function<void(std::map<std::string,std::string>&)>& fill)> audit_emit;
};

// Shared handler used by both /api/v4/verify and /api/v5/verify
void handle_verify_login_common(const httplib::Request& req,
                               httplib::Response& res,
                               int api_version, // 4 or 5 (route version)
                               const VerifyLoginCommonContext& ctx);
