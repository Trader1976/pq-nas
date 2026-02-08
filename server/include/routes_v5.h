#pragma once
#include <httplib.h>

#include <array>
#include <functional>
#include <string>
#include <nlohmann/json.hpp>
#include <map>

// Forward decls (these types already exist in your codebase)
namespace pqnas {
class Allowlist;
class UsersRegistry;
struct VerifyV4Config;
} // namespace pqnas

// NOTE: We keep context small and “pluggable” so routes_v5.cc does not
// depend on main.cpp internals except through these callbacks/refs.
struct RoutesV5Context {
    // config strings (owned by main.cpp)
    const std::string* origin = nullptr;   // ORIGIN
    const std::string* rp_id  = nullptr;   // RP_ID
    const std::string* app    = nullptr;   // APP_NAME

    // TTLs (owned by main.cpp)
    const int*  req_ttl  = nullptr;        // REQ_TTL
    const int*  sess_ttl = nullptr;        // SESS_TTL

    // keys (owned by main.cpp)
    const unsigned char* server_pk = nullptr;  // 32 bytes
    const unsigned char* server_sk = nullptr;  // 64 bytes
    const unsigned char* cookie_key = nullptr; // whatever size you use internally

    // registries (owned by main.cpp)
    pqnas::Allowlist*    allowlist = nullptr;
    pqnas::UsersRegistry* users    = nullptr;

    // paths (owned by main.cpp)
    const std::string* allowlist_path = nullptr;
    const std::string* users_path     = nullptr;

    // ---- callbacks into your existing helpers (defined in main.cpp today) ----
    std::function<long()> now_epoch;
    std::function<std::string()> now_iso_utc;

    std::function<std::string(int)> random_b64url;  // len -> string
    std::function<std::string(const std::string&)> url_encode;

    std::function<std::string(const std::string& sid,
                              const std::string& chal,
                              const std::string& nonce,
                              long issued_at,
                              long expires_at)> build_req_payload_canonical;

    std::function<std::string(const std::string& payload)> sign_req_token;

    std::function<std::string(const std::string& text, int scale, int border)> qr_svg_from_text;

    // NEW: compute the v5 correlation key (k) from st token.
    // Must match verify_login_common.cc v5 approval_key: vr.st_hash_b64
    //
    // If nullptr/unset, v5 session will still work in legacy sid-mode (not stateless-ready).
    std::function<std::string(const std::string& st_token)> st_hash_b64_from_st;

    // approvals / pending maps
    struct ApprovalEntry { std::string cookie_val; std::string fingerprint; long expires_at = 0; };
    struct PendingEntry  { long expires_at = 0; std::string reason; };

    std::function<void(long now)> approvals_prune;
    std::function<void(long now)> pending_prune;

    std::function<bool(const std::string& sid, ApprovalEntry& out)> approvals_get;
    std::function<void(const std::string& sid, const ApprovalEntry& e)> approvals_put;
    std::function<void(const std::string& sid)> approvals_pop;

    std::function<bool(const std::string& sid, PendingEntry& out)> pending_get;
    std::function<void(const std::string& sid, const PendingEntry& e)> pending_put;
    std::function<void(const std::string& sid)> pending_pop;

    // cookie minting
    std::function<bool(const unsigned char* cookie_key,
                       const std::string& fp_b64,
                       long iat,
                       long exp,
                       std::string& out_cookie_val)> session_cookie_mint;

    // base64 helpers (your pqnas::b64_std etc.)
    std::function<std::string(const unsigned char* data, size_t len)> b64_std;

    // audit
    std::function<std::string(const httplib::Request&)> client_ip;
    std::function<std::string(const std::string&, size_t)> shorten;
    std::function<void(const std::string& event,
                       const std::string& outcome,
                       const std::function<void(std::map<std::string,std::string>&)>& fill_fields)> audit_emit;

    // v4 verifier (we reuse it for v5 “phase 1”)
    enum class VerifyRc {
        OK = 0,
        ST_EXPIRED,
        RP_ID_HASH_MISMATCH,
        FINGERPRINT_MISMATCH,
        PQ_SIG_INVALID,
        POLICY_DENY,
        OTHER
    };

    struct VerifyResult {
        bool ok = false;
        VerifyRc rc = VerifyRc::OTHER;
        std::string detail;

        std::string sid;
        std::string origin;
        std::string rp_id_hash;
        std::string st_hash_b64;
        std::string fingerprint_hex;
    };

    std::function<VerifyResult(const std::string& body)> verify_v4_json;
    std::function<std::string(const nlohmann::json&, const unsigned char* /*SERVER_SK*/)> sign_token_v4_ed25519;
};

void register_routes_v5(httplib::Server& srv, const RoutesV5Context& ctx);
