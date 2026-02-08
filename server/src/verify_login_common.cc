#include "verify_login_common.h"

#include "allowlist.h"
#include "users_registry.h"

#include "v4_verify_shared.h"
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <mutex>

using nlohmann::json;

static void reply_json(httplib::Response& res, int code, const std::string& body) {
    res.status = code;
    res.set_header("Content-Type", "application/json; charset=utf-8");
    res.set_header("Cache-Control", "no-store");
    res.body = body;
}

static std::string hdr(const httplib::Request& req, const char* key) {
    auto it = req.headers.find(key);
    return (it == req.headers.end()) ? "" : it->second;
}

void handle_verify_login_common(const httplib::Request& req,
                               httplib::Response& res,
                               int api_version,
                               const VerifyLoginCommonContext& ctx) {
    auto fail = [&](int code, const std::string& msg, const std::string& detail = "") {
        json out = {
            {"ok", false},
            {"error", (code == 400 ? "bad_request" : "not_authorized")},
            {"message", msg}
        };
        if (api_version == 5) out["v"] = 5;
        if (!detail.empty()) out["detail"] = detail;
        reply_json(res, code, out.dump());
    };

    // --- audit context (filled after verify_v4_json) ---
    std::string audit_sid;
    std::string audit_st_hash_b64;
    std::string audit_origin;
    std::string audit_rp_id_hash;
    std::string audit_fp;

    auto ua_short = [&]() -> std::string {
        const std::string ua = hdr(req, "User-Agent");
        return ctx.shorten ? ctx.shorten(ua, 120) : ua;
    };

    auto audit_fail = [&](const std::string& reason, const std::string& detail = "") {
        if (!ctx.audit_emit) return;
        ctx.audit_emit((api_version == 5 ? "v5.verify_fail" : "v4.verify_fail"), "fail",
                       [&](std::map<std::string,std::string>& f) {
            if (!audit_sid.empty()) f["sid"] = audit_sid;
            if (!audit_st_hash_b64.empty()) f["st_hash_b64"] = audit_st_hash_b64;
            if (!audit_origin.empty()) f["origin"] = audit_origin;
            if (!audit_rp_id_hash.empty()) f["rp_id_hash"] = audit_rp_id_hash;
            if (!audit_fp.empty()) f["fingerprint"] = audit_fp;

            f["reason"] = reason;
            if (!detail.empty()) f["detail"] = ctx.shorten ? ctx.shorten(detail, 180) : detail;

            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            const std::string cfip = hdr(req, "CF-Connecting-IP");
            if (!cfip.empty()) f["cf_ip"] = cfip;

            const std::string xff = hdr(req, "X-Forwarded-For");
            if (!xff.empty()) f["xff"] = ctx.shorten ? ctx.shorten(xff, 120) : xff;

            f["ua"] = ua_short();
        });
    };

    auto audit_info = [&](const std::string& event, const std::string& outcome,
                          const std::string& reason = "", const std::string& detail = "") {
        if (!ctx.audit_emit) return;
        ctx.audit_emit(event, outcome, [&](std::map<std::string,std::string>& f) {
            if (!audit_sid.empty()) f["sid"] = audit_sid;
            if (!audit_st_hash_b64.empty()) f["st_hash_b64"] = audit_st_hash_b64;
            if (!audit_origin.empty()) f["origin"] = audit_origin;
            if (!audit_rp_id_hash.empty()) f["rp_id_hash"] = audit_rp_id_hash;
            if (!audit_fp.empty()) f["fingerprint"] = audit_fp;

            if (!reason.empty()) f["reason"] = reason;
            if (!detail.empty()) f["detail"] = ctx.shorten ? ctx.shorten(detail, 180) : detail;

            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            const std::string cfip = hdr(req, "CF-Connecting-IP");
            if (!cfip.empty()) f["cf_ip"] = cfip;

            const std::string xff = hdr(req, "X-Forwarded-For");
            if (!xff.empty()) f["xff"] = ctx.shorten ? ctx.shorten(xff, 120) : xff;

            f["ua"] = ua_short();
        });
    };

    try {
        // ---- shared verification (crypto + bindings) ----
        pqnas::VerifyV4Config cfg;
        cfg.now_unix_sec = 0;
        cfg.expected_origin = ctx.origin ? *ctx.origin : "";
        cfg.expected_rp_id  = ctx.rp_id  ? *ctx.rp_id  : "";
        cfg.enforce_allowlist = false; // enforce after we know fingerprint

        std::array<unsigned char, 32> server_pk{};
        if (!ctx.server_pk) return fail(500, "server misconfigured", "missing server_pk");
        std::memcpy(server_pk.data(), ctx.server_pk, 32);

        auto vr = pqnas::verify_v4_json(req.body, server_pk, cfg);

        audit_sid         = vr.sid;
        audit_origin      = vr.origin;
        audit_rp_id_hash  = vr.rp_id_hash;
        audit_st_hash_b64 = vr.st_hash_b64;
        audit_fp          = vr.fingerprint_hex;

        if (!vr.ok) {
            int http = 400;
            switch (vr.rc) {
                case pqnas::VerifyV4Rc::ST_EXPIRED: http = 410; break;
                case pqnas::VerifyV4Rc::RP_ID_HASH_MISMATCH:
                case pqnas::VerifyV4Rc::FINGERPRINT_MISMATCH:
                case pqnas::VerifyV4Rc::PQ_SIG_INVALID:
                case pqnas::VerifyV4Rc::POLICY_DENY:
                    http = 403; break;
                default: http = 400; break;
            }

            audit_fail(std::string("v4_shared_rc_") + std::to_string((int)vr.rc), vr.detail);
            if (http == 410) return fail(410, "st expired");
            return fail(http, "verify failed", vr.detail);
        }

        const bool vectors_mode = (std::getenv("PQNAS_V4_VECTORS") != nullptr);
        const long at_ttl = vectors_mode ? (10L * 365 * 24 * 3600) : 60L;

        const long now = ctx.now_epoch ? ctx.now_epoch() : 0;

        const std::string& st_hash     = vr.st_hash_b64;
        const std::string& computed_fp = vr.fingerprint_hex;

        // ---- approval key selection (v5: stateless-ready key) ----
        //
        // v4 legacy uses vr.sid (session id).
        // v5 should NOT rely on sid; key off st_hash_b64 (derived from signed st).
        const std::string approval_key = (api_version == 5) ? st_hash : vr.sid;
        if (approval_key.empty()) {
            audit_fail("missing_approval_key");
            return fail(400, "verify failed", "missing approval key");
        }

        // Bootstrap: first verified fingerprint becomes admin if fresh install
        {
            static std::mutex bootstrap_mu;
            std::lock_guard<std::mutex> lk(bootstrap_mu);

            const bool no_users = (ctx.users && ctx.users->snapshot().empty());
            const bool no_policy_users = (ctx.allowlist && ctx.allowlist->empty());

            if (no_users && no_policy_users && ctx.users && ctx.allowlist && ctx.users_path && ctx.allowlist_path) {
                const std::string now_iso = ctx.now_iso_utc ? ctx.now_iso_utc() : "";

                ctx.users->ensure_present_disabled_user(computed_fp, now_iso);
                ctx.users->set_role(computed_fp, "admin");
                ctx.users->set_status(computed_fp, "enabled");
                ctx.users->save(*ctx.users_path);

                ctx.allowlist->add_admin(computed_fp);
                ctx.allowlist->save(*ctx.allowlist_path);

                audit_info((api_version == 5 ? "v5.bootstrap_first_admin" : "v4.bootstrap_first_admin"), "ok");
            }
        }

        // ---- Users registry policy (fail-closed) ----
        const std::string now_iso = ctx.now_iso_utc ? ctx.now_iso_utc() : "";

        if (!ctx.users || !ctx.users_path) {
            audit_fail("server_misconfig_users");
            return fail(500, "server misconfigured");
        }

        // Unknown user => create disabled, mark pending, deny
        if (!ctx.users->exists(computed_fp)) {
            const bool created = ctx.users->ensure_present_disabled_user(computed_fp, now_iso);
            const bool saved   = created ? ctx.users->save(*ctx.users_path) : false;

            audit_info((api_version == 5 ? "v5.user_auto_created_disabled" : "v4.user_auto_created_disabled"),
                       "ok",
                       created ? "created" : "already_exists_race",
                       saved ? "" : "users_save_failed");

            if (ctx.pending_put) {
				VerifyLoginCommonContext::PendingEntry p;
				p.expires_at = now + 120;
				p.reason = "pending_admin";   // IMPORTANT
				ctx.pending_put(approval_key, p);
            }
            return fail(403, "user disabled");
        }

        if (!ctx.users->is_enabled_user(computed_fp)) {
            audit_info((api_version == 5 ? "v5.user_disabled" : "v4.user_disabled"), "fail", "not_enabled");

            if (ctx.pending_put) {
				VerifyLoginCommonContext::PendingEntry p;
				p.expires_at = now + 120;
				p.reason = "pending_admin";   // IMPORTANT
				ctx.pending_put(approval_key, p);
            }
            return fail(403, "user disabled");
        }

        // Update last_seen
        {
            const bool touched = ctx.users->touch_last_seen(computed_fp, now_iso);
            const bool saved   = touched ? ctx.users->save(*ctx.users_path) : false;

            if (touched && saved) {
                audit_info((api_version == 5 ? "v5.user_last_seen_updated" : "v4.user_last_seen_updated"), "ok");
            } else if (touched && !saved) {
                audit_info((api_version == 5 ? "v5.user_last_seen_updated" : "v4.user_last_seen_updated"),
                           "fail", "users_save_failed");
            } else {
                audit_info((api_version == 5 ? "v5.user_last_seen_updated" : "v4.user_last_seen_updated"),
                           "fail", "touch_failed");
            }
        }

        // ---- vectors logging ----
        if (vectors_mode) {
            std::cerr << "[v4_vectors] FP_HEX " << computed_fp
                      << " SID " << vr.sid
                      << " ST_HASH " << st_hash
                      << "\n";
            std::cerr << "[v4_vectors] CANON_SHA256_B64 " << vr.canonical_sha256_b64 << "\n";
        }

        // ---- mint AT (still v4 format in phase-1) ----
        if (!ctx.sign_token_v4_ed25519 || !ctx.server_sk) {
            audit_fail("server_misconfig_at");
            return fail(500, "server misconfigured");
        }

        json at_payload = {
            {"v", 4},
            {"typ","at"},
            {"sid", vr.sid},
            {"st_hash", st_hash},
            {"rp_id_hash", vr.rp_id_hash},
            {"fingerprint", computed_fp},
            {"issued_at", now},
            {"expires_at", now + at_ttl}
        };
        std::string at = ctx.sign_token_v4_ed25519(at_payload, ctx.server_sk);

        // ---- mint browser session cookie (stored for /consume) ----
        std::string cookieVal;
        const long sess_iat = now;
        const long sess_exp = now + (ctx.sess_ttl ? *ctx.sess_ttl : 3600);

        if (!ctx.b64_std || !ctx.session_cookie_mint || !ctx.cookie_key) {
            audit_fail("server_misconfig_cookie");
            return fail(500, "server misconfigured");
        }

        const std::string fp_b64 = ctx.b64_std(
            reinterpret_cast<const unsigned char*>(computed_fp.data()),
            computed_fp.size()
        );

        if (ctx.session_cookie_mint(ctx.cookie_key, fp_b64, sess_iat, sess_exp, cookieVal)) {
			if (ctx.audit_emit) {
    		ctx.audit_emit("debug.cookie_format", "ok", [&](std::map<std::string,std::string>& f) {
				f["cookie_has_path_root"] = (cookieVal.find("Path=/") != std::string::npos) ? "1" : "0";
				f["cookie_has_httponly"]  = (cookieVal.find("HttpOnly") != std::string::npos) ? "1" : "0";
				f["cookie_has_samesite"]  = (cookieVal.find("SameSite=") != std::string::npos) ? "1" : "0";

        		f["starts_with_set_cookie"] =
            		(cookieVal.rfind("Set-Cookie:", 0) == 0) ? "1" : "0";
        		f["cookie_len"] = std::to_string(cookieVal.size());
    		});
		}
            if (ctx.approvals_put) {
                VerifyLoginCommonContext::ApprovalEntry e;
                e.cookie_val  = cookieVal;
                e.fingerprint = computed_fp;
                e.expires_at  = now + 120;
                ctx.approvals_put(approval_key, e);
            }

            audit_info((api_version == 5 ? "v5.cookie_minted" : "v4.cookie_minted"), "ok");
        } else {
            audit_fail("cookie_mint_failed");
        }

        // ---- verify ok audit ----
        audit_info((api_version == 5 ? "v5.verify_ok" : "v4.verify_ok"), "ok");

        // Response version matches route version (v4 or v5), AT is still v4 in phase-1.
        //
        // For v5, include "k" (approval key) so the browser can poll/consume without sid.
        json out = {{"ok",true},{"v", api_version},{"at",at}};
        if (api_version == 5) {
            out["k"] = approval_key;        // stateless-ready correlation key (st_hash_b64)
            out["st_hash_b64"] = st_hash;   // redundant but useful for debugging
        }

        reply_json(res, 200, out.dump());
    }
    catch (const std::exception& e) {
        audit_fail("exception", e.what());
        return fail(400, "exception", e.what());
    }
}
