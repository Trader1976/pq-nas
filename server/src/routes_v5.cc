// server/src/routes_v5.cc
// routes_v5.cc
//
// v5 Stateless Login ("2A" flow) HTTP routes.
//
// Design goals
// - Stateless-ready correlation: clients can use `k = H(st)` (st_hash_b64) as the
//   primary lookup key. This avoids reliance on `sid` for v5.
// - Separation of concerns: this file is *transport + orchestration only*.
//   All crypto, token signing, storage, and auditing are delegated to callbacks
//   in RoutesV5Context (dependency injection).
// - Short-lived server-side state: the server keeps only minimal "pending" +
//   "approval" entries for UX and single-use consumption. These are pruned
//   aggressively by TTL to keep memory bounded.
//
// Flow summary
//   1) /api/v5/session
//      - Mint request token `st` (signed), return {sid, st, k, iat, exp, qr_svg}
//      - Insert PendingEntry keyed by `k` so status can immediately report "pending"
//   2) /api/v5/qr.svg
//      - Render QR containing dna://auth?v=5&st=...&origin=...&app=...
//   3) /api/v5/status (GET or POST)
//      - Resolve correlation key from {st|k|sid}
//      - Report {approved|pending|missing} with TTL metadata
//   4) /api/v5/consume
//      - Resolve correlation key from {st|k|sid}
//      - If approved, issue Set-Cookie(pqnas_session=...) and atomically consume
//        approval + pending entries (one-time use).
//
// Security notes
// - `st` is a signed request token. `k` is derived from st and is safe to expose.
// - `/consume` is intentionally strict: if approval exists but cookie is missing,
//   we fail loudly (500) because a partially-approved login is a server bug.
// - All JSON responses are no-store to avoid caching sensitive flow state.

#include "routes_v5.h"

#include <algorithm>
#include <stdexcept>

using nlohmann::json;


// Uniform JSON response helper:
// - forces application/json + no-store
// - caller provides already-serialized JSON string (avoids double-encoding)
static void reply_json(httplib::Response& res, int status, const std::string& body) {
    res.status = status;
    res.set_header("Content-Type", "application/json; charset=utf-8");
    res.set_header("Cache-Control", "no-store");
    res.body = body;
}


// Normalizes base64 values that arrive via URL/query decoding.
// Some stacks decode '+' as space in query parameters (application/x-www-form-urlencoded).
// We reverse that and trim surrounding whitespace to keep k parsing robust.
static std::string normalize_query_b64(std::string s) {
    // In URL query params, '+' often becomes ' ' after form-style decoding.
    // Our k is standard base64, so undo that when it happens.
    for (char& ch : s) {
        if (ch == ' ') ch = '+';
    }
    // also trim accidental surrounding whitespace
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r')) s.erase(s.begin());
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t' || s.back()  == '\n' || s.back()  == '\r')) s.pop_back();
    return s;
}


// Strictly parse request body as a JSON object. Returns false with a stable
// machine-readable error string for consistent 400 responses.
static bool parse_json_body(const httplib::Request& req, json& out, std::string& err) {
    try {
        if (req.body.empty()) { err = "empty_body"; return false; }
        out = json::parse(req.body);
        if (!out.is_object()) { err = "json_must_be_object"; return false; }
        return true;
    } catch (const std::exception& e) {
        err = std::string("json_parse_error: ") + e.what();
        return false;
    }
}

// Extract a correlation key from a JSON object:
// - If "k" is present, use it directly (normalized base64).
// - Else if "st" is present, derive k = H(st) via ctx.st_hash_b64_from_st.
// This supports "2A" POST /status style polling where the browser only has `st`.
// Returns false with a stable error code if fields are missing/invalid.
static bool get_key_from_json(const RoutesV5Context& ctx,
                              const json& j,
                              std::string& out_key,
                              std::string& err) {
    // Prefer explicit k if provided
    if (j.contains("k") && j["k"].is_string()) {
        out_key = normalize_query_b64(j["k"].get<std::string>());
        if (out_key.empty()) { err = "k_empty"; return false; }
        return true;
    }

    // Or derive from st
    if (j.contains("st") && j["st"].is_string()) {
        const std::string st = j["st"].get<std::string>();
        if (st.empty()) { err = "st_empty"; return false; }
        if (!ctx.st_hash_b64_from_st) { err = "server_missing_st_hash"; return false; }
        out_key = ctx.st_hash_b64_from_st(st);
        if (out_key.empty()) { err = "k_derive_failed"; return false; }
        return true;
    }

    err = "missing k/st";
    return false;
}

// resolve_approval_key_from_req
// Resolve the lookup key used by /status and /consume.
// Inputs can arrive via query (GET) or body (POST). Body fields override query.
// Accepted fields (in priority order):
//   1) st  -> derive k = H(st) (preferred, stateless-ready)
//   2) k   -> direct correlation key (normalized base64)
//   3) sid -> legacy/debug correlation key
//
// Rationale
// - v5 prefers `k` derived from signed `st` to avoid server-issued session IDs.
// - sid remains accepted for debugging and transitional compatibility.
static bool resolve_approval_key_from_req(const RoutesV5Context& ctx,
                                         const httplib::Request& req,
                                         const json* body_opt,
                                         std::string& out_key,
                                         std::string& err) {
	auto get_param = [&](const char* name) -> std::string {
    	auto it = req.params.find(name);
    	if (it == req.params.end()) return "";
    	std::string v = it->second;
    	if (std::string(name) == "k") v = normalize_query_b64(std::move(v));
    	return v;
	};

	std::string st;
	std::string k   = normalize_query_b64(get_param("k"));
	std::string sid = get_param("sid");

    // body fields override query (for POST)
    if (body_opt && body_opt->is_object()) {
        if (body_opt->contains("st") && (*body_opt)["st"].is_string())   st  = (*body_opt)["st"].get<std::string>();
        if (body_opt->contains("k")  && (*body_opt)["k"].is_string())    k   = normalize_query_b64((*body_opt)["k"].get<std::string>());
        if (body_opt->contains("sid")&& (*body_opt)["sid"].is_string())  sid = (*body_opt)["sid"].get<std::string>();
    }

    if (!st.empty()) {
        if (!ctx.st_hash_b64_from_st) { err = "server_missing_st_hash"; return false; }
        out_key = ctx.st_hash_b64_from_st(st);
        if (out_key.empty()) { err = "k_derive_failed"; return false; }
        return true;
    }

    if (!k.empty())   { out_key = k;   return true; }
    if (!sid.empty()) { out_key = sid; return true; }

    err = "missing st/k/sid";
    return false;
}

void register_routes_v5(httplib::Server& srv, const RoutesV5Context& ctx) {
    // ---- POST/GET /api/v5/session ----
	// Route group: /api/v5/session
	// Issues a signed request token (st) and correlation key (k). Inserts PendingEntry.

    auto session_handler = [&](const httplib::Request& req, httplib::Response& res) {
        const long now = ctx.now_epoch ? ctx.now_epoch() : 0;

        // prune old entries first
        if (ctx.approvals_prune) ctx.approvals_prune(now);
        if (ctx.pending_prune)   ctx.pending_prune(now);

        // mint session request token (st)
        const std::string sid   = ctx.random_b64url ? ctx.random_b64url(18) : std::string{};
        const std::string chal  = ctx.random_b64url ? ctx.random_b64url(32) : std::string{};
        const std::string nonce = ctx.random_b64url ? ctx.random_b64url(18) : std::string{};
        if (sid.empty() || chal.empty() || nonce.empty()) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "rng_failed"}}.dump());
            return;
        }

        const long iat = now;
        const long exp = now + (ctx.req_ttl ? *ctx.req_ttl : 120);

        if (!ctx.build_req_payload_canonical || !ctx.sign_req_token) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "missing_callbacks"}}.dump());
            return;
        }

        const std::string payload = ctx.build_req_payload_canonical(sid, chal, nonce, iat, exp);
        const std::string st      = ctx.sign_req_token(payload);
        if (st.empty()) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "sign_failed"}}.dump());
            return;
        }

        // derive k (stateless-ready correlation key)
        std::string k;
        if (ctx.st_hash_b64_from_st) k = ctx.st_hash_b64_from_st(st);
        if (k.empty()) {
            // We require k for 2A flow
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "k_derive_failed"}}.dump());
            return;
        }

        // mark pending so status can return "pending" immediately
        if (!ctx.pending_put) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "pending_put_not_configured"}}.dump());
            return;
        }
        RoutesV5Context::PendingEntry pe;
        pe.expires_at = exp;
        pe.reason = "awaiting_scan";
        ctx.pending_put(k, pe);

        if (!(ctx.pending_get)) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "pending_get_not_configured"}}.dump());
            return;
        }

        RoutesV5Context::PendingEntry verify_pe;
        if (!ctx.pending_get(k, verify_pe)) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "pending_put_failed"}}.dump());
            return;
        }

        // audit (optional)
        if (ctx.audit_emit) {
            ctx.audit_emit("v5.session_issued", "ok", [&](std::map<std::string,std::string>& f) {
                f["sid"] = sid;
                f["k"] = k;
                f["now"] = std::to_string(now);
                f["iat"] = std::to_string(iat);
                f["exp"] = std::to_string(exp);
                if (ctx.client_ip) f["ip"] = ctx.client_ip(req);
            });
        }

        reply_json(res, 200, json{
            {"ok", true},
            {"sid", sid},
            {"st", st},
            {"k", k},
            {"iat", iat},
            {"exp", exp},
            {"qr_svg", std::string("/api/v5/qr.svg?st=") + (ctx.url_encode ? ctx.url_encode(st) : st)}
        }.dump());
    };

    srv.Post("/api/v5/session", session_handler);
    srv.Get ("/api/v5/session", session_handler); // harmless / useful for debugging

    // ---- GET /api/v5/qr.svg?st=... ----
    srv.Get("/api/v5/qr.svg", [&](const httplib::Request& req, httplib::Response& res) {
        auto it = req.params.find("st");
        if (it == req.params.end() || it->second.empty()) {
            reply_json(res, 400, json({{"ok", false}, {"error", "bad_request"}, {"message", "missing st"}}).dump());
            return;
        }

        const std::string st = it->second;
        const std::string qr_uri =
            "dna://auth?v=5&st=" + (ctx.url_encode ? ctx.url_encode(st) : st) +
            "&origin=" + (ctx.url_encode ? ctx.url_encode(*ctx.origin) : *ctx.origin) +
            "&app=" + (ctx.url_encode ? ctx.url_encode(*ctx.app) : *ctx.app);

        try {
            if (!ctx.qr_svg_from_text) throw std::runtime_error("missing qr_svg_from_text");
            const std::string svg = ctx.qr_svg_from_text(qr_uri, 6, 4);
            res.status = 200;
            res.set_header("Content-Type", "image/svg+xml; charset=utf-8");
            res.set_header("Cache-Control", "no-store");
            res.body = svg;
        } catch (const std::exception& e) {
            reply_json(res, 500, json({{"ok", false}, {"error", "server_error"}, {"message", e.what()}}).dump());
        }
    });

    // ---- GET /api/v5/status?k=...|sid=... (and optionally st=...) ----
    srv.Get("/api/v5/status", [&](const httplib::Request& req, httplib::Response& res) {
        const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
        if (ctx.approvals_prune) ctx.approvals_prune(now);
        if (ctx.pending_prune)   ctx.pending_prune(now);

        std::string key, err;
        if (!resolve_approval_key_from_req(ctx, req, nullptr, key, err)) {
            reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", err}}.dump());
            return;
        }

        RoutesV5Context::ApprovalEntry ae;
        if (ctx.approvals_get && ctx.approvals_get(key, ae)) {
            reply_json(res, 200, json{{"ok", true}, {"approved", true}, {"k", key}, {"expires_at", ae.expires_at}}.dump());
            return;
        }

        RoutesV5Context::PendingEntry pe;
        if (ctx.pending_get && ctx.pending_get(key, pe)) {
            reply_json(res, 200, json{
                {"ok", true},
                {"approved", false},
                {"pending", true},
                {"k", key},
                {"expires_at", pe.expires_at},
                {"reason", pe.reason}
            }.dump());
            return;
        }


        reply_json(res, 200, json{{"ok", true}, {"approved", false}}.dump());
    });

    // ---- 2A: POST /api/v5/status {st} ----
    srv.Post("/api/v5/status", [&](const httplib::Request& req, httplib::Response& res) {
        const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
        if (ctx.approvals_prune) ctx.approvals_prune(now);
        if (ctx.pending_prune)   ctx.pending_prune(now);

        json j;
        std::string err;
        if (!parse_json_body(req, j, err)) {
            reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", err}}.dump());
            return;
        }

		std::string k;
		if (!get_key_from_json(ctx, j, k, err)) {
    		reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", err}}.dump());
    		return;
		}


        RoutesV5Context::ApprovalEntry ae;
        if (ctx.approvals_get && ctx.approvals_get(k, ae)) {
            reply_json(res, 200, json{
                {"ok", true},
                {"approved", true},
                {"state", "approved"},
                {"k", k},
                {"expires_at", ae.expires_at}
            }.dump());
            return;
        }

        RoutesV5Context::PendingEntry pe;
        if (ctx.pending_get && ctx.pending_get(k, pe)) {
            reply_json(res, 200, json{
                {"ok", true},
                {"approved", false},
                {"state", "pending"},
                {"k", k},
                {"expires_at", pe.expires_at},
                {"reason", pe.reason}
            }.dump());
            return;
        }

        reply_json(res, 200, json{
            {"ok", true},
            {"approved", false},
            {"state", "missing"},
            {"k", k}
        }.dump());
    });

// ---- 2A: POST /api/v5/consume {st|k|sid} ----
// Route group: /api/v5/session
// Issues a signed request token (st) and correlation key (k). Inserts PendingEntry.
srv.Post("/api/v5/consume", [&](const httplib::Request& req, httplib::Response& res) {
    const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
    if (ctx.approvals_prune) ctx.approvals_prune(now);
    if (ctx.pending_prune)   ctx.pending_prune(now);

    json j;
    std::string jerr;
    if (!parse_json_body(req, j, jerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", jerr}}.dump());
        return;
    }

    std::string key, kerr;
    if (!resolve_approval_key_from_req(ctx, req, &j, key, kerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", kerr}}.dump());
        return;
    }

    RoutesV5Context::ApprovalEntry ae;
    if (!(ctx.approvals_get && ctx.approvals_get(key, ae))) {
        reply_json(res, 409, json{{"ok", false}, {"error", "not_approved"}, {"k", key}}.dump());
        return;
    }

    // If cookie is missing, fail loudly
    if (ae.cookie_val.empty()) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "cookie_empty"}, {"k", key}}.dump());
        return;
    }

    // Build full Set-Cookie header (name=value; attributes)
    //
    // NOTE: ae.cookie_val is ONLY the cookie VALUE (our signed token),
    // not a full "Set-Cookie:" header. The browser will ignore it unless
    // we provide "pqnas_session=<value>; Path=/; ...".
    //
    // SameSite=None requires Secure (modern browsers).
    const std::string set_cookie =
        std::string("pqnas_session=") + ae.cookie_val +
        "; Path=/" +
        "; HttpOnly" +
        "; SameSite=None" +
        "; Secure";

    // IMPORTANT: set cookie header BEFORE body is finalized
    res.set_header("Set-Cookie", set_cookie);

    // Audit (now we can audit the *actual* header we are sending)
    if (ctx.audit_emit) {
        ctx.audit_emit("v5.consume_cookie", "ok", [&](std::map<std::string,std::string>& f) {
            f["k"] = key;
            f["cookie_len"] = std::to_string(ae.cookie_val.size());
            f["set_cookie_len"] = std::to_string(set_cookie.size());
            f["cookie_has_secure"] = (set_cookie.find("Secure") != std::string::npos) ? "1" : "0";
            f["cookie_has_domain"] = (set_cookie.find("Domain=") != std::string::npos) ? "1" : "0";
            f["cookie_has_samesite_none"] = (set_cookie.find("SameSite=None") != std::string::npos) ? "1" : "0";
        });
    }

    // Now that we have everything, consume the one-time approval + pending entries.
    if (ctx.approvals_pop) ctx.approvals_pop(key);
    if (ctx.pending_pop)   ctx.pending_pop(key);

    reply_json(res, 200, json{
        {"ok", true},
        {"state", "consumed"},
        {"k", key},
        {"fingerprint", ae.fingerprint},
        {"expires_at", ae.expires_at}
    }.dump());
});

}


