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
#include <openssl/sha.h>

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


static std::string req_header_or_empty(const httplib::Request& req, const char* key) {
    auto it = req.headers.find(key);
    return (it == req.headers.end()) ? std::string{} : it->second;
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

static std::string sha256_hex(const std::string& s) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);

    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(SHA256_DIGEST_LENGTH * 2);

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out[i * 2]     = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    return out;
}

static std::string get_cookie_value(const httplib::Request& req, const std::string& name) {
    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) return {};

    const std::string& cookies = it->second;
    size_t pos = 0;

    while (pos < cookies.size()) {
        while (pos < cookies.size() && (cookies[pos] == ' ' || cookies[pos] == ';')) pos++;

        size_t eq = cookies.find('=', pos);
        if (eq == std::string::npos) break;

        size_t end = cookies.find(';', eq + 1);

        std::string key = cookies.substr(pos, eq - pos);
        std::string val = (end == std::string::npos)
            ? cookies.substr(eq + 1)
            : cookies.substr(eq + 1, end - (eq + 1));

        if (key == name) return val;

        if (end == std::string::npos) break;
        pos = end + 1;
    }

    return {};
}

static std::string make_preauth_cookie(const std::string& value, long max_age_sec) {
    return std::string("pqnas_preauth=") + value +
           "; Path=/api/v5/consume" +
           "; Max-Age=" + std::to_string(max_age_sec) +
           "; HttpOnly" +
           "; SameSite=Strict" +
           "; Secure";
}

static std::string clear_preauth_cookie() {
    return std::string("pqnas_preauth=") +
           "; Path=/api/v5/consume" +
           "; Max-Age=0" +
           "; HttpOnly" +
           "; SameSite=Strict" +
           "; Secure";
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

        const std::string preauth = ctx.random_b64url ? ctx.random_b64url(32) : std::string{};
        if (preauth.empty()) {
            reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "preauth_rng_failed"}}.dump());
            return;
        }

        const std::string preauth_hash = sha256_hex(preauth);

        RoutesV5Context::PendingEntry pe;
        pe.expires_at = exp;
        pe.reason = "awaiting_scan";
        pe.browser_bind_hash = preauth_hash;
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

        const long max_age = (exp > now) ? (exp - now) : 0;
        res.set_header("Set-Cookie", make_preauth_cookie(preauth, max_age));

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

    RoutesV5Context::PendingEntry pe;
    if (!(ctx.pending_get && ctx.pending_get(key, pe))) {
        reply_json(res, 409, json{
            {"ok", false},
            {"error", "session_missing"},
            {"k", key}
        }.dump());
        return;
    }

    const std::string preauth = get_cookie_value(req, "pqnas_preauth");
    if (preauth.empty()) {
        reply_json(res, 428, json{
            {"ok", false},
            {"error", "preauth_required"},
            {"message", "missing browser binding cookie"},
            {"k", key}
        }.dump());
        return;
    }

    if (pe.browser_bind_hash.empty() || sha256_hex(preauth) != pe.browser_bind_hash) {
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "browser_binding_failed"},
            {"message", "browser binding check failed"},
            {"k", key}
        }.dump());
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

    // IMPORTANT:
    // - issue the real authenticated session cookie
    // - immediately clear the one-time browser binding cookie
    //
    // We need TWO Set-Cookie headers here.
    const std::string clear_cookie = clear_preauth_cookie();

    res.headers.emplace("Set-Cookie", set_cookie);
    res.headers.emplace("Set-Cookie", clear_cookie);

    if (ctx.audit_emit) {
        ctx.audit_emit("v5.consume_cookie", "ok", [&](std::map<std::string,std::string>& f) {
            f["k"] = key;
            f["cookie_len"] = std::to_string(ae.cookie_val.size());
            f["set_cookie_len"] = std::to_string(set_cookie.size());
            f["clear_cookie_len"] = std::to_string(clear_cookie.size());
        });
    }

    // Now that we have everything, consume the one-time approval + pending entries.
    if (ctx.approvals_pop) ctx.approvals_pop(key);
    if (ctx.pending_pop)   ctx.pending_pop(key);

    reply_json(res, 200, json{
        {"ok", true},
        {"state", "consumed"},
        {"k", key}
    }.dump());
});

// ---- POST /api/v5/consume_app {st|k|sid, device_name?, platform?, app_version?} ----
// Mobile/app equivalent of /consume: returns bearer tokens instead of Set-Cookie.
srv.Post("/api/v5/consume_app", [&](const httplib::Request& req, httplib::Response& res) {
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

    if (ae.fingerprint.empty()) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "approval_missing_fingerprint"}, {"k", key}}.dump());
        return;
    }

    if (!ctx.consume_app_mint) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "consume_app_not_configured"}, {"k", key}}.dump());
        return;
    }

	const std::string device_name = j.value("device_name", std::string{});
	std::string platform = j.value("platform", std::string{});
	const std::string app_version = j.value("app_version", std::string{});
	const std::string device_model = j.value("device_model", std::string{});
	const std::string device_manufacturer = j.value("device_manufacturer", std::string{});
	const std::string os_version = j.value("os_version", std::string{});
	if (platform.empty()) platform = "android";

    RoutesV5Context::ConsumeAppResult out;
    std::string merr;
    const std::string client_ip = ctx.client_ip ? ctx.client_ip(req) : req.remote_addr;

    if (!ctx.consume_app_mint(ae.fingerprint,
                          device_name,
                          platform,
                          app_version,
                          device_model,
                          device_manufacturer,
                          os_version,
                          client_ip,
                          out,
                          merr)) {
        if (ctx.audit_emit) {
            ctx.audit_emit("v5.consume_app_fail", "fail", [&](std::map<std::string,std::string>& f) {
                f["k"] = key;
                f["fingerprint"] = ae.fingerprint;
                f["reason"] = merr.empty() ? "mint_failed" : merr;
                if (!platform.empty()) f["platform"] = platform;
                if (!device_name.empty()) f["device_name"] = device_name;
                if (!app_version.empty()) f["app_version"] = app_version;
				if (!device_model.empty()) f["device_model"] = device_model;
				if (!device_manufacturer.empty()) f["device_manufacturer"] = device_manufacturer;
				if (!os_version.empty()) f["os_version"] = os_version;
                if (!client_ip.empty()) f["ip"] = client_ip;
                const std::string ua = req_header_or_empty(req, "User-Agent");
                if (!ua.empty()) f["ua"] = ua;
            });
        }

        reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", merr.empty() ? "app consume denied" : merr},
            {"k", key}
        }.dump());
        return;
    }

    if (ctx.approvals_pop) ctx.approvals_pop(key);

    if (ctx.audit_emit) {
        ctx.audit_emit("v5.consume_app_ok", "ok", [&](std::map<std::string,std::string>& f) {
            f["k"] = key;
            f["fingerprint"] = out.fingerprint_hex.empty() ? ae.fingerprint : out.fingerprint_hex;
            f["device_id"] = out.device_id;
            f["role"] = out.role;
            f["platform"] = platform;
            if (!device_name.empty()) f["device_name"] = device_name;
            if (!app_version.empty()) f["app_version"] = app_version;
			if (!device_model.empty()) f["device_model"] = device_model;
			if (!device_manufacturer.empty()) f["device_manufacturer"] = device_manufacturer;
			if (!os_version.empty()) f["os_version"] = os_version;
            if (!client_ip.empty()) f["ip"] = client_ip;
            const std::string ua = req_header_or_empty(req, "User-Agent");
            if (!ua.empty()) f["ua"] = ua;
        });
    }

    reply_json(res, 200, json{
        {"ok", true},
        {"token_type", "Bearer"},
        {"access_token", out.access_token},
        {"expires_in", (out.access_exp > now ? out.access_exp - now : 0)},
        {"refresh_token", out.refresh_token},
        {"refresh_expires_in", (out.refresh_exp > now ? out.refresh_exp - now : 0)},
        {"device_id", out.device_id},
        {"fingerprint_hex", out.fingerprint_hex.empty() ? ae.fingerprint : out.fingerprint_hex},
        {"role", out.role}
    }.dump());
});

// ---- POST /api/v5/token/refresh {refresh_token, device_id} ----
// Mobile/app access-token refresh.
srv.Post("/api/v5/token/refresh", [&](const httplib::Request& req, httplib::Response& res) {
    json j;
    std::string jerr;
    if (!parse_json_body(req, j, jerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", jerr}}.dump());
        return;
    }

    const std::string refresh_token = j.value("refresh_token", std::string{});
    const std::string device_id = j.value("device_id", std::string{});
    if (refresh_token.empty() || device_id.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing refresh_token or device_id"}}.dump());
        return;
    }

    if (!ctx.refresh_app_token) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "refresh_app_token_not_configured"}}.dump());
        return;
    }

    RoutesV5Context::RefreshAppResult out;
    std::string rerr;
    const std::string client_ip = ctx.client_ip ? ctx.client_ip(req) : req.remote_addr;

    if (!ctx.refresh_app_token(refresh_token, device_id, client_ip, out, rerr)) {
        if (ctx.audit_emit) {
            ctx.audit_emit("v5.token_refresh_fail", "fail", [&](std::map<std::string,std::string>& f) {
                f["device_id"] = device_id;
                f["reason"] = rerr.empty() ? "refresh_failed" : rerr;
                if (!client_ip.empty()) f["ip"] = client_ip;
                const std::string ua = req_header_or_empty(req, "User-Agent");
                if (!ua.empty()) f["ua"] = ua;
            });
        }

        reply_json(res, 401, json{
            {"ok", false},
            {"error", "unauthorized"},
            {"message", rerr.empty() ? "refresh denied" : rerr},
            {"device_id", device_id}
        }.dump());
        return;
    }

    if (ctx.audit_emit) {
        ctx.audit_emit("v5.token_refresh_ok", "ok", [&](std::map<std::string,std::string>& f) {
            f["device_id"] = out.device_id.empty() ? device_id : out.device_id;
            if (!out.fingerprint_hex.empty()) f["fingerprint"] = out.fingerprint_hex;
            if (!out.role.empty()) f["role"] = out.role;
            if (!client_ip.empty()) f["ip"] = client_ip;
            const std::string ua = req_header_or_empty(req, "User-Agent");
            if (!ua.empty()) f["ua"] = ua;
        });
    }

    const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
    reply_json(res, 200, json{
        {"ok", true},
        {"token_type", "Bearer"},
        {"access_token", out.access_token},
        {"expires_in", (out.access_exp > now ? out.access_exp - now : 0)},
        {"fingerprint_hex", out.fingerprint_hex},
        {"role", out.role},
        {"device_id", out.device_id.empty() ? device_id : out.device_id}
    }.dump());
});

// ---- POST /api/v5/app_pair/start ----
srv.Post("/api/v5/app_pair/start", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ctx.require_user_cookie) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "require_user_cookie_not_configured"}}.dump());
        return;
    }

    std::string fp_hex, role;
    if (!ctx.require_user_cookie(req, res, &fp_hex, &role)) return;

    const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
    if (ctx.app_pair_prune) ctx.app_pair_prune(now);

    if (!ctx.app_pair_start) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "app_pair_start_not_configured"}}.dump());
        return;
    }

    RoutesV5Context::AppPairStartResult out;
    std::string err;
    if (!ctx.app_pair_start(fp_hex, role, out, err)) {
        reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", err.empty() ? "pair start failed" : err}
        }.dump());
        return;
    }

    reply_json(res, 200, json{
        {"ok", true},
        {"pair_id", out.pair_id},
        {"expires_at", out.expires_at},
        {"qr_uri", out.qr_uri},
        {"qr_svg", std::string("/api/v5/app_pair/qr.svg?pt=") + (ctx.url_encode ? ctx.url_encode(out.pair_token) : out.pair_token)}
    }.dump());
});

srv.Post("/api/v5/app_pair/cancel", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ctx.require_user_cookie) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "require_user_cookie_not_configured"}}.dump());
        return;
    }

    std::string fp_hex, role;
    if (!ctx.require_user_cookie(req, res, &fp_hex, &role)) return;

    json j;
    std::string jerr;
    if (!parse_json_body(req, j, jerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", jerr}}.dump());
        return;
    }

    const std::string pair_id = j.value("pair_id", std::string{});
    if (pair_id.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing pair_id"}}.dump());
        return;
    }

    if (!ctx.app_pair_get || !ctx.app_pair_cancel) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "app_pair cancel dependencies missing"}}.dump());
        return;
    }

    RoutesV5Context::AppPairStatusResult st;
    std::string err;
    if (!ctx.app_pair_get(pair_id, st, err)) {
        reply_json(res, 404, json{{"ok", false}, {"error", "not_found"}, {"message", "pairing not found"}, {"pair_id", pair_id}}.dump());
        return;
    }

    if (st.fingerprint_hex != fp_hex) {
        reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "pairing does not belong to current user"}}.dump());
        return;
    }

    if (!ctx.app_pair_cancel(pair_id, err)) {
        reply_json(res, 409, json{{"ok", false}, {"error", "not_allowed"}, {"message", err.empty() ? "cancel failed" : err}, {"pair_id", pair_id}}.dump());
        return;
    }

    reply_json(res, 200, json{{"ok", true}, {"pair_id", pair_id}, {"state", "cancelled"}}.dump());
});

srv.Get("/api/v5/app_devices", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ctx.require_user_cookie) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "require_user_cookie_not_configured"}}.dump());
        return;
    }

    std::string fp_hex, role;
    if (!ctx.require_user_cookie(req, res, &fp_hex, &role)) return;

    if (!ctx.app_devices_list_for_fingerprint) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "app_devices_list_for_fingerprint_not_configured"}}.dump());
        return;
    }

    const auto devices = ctx.app_devices_list_for_fingerprint(fp_hex);

    json arr = json::array();

	for (const auto& d : devices) {
    	if (d.revoked) continue;

	    long refresh_expires_at = 0;
    	const bool has_refresh_expiry =
        	ctx.app_device_refresh_expiry &&
	        ctx.app_device_refresh_expiry(d.device_id, refresh_expires_at);

		arr.push_back(json{
    		{"device_id", d.device_id},
	    	{"role", d.role},
	    	{"platform", d.platform},
		    {"device_name", d.device_name},
    		{"app_version", d.app_version},
		    {"device_model", d.device_model},
    		{"device_manufacturer", d.device_manufacturer},
	    	{"os_version", d.os_version},
	    	{"created_at", d.created_at},
		    {"last_seen_at", d.last_seen_at},
    		{"last_ip", d.last_ip},
	    	{"revoked", d.revoked},
		    {"refresh_expires_at", has_refresh_expiry ? refresh_expires_at : 0}
		});
	}

    reply_json(res, 200, json{
        {"ok", true},
        {"devices", arr}
    }.dump());
});

srv.Post("/api/v5/app_devices/revoke", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ctx.require_user_cookie) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "require_user_cookie_not_configured"}}.dump());
        return;
    }

    std::string fp_hex, role;
    if (!ctx.require_user_cookie(req, res, &fp_hex, &role)) return;

    json j;
    std::string jerr;
    if (!parse_json_body(req, j, jerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", jerr}}.dump());
        return;
    }

    const std::string device_id = j.value("device_id", std::string{});
    if (device_id.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing device_id"}}.dump());
        return;
    }

    if (!ctx.app_device_get || !ctx.app_device_revoke) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "app device revoke dependencies missing"}}.dump());
        return;
    }

    pqnas::TrustedAppDevice d;
    if (!ctx.app_device_get(device_id, d)) {
        reply_json(res, 404, json{{"ok", false}, {"error", "not_found"}, {"message", "device not found"}, {"device_id", device_id}}.dump());
        return;
    }

    if (d.fingerprint_hex != fp_hex) {
        reply_json(res, 403, json{{"ok", false}, {"error", "forbidden"}, {"message", "device does not belong to current user"}}.dump());
        return;
    }

    std::string err;
    if (!ctx.app_device_revoke(device_id, err)) {
        reply_json(res, 409, json{{"ok", false}, {"error", "not_allowed"}, {"message", err.empty() ? "revoke failed" : err}, {"device_id", device_id}}.dump());
        return;
    }

    reply_json(res, 200, json{
        {"ok", true},
        {"device_id", device_id},
        {"state", "revoked"}
    }.dump());
});

// ---- GET /api/v5/app_pair/qr.svg?pt=... ----
srv.Get("/api/v5/app_pair/qr.svg", [&](const httplib::Request& req, httplib::Response& res) {
    auto it = req.params.find("pt");
    if (it == req.params.end() || it->second.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing pt"}}.dump());
        return;
    }

    if (!ctx.app_pair_build_qr_uri || !ctx.qr_svg_from_text || !ctx.origin || !ctx.app) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "pair qr dependencies missing"}}.dump());
        return;
    }

    const std::string pt = it->second;
    const std::string qr_uri = ctx.app_pair_build_qr_uri(*ctx.origin, pt, *ctx.app);

    try {
        const std::string svg = ctx.qr_svg_from_text(qr_uri, 6, 4);
        res.status = 200;
        res.set_header("Content-Type", "image/svg+xml; charset=utf-8");
        res.set_header("Cache-Control", "no-store");
        res.body = svg;
    } catch (const std::exception& e) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", e.what()}}.dump());
    }
});
// ---- GET /api/v5/app_pair/status?pair_id=... ----
srv.Get("/api/v5/app_pair/status", [&](const httplib::Request& req, httplib::Response& res) {
    auto it = req.params.find("pair_id");
    if (it == req.params.end() || it->second.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing pair_id"}}.dump());
        return;
    }

    const std::string pair_id = it->second;
    const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
    if (ctx.app_pair_prune) ctx.app_pair_prune(now);

    if (!ctx.app_pair_get) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "app_pair_get_not_configured"}}.dump());
        return;
    }

    RoutesV5Context::AppPairStatusResult st;
    std::string err;
    if (!ctx.app_pair_get(pair_id, st, err)) {
        reply_json(res, 200, json{
            {"ok", true},
            {"state", "missing"},
            {"pair_id", pair_id}
        }.dump());
        return;
    }

    if (st.expires_at > 0 && now > st.expires_at) {
		reply_json(res, 200, json{
    		{"ok", true},
		    {"state", "expired"},
    		{"pair_id", pair_id},
    		{"issued_at", st.issued_at},
    		{"expires_at", st.expires_at},
    		{"now", now}
		}.dump());
        return;
    }

    if (st.consumed) {
		reply_json(res, 200, json{
    		{"ok", true},
    		{"state", "consumed"},
    		{"pair_id", pair_id},
    		{"issued_at", st.issued_at},
    		{"expires_at", st.expires_at},
    		{"consumed_at", st.consumed_at},
    		{"device_id", st.consumed_device_id},
    		{"now", now}
		}.dump());
        return;
    }

	reply_json(res, 200, json{
	    {"ok", true},
    	{"state", "pending"},
    	{"pair_id", pair_id},
	    {"issued_at", st.issued_at},
    	{"expires_at", st.expires_at},
    	{"now", now}
	}.dump());
});

// ---- POST /api/v5/app_pair/consume {pair_token, device_name?, platform?, app_version?} ----
srv.Post("/api/v5/app_pair/consume", [&](const httplib::Request& req, httplib::Response& res) {
    json j;
    std::string jerr;
    if (!parse_json_body(req, j, jerr)) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", jerr}}.dump());
        return;
    }

	const std::string pair_token = j.value("pair_token", std::string{});
	const std::string device_name = j.value("device_name", std::string{});
	std::string platform = j.value("platform", std::string{});
	const std::string app_version = j.value("app_version", std::string{});
	const std::string device_model = j.value("device_model", std::string{});
	const std::string device_manufacturer = j.value("device_manufacturer", std::string{});
	const std::string os_version = j.value("os_version", std::string{});
	if (platform.empty()) platform = "android";

    if (pair_token.empty()) {
        reply_json(res, 400, json{{"ok", false}, {"error", "bad_request"}, {"message", "missing pair_token"}}.dump());
        return;
    }

    if (!ctx.app_pair_consume || !ctx.consume_app_mint) {
        reply_json(res, 500, json{{"ok", false}, {"error", "server_error"}, {"message", "pair consume not configured"}}.dump());
        return;
    }

    std::string pair_id, fingerprint_hex, role;
    std::string cerr;
    if (!ctx.app_pair_consume(pair_token, pair_id, fingerprint_hex, role, cerr)) {
        reply_json(res, 409, json{
            {"ok", false},
            {"error", "not_allowed"},
            {"message", cerr.empty() ? "pair consume failed" : cerr}
        }.dump());
        return;
    }

    RoutesV5Context::ConsumeAppResult out;
    std::string merr;
    const std::string client_ip = ctx.client_ip ? ctx.client_ip(req) : req.remote_addr;

    if (!ctx.consume_app_mint(fingerprint_hex,
                          device_name,
                          platform,
                          app_version,
                          device_model,
                          device_manufacturer,
                          os_version,
                          client_ip,
                          out,
                          merr)) {
        reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", merr.empty() ? "pair mint denied" : merr}
        }.dump());
        return;
    }

    if (ctx.app_pair_mark_consumed_device) {
        std::string derr;
        ctx.app_pair_mark_consumed_device(pair_id, out.device_id, derr);
    }

    const long now = ctx.now_epoch ? ctx.now_epoch() : 0;
    reply_json(res, 200, json{
        {"ok", true},
        {"token_type", "Bearer"},
        {"access_token", out.access_token},
        {"expires_in", (out.access_exp > now ? out.access_exp - now : 0)},
        {"refresh_token", out.refresh_token},
        {"refresh_expires_in", (out.refresh_exp > now ? out.refresh_exp - now : 0)},
        {"device_id", out.device_id},
        {"fingerprint_hex", out.fingerprint_hex.empty() ? fingerprint_hex : out.fingerprint_hex},
        {"role", out.role.empty() ? role : out.role}
    }.dump());
});
}


