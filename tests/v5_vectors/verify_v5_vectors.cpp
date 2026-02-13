// tests/v5_vectors/verify_v5_vectors.cpp
//
// v5 vectors verifier:
// - Replays the existing v4 proof verifier (pqnas::verify_v4_json) using frozen JSON bodies
// - Adds a v5-specific assertion: derived correlation key k == st_hash_b64
//
// Expected tests/v5_vectors/v5_vectors.json format (recommended):
// {
//   "server_pk_b64": "...",
//   "now_unix_sec": 1768859820,           // optional (freeze time)
//   "expected_origin": "https://example", // optional
//   "expected_rp_id": "example.com",      // optional
//   "enforce_origin_rp": true,            // optional
//   "enforce_allowlist": false,           // optional
//   "cases": [
//     {
//       "name": "happy_path",
//       "expect_ok": true,
//       "verify_body_json": "{... exact JSON body verified by server ...}",
//       "expect_k": "...."                // must match derived st_hash_b64
//     },
//     { "name": "tamper_st_one_char_should_fail", "expect_ok": false, "verify_body_json": "{...}" }
//   ]
// }

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <array>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include "v4_verify_shared.h"

using json = nlohmann::json;

static std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) throw std::runtime_error("cannot open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Decode base64url(no padding) or standard base64 (with/without padding).
static std::vector<unsigned char> b64_loose_bytes(const std::string& in_raw) {
    std::string in = in_raw;

    while (!in.empty() && (in.front()==' '||in.front()=='\t'||in.front()=='\r'||in.front()=='\n')) in.erase(in.begin());
    while (!in.empty() && (in.back() ==' '||in.back() =='\t'||in.back() =='\r'||in.back() =='\n')) in.pop_back();

    bool urlsafe = (in.find('-') != std::string::npos) || (in.find('_') != std::string::npos);

    if (urlsafe) {
        in.erase(std::remove(in.begin(), in.end(), '='), in.end());
    } else {
        while ((in.size() % 4) != 0) in.push_back('=');
    }

    std::vector<unsigned char> out((in.size() * 3) / 4 + 8);
    size_t out_len = 0;

    int variant = urlsafe ? sodium_base64_VARIANT_URLSAFE_NO_PADDING
                          : sodium_base64_VARIANT_ORIGINAL;

    if (sodium_base642bin(out.data(), out.size(),
                          in.c_str(), in.size(),
                          nullptr, &out_len, nullptr,
                          variant) != 0) {
        throw std::runtime_error("base64 decode failed");
    }

    out.resize(out_len);
    return out;
}

static bool eq_or_empty(const json& c, const char* k, const std::string& got) {
    if (!c.contains(k)) return true;
    if (!c[k].is_string()) return false;
    std::string exp = c[k].get<std::string>();
    if (exp.empty()) return true;
    return exp == got;
}

// Flip a char in the *payload* portion of st: "v4.<payload>.<sig>"
static std::string tamper_st_payload_one_char(std::string st) {
    auto dot1 = st.find('.');
    auto dot2 = (dot1 == std::string::npos) ? std::string::npos : st.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos) {
        throw std::runtime_error("tamper_st: bad st format");
    }

    std::string prefix  = st.substr(0, dot1);
    std::string payload = st.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig     = st.substr(dot2 + 1);

    if (payload.size() < 6) throw std::runtime_error("tamper_st: payload too short");
    char &ch = payload[5];
    ch = (ch == 'A') ? 'B' : 'A';

    return prefix + "." + payload + "." + sig;
}

static bool extract_iat_exp_from_signed_payload(const json& body, long& iat_out, long& exp_out) {
    if (!body.contains("signed_payload") || !body["signed_payload"].is_object()) return false;
    const auto& sp = body["signed_payload"];

    // Allow both naming styles.
    auto get_long = [&](const char* a, const char* b, long& out) -> bool {
        if (sp.contains(a) && sp[a].is_number_integer()) { out = sp[a].get<long>(); return true; }
        if (sp.contains(b) && sp[b].is_number_integer()) { out = sp[b].get<long>(); return true; }
        return false;
    };

    long iat = 0, exp = 0;
    if (!get_long("issued_at", "iat", iat)) return false;
    if (!get_long("expires_at", "exp", exp)) return false;

    iat_out = iat;
    exp_out = exp;
    return true;
}

static bool extract_iat_exp_from_st_payload(const std::string& st, long& iat_out, long& exp_out) {
    // st = "v4.<payload_b64url>.<sig_b64url>"
    auto dot1 = st.find('.');
    auto dot2 = (dot1 == std::string::npos) ? std::string::npos : st.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos) return false;

    std::string payload_b64url = st.substr(dot1 + 1, dot2 - dot1 - 1);

    // Decode payload as JSON using existing base64 helper.
    auto bytes = b64_loose_bytes(payload_b64url);
    std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    json p;
    try {
        p = json::parse(s);
    } catch (...) {
        return false;
    }

    // Allow both naming styles.
    auto get_long = [&](const char* a, const char* b, long& out) -> bool {
        if (p.contains(a) && p[a].is_number_integer()) { out = p[a].get<long>(); return true; }
        if (p.contains(b) && p[b].is_number_integer()) { out = p[b].get<long>(); return true; }
        return false;
    };

    long iat = 0, exp = 0;
    if (!get_long("iat", "issued_at", iat)) return false;
    if (!get_long("exp", "expires_at", exp)) return false;

    iat_out = iat;
    exp_out = exp;
    return true;
}

static bool derive_now_unix_sec_from_body_json(const std::string& verify_body_json, long& now_out) {
    json body;
    try {
        body = json::parse(verify_body_json);
    } catch (...) {
        return false;
    }

    long iat = 0, exp = 0;

    if (extract_iat_exp_from_signed_payload(body, iat, exp)) {
        // ok
    } else if (body.contains("st") && body["st"].is_string() &&
               extract_iat_exp_from_st_payload(body["st"].get<std::string>(), iat, exp)) {
        // ok
    } else {
        return false;
    }

    if (iat <= 0 || exp <= 0 || exp < iat) return false;

    // Pick midpoint (stable).
    now_out = (iat + exp) / 2;
    return (now_out >= iat && now_out <= exp);
}

// v5 correlation: compare captured body's st_hash (and/or k) to derived st_hash_b64.
static bool extract_v5_st_hash_from_body(const json& body, std::string& out) {
    if (!body.contains("signed_payload") || !body["signed_payload"].is_object()) return false;
    const auto& sp = body["signed_payload"];

    // Common key names you might have used.
    const char* keys[] = { "st_hash_b64", "st_hash", "k" };

    for (auto* k : keys) {
        if (sp.contains(k) && sp[k].is_string()) {
            out = sp[k].get<std::string>();
            return !out.empty();
        }
    }
    return false;
}

static bool extract_top_level_k_from_body(const json& body, std::string& out) {
    if (body.contains("k") && body["k"].is_string()) {
        out = body["k"].get<std::string>();
        return !out.empty();
    }
    return false;
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "[v5_vectors] sodium_init failed\n");
        return 2;
    }

    const char* path = (argc >= 2) ? argv[1] : "tests/v5_vectors/v5_vectors.json";

    json j;
    try {
        j = json::parse(slurp(path));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[v5_vectors] failed to parse %s: %s\n", path, e.what());
        return 2;
    }

    if (!j.is_object() || !j.contains("cases") || !j["cases"].is_array()) {
        std::fprintf(stderr, "[v5_vectors] invalid format: expected { cases: [...] }\n");
        return 2;
    }

    // server_pk_b64 -> std::array<uchar,32>
    std::array<unsigned char, 32> server_pk{};
    try {
        if (!j.contains("server_pk_b64") || !j["server_pk_b64"].is_string()) {
            std::fprintf(stderr, "[v5_vectors] missing server_pk_b64\n");
            return 2;
        }
        auto pk = b64_loose_bytes(j["server_pk_b64"].get<std::string>());
        if (pk.size() != 32) {
            std::fprintf(stderr, "[v5_vectors] server_pk_b64 decoded to %zu bytes, expected 32\n", pk.size());
            return 2;
        }
        std::memcpy(server_pk.data(), pk.data(), 32);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[v5_vectors] server_pk decode error: %s\n", e.what());
        return 2;
    }

    // Optional: deployment binding config
    const std::string expected_origin = j.value("expected_origin", "");
    const std::string expected_rp_id  = j.value("expected_rp_id", "");

    const bool enforce_allowlist = j.value("enforce_allowlist", false);

    int failures = 0;

    for (const auto& c : j["cases"]) {
        std::string name = c.value("name", "unnamed");
        bool expect_ok = c.value("expect_ok", false);
    	// Per-case overrides (fall back to global defaults)
    	const bool enforce_origin_rp_case =
        	c.value("enforce_origin_rp", j.value("enforce_origin_rp", false));

	    const std::string expected_origin_case =
    	    c.value("expected_origin", j.value("expected_origin", ""));

	    const std::string expected_rp_id_case =
    	    c.value("expected_rp_id", j.value("expected_rp_id", ""));

	        if (!c.contains("verify_body_json") || !c["verify_body_json"].is_string()) {
    	        std::fprintf(stderr, "[%s] missing verify_body_json\n", name.c_str());
        	    failures++;
            	continue;
	        }

        std::string verify_body_json = c["verify_body_json"].get<std::string>();

		// Optional convenience: if global now_unix_sec is NOT provided,
		// derive a stable now from the captured body (signed_payload iat/exp or st payload).
		long derived_now = 0;
		bool have_derived_now = false;
		if (!j.contains("now_unix_sec")) {
    		have_derived_now = derive_now_unix_sec_from_body_json(verify_body_json, derived_now);
		}


        // ---- Shared verifier config (mirror server policy toggles safely) ----
        pqnas::VerifyV4Config cfg;

        // Freeze time for vectors (optional)
		if (j.contains("now_unix_sec")) {
    		cfg.now_unix_sec = j.at("now_unix_sec").get<long>();
		} else if (have_derived_now) {
    		cfg.now_unix_sec = derived_now;
		}


        // For vectors, allowlist is typically off unless explicitly testing policy.
        cfg.enforce_allowlist = enforce_allowlist;
        cfg.allowlist_is_allowed = [](const std::string&) { return true; };

		if (enforce_origin_rp_case) {
    		cfg.expected_origin = expected_origin_case;
    		cfg.expected_rp_id  = expected_rp_id_case;
		} else {
    		cfg.expected_origin.clear();
    		cfg.expected_rp_id.clear();
		}


        // Per-case tamper: flip one char in st payload inside the JSON body.
        if (name == "tamper_st_one_char_should_fail") {
            json body = json::parse(verify_body_json);
            if (!body.contains("st") || !body["st"].is_string()) {
                std::fprintf(stderr, "[%s] FAIL: tamper case: missing string field 'st'\n", name.c_str());
                failures++;
                continue;
            }
            std::string st = body.at("st").get<std::string>();
            body["st"] = tamper_st_payload_one_char(std::move(st));
            verify_body_json = body.dump();
        }

        auto r = pqnas::verify_v4_json(verify_body_json, server_pk, cfg);
        bool ok = r.ok;

        if (ok != expect_ok) {
            std::fprintf(stderr, "[%s] FAIL: expect_ok=%s got_ok=%s rc=%d detail=%s\n",
                         name.c_str(),
                         expect_ok ? "true" : "false",
                         ok ? "true" : "false",
                         (int)r.rc,
                         r.detail.c_str());
            failures++;
            continue;
        }

        // Optional: assert exact rc for either success or failure cases
        if (c.contains("expect_rc") && c["expect_rc"].is_number_integer()) {
            int exp_rc = c["expect_rc"].get<int>();
            if ((int)r.rc != exp_rc) {
                std::fprintf(stderr, "[%s] FAIL: expect_rc=%d got_rc=%d detail=%s\n",
                             name.c_str(), exp_rc, (int)r.rc, r.detail.c_str());
                failures++;
                continue;
            }
        }

        if (ok) {
            bool good = true;

            // v5 correlation check: captured body must agree with derived st_hash_b64.
            try {
                json body = json::parse(verify_body_json);

                std::string body_st_hash;
                if (extract_v5_st_hash_from_body(body, body_st_hash)) {
                    if (body_st_hash != r.st_hash_b64) {
                        std::fprintf(stderr, "[%s] FAIL: body signed_payload st_hash mismatch\n", name.c_str());
                        std::fprintf(stderr, "  body.signed_payload.st_hash=%s\n", body_st_hash.c_str());
                        std::fprintf(stderr, "  derived st_hash_b64(k)=%s\n", r.st_hash_b64.c_str());
                        good = false;
                    }
                }

                // If body has top-level k, also require it matches (optional).
                std::string body_k;
                if (extract_top_level_k_from_body(body, body_k)) {
                    if (body_k != r.st_hash_b64) {
                        std::fprintf(stderr, "[%s] FAIL: body top-level k mismatch\n", name.c_str());
                        std::fprintf(stderr, "  body.k=%s\n", body_k.c_str());
                        std::fprintf(stderr, "  derived st_hash_b64(k)=%s\n", r.st_hash_b64.c_str());
                        good = false;
                    }
                }
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[%s] FAIL: could not parse verify_body_json for v5 correlation check: %s\n",
                             name.c_str(), e.what());
                good = false;
            }

            // v5-specific: expect_k must match derived st_hash_b64
            if (!eq_or_empty(c, "expect_k", r.st_hash_b64)) {
                std::string expk =
                    (c.contains("expect_k") && c["expect_k"].is_string())
                        ? c["expect_k"].get<std::string>()
                        : "";
                std::fprintf(stderr, "[%s] FAIL: expect_k mismatch\n", name.c_str());
                std::fprintf(stderr, "  expected expect_k=%s\n", expk.c_str());
                std::fprintf(stderr, "  got      k(st_hash_b64)=%s\n", r.st_hash_b64.c_str());
                good = false;
            }

            // Optional cross-checks
            if (!eq_or_empty(c, "expect_fingerprint_hex", r.fingerprint_hex)) {
                std::fprintf(stderr, "[%s] FAIL: fingerprint mismatch\n", name.c_str());
                good = false;
            }
            if (!eq_or_empty(c, "expect_st_hash_b64", r.st_hash_b64)) {
                std::fprintf(stderr, "[%s] FAIL: st_hash_b64 mismatch\n", name.c_str());
                good = false;
            }
            if (!eq_or_empty(c, "expect_canonical_sha256_b64", r.canonical_sha256_b64)) {
                std::fprintf(stderr, "[%s] FAIL: canonical_sha256_b64 mismatch\n", name.c_str());
                good = false;
            }

            if (!good) {
                std::fprintf(stderr, "  got sid=%s\n", r.sid.c_str());
                std::fprintf(stderr, "  got fingerprint_hex=%s\n", r.fingerprint_hex.c_str());
                std::fprintf(stderr, "  got st_hash_b64(k)=%s\n", r.st_hash_b64.c_str());
                std::fprintf(stderr, "  got canonical_sha256_b64=%s\n", r.canonical_sha256_b64.c_str());
                failures++;
                continue;
            }

            std::printf("[%s] OK (k=%s sid=%s)\n",
                        name.c_str(), r.st_hash_b64.c_str(), r.sid.c_str());
        } else {
            std::printf("[%s] OK (expected failure rc=%d)\n", name.c_str(), (int)r.rc);
        }
    }
    if (failures) {
        std::fprintf(stderr, "[v5_vectors] FAILURES: %d\n", failures);
        return 1;
    }

    std::printf("[v5_vectors] ALL OK\n");
    return 0;
}
