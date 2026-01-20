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

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "[v4_vectors] sodium_init failed\n");
        return 2;
    }

    const char* path = (argc >= 2) ? argv[1] : "tests/v4_vectors/vectors.json";

    json j;
    try {
        j = json::parse(slurp(path));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[v4_vectors] failed to parse %s: %s\n", path, e.what());
        return 2;
    }

    if (!j.is_object() || !j.contains("cases") || !j["cases"].is_array()) {
        std::fprintf(stderr, "[v4_vectors] invalid format: expected { cases: [...] }\n");
        return 2;
    }

    // server_pk_b64 -> std::array<uchar,32>
    std::array<unsigned char, 32> server_pk{};
    try {
        if (!j.contains("server_pk_b64") || !j["server_pk_b64"].is_string()) {
            std::fprintf(stderr, "[v4_vectors] missing server_pk_b64\n");
            return 2;
        }
        auto pk = b64_loose_bytes(j["server_pk_b64"].get<std::string>());
        if (pk.size() != 32) {
            std::fprintf(stderr, "[v4_vectors] server_pk_b64 decoded to %zu bytes, expected 32\n", pk.size());
            return 2;
        }
        std::memcpy(server_pk.data(), pk.data(), 32);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[v4_vectors] server_pk decode error: %s\n", e.what());
        return 2;
    }

    // Optional: vectors can carry deployment binding config (recommended)
    const std::string expected_origin = j.value("expected_origin", "");
    const std::string expected_rp_id  = j.value("expected_rp_id", "");

    // Tool should replay crypto; allow policy/binding to be toggled.
    const bool enforce_allowlist = j.value("enforce_allowlist", false);
    const bool enforce_origin_rp = j.value("enforce_origin_rp", false);
    int failures = 0;

    for (const auto& c : j["cases"]) {
        std::string name = c.value("name", "unnamed");
        bool expect_ok = c.value("expect_ok", false);

        if (!c.contains("verify_body_json") || !c["verify_body_json"].is_string()) {
            std::fprintf(stderr, "[%s] missing verify_body_json\n", name.c_str());
            failures++;
            continue;
        }

        // Vectors may also carry a separate "st" field (for humans), but the verifier
        // MUST use the exact JSON blob captured from server logs, because that is what
        // /api/v4/verify verifies. So: only feed verify_body_json into verify_v4_json().
        std::string verify_body_json = c["verify_body_json"].get<std::string>();

        // ---- Shared verifier config (mirror server policy toggles safely) ----
        pqnas::VerifyV4Config cfg;

        // Deterministic time for frozen vectors:
        // If vectors.json includes now_unix_sec, use it; otherwise use real time.

        // Freeze time for vectors (optional)
        if (j.contains("now_unix_sec")) {
            cfg.now_unix_sec = j.at("now_unix_sec").get<long>();
        }

		// For vectors: don't require allowlist unless you're explicitly testing policy
		cfg.enforce_allowlist = enforce_allowlist; //was false before

        // For tool runs, we typically want to skip allowlist decisions unless explicitly
        // requested in the vectors file (enforce_allowlist=true). If enforce_allowlist=true
        // we still provide a callback; vectors can fail for other reasons.
        // Provide callback (only used if enforce_allowlist=true)
        cfg.allowlist_is_allowed = [](const std::string&) { return true; };

        if (enforce_origin_rp) {
            cfg.expected_origin = expected_origin;
            cfg.expected_rp_id  = expected_rp_id;
        } else {
            // Make the intent explicit: skip deployment-binding checks.
            cfg.expected_origin.clear();
            cfg.expected_rp_id.clear();
        }

		// Apply per-case tampering to the *actual* payload verified (verify_body_json).
		if (name == "tamper_st_one_char_should_fail") {
    		json body = json::parse(verify_body_json);

    		std::string st = body.at("st").get<std::string>();

    		// Token format: v4.<payload_b64url_no_pad>.<sig_b64url_no_pad>
    		auto dot1 = st.find('.');
    		auto dot2 = (dot1 == std::string::npos) ? std::string::npos : st.find('.', dot1 + 1);
    		if (dot1 == std::string::npos || dot2 == std::string::npos) {
        		throw std::runtime_error("tamper case: bad st format");
    		}

    		std::string prefix  = st.substr(0, dot1);
    		std::string payload = st.substr(dot1 + 1, dot2 - dot1 - 1);
    		std::string sig     = st.substr(dot2 + 1);

    		// Flip a character in the PAYLOAD (not the signature).
    		// Pick a position that exists and isn't '.'.
    		if (payload.size() < 6) throw std::runtime_error("tamper case: payload too short");
    		char &c = payload[5];
    		c = (c == 'A') ? 'B' : 'A';

    		st = prefix + "." + payload + "." + sig;
    		body["st"] = st;

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

        if (ok) {
            bool good = true;

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
                // Print only derived values (safe)
                std::fprintf(stderr, "  got fingerprint_hex=%s\n", r.fingerprint_hex.c_str());
                std::fprintf(stderr, "  got st_hash_b64=%s\n", r.st_hash_b64.c_str());
                std::fprintf(stderr, "  got canonical_sha256_b64=%s\n", r.canonical_sha256_b64.c_str());
                failures++;
                continue;
            }

            std::printf("[%s] OK (sid=%s)\n", name.c_str(), r.sid.c_str());
        } else {
            std::printf("[%s] OK (expected failure rc=%d)\n", name.c_str(), (int)r.rc);
        }
    }

    if (failures) {
        std::fprintf(stderr, "[v4_vectors] FAILURES: %d\n", failures);
        return 1;
    }

    std::printf("[v4_vectors] ALL OK\n");
    return 0;
}
