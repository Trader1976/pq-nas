#include "verify_v4_crypto.h"

#include "pqnas_util.h"   // b64decode_loose, lower_ascii
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <iostream>

#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <dlfcn.h>
#include <unistd.h>
#include <limits.h>
#include <filesystem>


namespace pqnas {

// -----------------------------------------------------------------------------
// Local helpers (file-private)
// -----------------------------------------------------------------------------

static std::string exe_dir_local() {
    char buf[PATH_MAX] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    std::string p(buf, (size_t)n);
    return std::filesystem::path(p).parent_path().string();
}

static std::string b64_std_bytes(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

static std::string sha256_b64_std_bytes(const unsigned char* data, size_t len) {
    unsigned char h[32];
    SHA256(data, len, h);
    return b64_std_bytes(h, 32);
}

static std::string hex_lower(const unsigned char* b, size_t n) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; i++) {
        out[2*i]     = hexd[(b[i] >> 4) & 0xF];
        out[2*i + 1] = hexd[b[i] & 0xF];
    }
    return out;
}

std::string b64_std(const unsigned char* data, size_t len) {
    size_t outLen = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(outLen, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}
// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

std::string sha256_b64_std_str(const std::string& s) {
    return sha256_b64_std_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

std::string trim_slashes(std::string s) {
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

std::string fingerprint_from_pubkey_sha3_512_hex(const std::vector<unsigned char>& pubkey) {
    unsigned char h[64]; // SHA3-512 digest size

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, pubkey.data(), pubkey.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, h, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP sha3-512 failed");
    }

    EVP_MD_CTX_free(ctx);
    return hex_lower(h, sizeof(h));
}

std::string canonical_v4_phone_auth(const nlohmann::json& sp) {
    using json = nlohmann::json;
    json c;
    c["expires_at"] = sp.at("expires_at");
    c["issued_at"]  = sp.at("issued_at");
    c["nonce"]      = sp.at("nonce");
    c["origin"]     = sp.at("origin");
    c["rp_id_hash"] = sp.at("rp_id_hash");
    c["session_id"] = sp.at("session_id");
    c["sid"]        = sp.at("sid");
    c["st_hash"]    = sp.at("st_hash");
    return c.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
}

nlohmann::json verify_token_v4_ed25519(const std::string& token,
                                       const unsigned char pk[32]) {
    using json = nlohmann::json;

    auto dot1 = token.find('.');
    auto dot2 = (dot1 == std::string::npos) ? std::string::npos : token.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos)
        throw std::runtime_error("bad token format");

    std::string prefix      = token.substr(0, dot1);
    std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig_b64     = token.substr(dot2 + 1);

    if (prefix != "v4") throw std::runtime_error("bad token prefix");

    // token uses URLSAFE_NO_PADDING, but we decode loosely (authenticated container)
    auto payload_bytes = pqnas::b64decode_loose(payload_b64);
    auto sig_bytes     = pqnas::b64decode_loose(sig_b64);

    if (sig_bytes.size() != crypto_sign_BYTES)
        throw std::runtime_error("bad signature size");

    if (crypto_sign_verify_detached(sig_bytes.data(),
                                    payload_bytes.data(),
                                    (unsigned long long)payload_bytes.size(),
                                    pk) != 0) {
        throw std::runtime_error("invalid signature");
    }

    return json::parse(payload_bytes.begin(), payload_bytes.end());
}

// -----------------------------------------------------------------------------
// Native PQ verifier loader (from libdna_lib.so)
// Symbol: qgp_dsa87_verify
// -----------------------------------------------------------------------------

using qgp_dsa87_verify_fn = int (*)(const uint8_t* sig, size_t siglen,
                                   const uint8_t* msg, size_t msglen,
                                   const uint8_t* pk);

    static qgp_dsa87_verify_fn load_qgp_dsa87_verify() {
        static void* h = nullptr;
        static qgp_dsa87_verify_fn fn = nullptr;
        if (fn) return fn;

        auto try_open = [&](const std::string& p) -> void* {
            void* hh = dlopen(p.c_str(), RTLD_NOW);
            if (hh) return hh;
            return nullptr;
        };

        std::vector<std::string> candidates;

        if (const char* env = std::getenv("PQNAS_DNA_LIB")) {
            candidates.emplace_back(env);
        }

        candidates.emplace_back(exe_dir_local() + "/libdna_lib.so");

        // Stable repo path (works when running from build/bin with repo layout unchanged)
        candidates.emplace_back(
            (std::filesystem::path(exe_dir_local()) / ".." / ".." / "server" / "third_party" / "dna" / "lib" / "linux" / "x64" / "libdna_lib.so")
                .lexically_normal().string()
        );

        std::string last_err;
        for (const auto& libpath : candidates) {
            h = try_open(libpath);
            if (h) {
                fn = (qgp_dsa87_verify_fn)dlsym(h, "qgp_dsa87_verify");
                if (!fn) {
                    last_err = std::string("dlsym failed in ") + libpath;
                    dlclose(h);
                    h = nullptr;
                    continue;
                }
                return fn;
            } else {
                const char* e = dlerror();
                last_err = std::string("dlopen failed: ") + libpath + " : " + (e ? e : "");
            }
        }

        throw std::runtime_error(last_err.empty() ? "dlopen failed" : last_err);
    }


bool verify_mldsa87_signature_native(const std::vector<unsigned char>& pubkey,
                                     const std::vector<unsigned char>& msg,
                                     const std::vector<unsigned char>& sig) {
    auto fn = load_qgp_dsa87_verify();

    const int rc = fn(
        sig.data(), sig.size(),
        msg.data(), msg.size(),
        pubkey.data()
    );

    // Keep this log (it’s useful for field debugging), but it’s not secret.
    std::cerr << "[pq-verify] qgp_dsa87_verify rc=" << rc
              << " sig_len=" << sig.size()
              << " msg_len=" << msg.size()
              << " pk_len=" << pubkey.size()
              << "\n" << std::flush;

    // pqcrystals_*_verify returns 0 on success
    return (rc == 0);
}

} // namespace pqnas
