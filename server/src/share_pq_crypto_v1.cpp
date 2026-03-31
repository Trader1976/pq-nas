#include "share_pq_crypto_v1.h"
#include "share_pq_mlkem_v1.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace pqnas {
namespace {

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static std::string b64_encode(const std::vector<std::uint8_t>& in) {
    if (in.empty()) return std::string{};
    const int out_len = 4 * static_cast<int>((in.size() + 2) / 3);
    std::string out(out_len, '\0');
    const int n = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        reinterpret_cast<const unsigned char*>(in.data()),
        static_cast<int>(in.size()));
    if (n < 0) return std::string{};
    out.resize(static_cast<std::size_t>(n));
    return out;
}

static bool b64_decode(const std::string& in, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->clear();
    if (in.empty()) return true;

    int pad = 0;
    if (!in.empty() && in.back() == '=') ++pad;
    if (in.size() >= 2 && in[in.size() - 2] == '=') ++pad;

    std::vector<std::uint8_t> tmp(3 * ((in.size() + 3) / 4), 0);
    const int n = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(tmp.data()),
        reinterpret_cast<const unsigned char*>(in.data()),
        static_cast<int>(in.size()));
    if (n < 0) return false;

    tmp.resize(static_cast<std::size_t>(n - pad));
    *out = std::move(tmp);
    return true;
}

static bool random_bytes(std::size_t n, std::vector<std::uint8_t>* out) {
    if (!out) return false;
    out->assign(n, 0);
    return RAND_bytes(reinterpret_cast<unsigned char*>(out->data()), static_cast<int>(n)) == 1;
}

static bool make_x25519_ephemeral(EVP_PKEY** out_key, std::string* err) {
    if (!out_key) return false;
    *out_key = nullptr;

    EvpPkeyCtxPtr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    if (!kctx) {
        if (err) *err = "x25519_keygen_ctx_create_failed";
        return false;
    }
    if (EVP_PKEY_keygen_init(kctx.get()) <= 0) {
        if (err) *err = "x25519_keygen_init_failed";
        return false;
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &raw) <= 0 || !raw) {
        if (err) *err = "x25519_keygen_failed";
        return false;
    }
    *out_key = raw;
    return true;
}

static bool export_x25519_public_raw(EVP_PKEY* pkey, std::vector<std::uint8_t>* out, std::string* err) {
    if (!pkey || !out) return false;
    std::size_t n = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &n) <= 0 || n == 0) {
        if (err) *err = "x25519_export_public_len_failed";
        return false;
    }
    out->assign(n, 0);
    if (EVP_PKEY_get_raw_public_key(pkey, out->data(), &n) <= 0) {
        if (err) *err = "x25519_export_public_failed";
        return false;
    }
    out->resize(n);
    return true;
}

static bool import_x25519_public_raw(
    const std::vector<std::uint8_t>& raw_pub,
    EVP_PKEY** out_key,
    std::string* err) {
    if (!out_key) return false;
    *out_key = nullptr;

    if (raw_pub.empty()) {
        if (err) *err = "recipient_public_key_empty";
        return false;
    }

    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(raw_pub.data()),
        raw_pub.size());
    if (!p) {
        if (err) *err = "recipient_public_key_import_failed";
        return false;
    }
    *out_key = p;
    return true;
}

static bool derive_x25519_shared_secret(
    EVP_PKEY* local_private,
    EVP_PKEY* peer_public,
    std::vector<std::uint8_t>* out,
    std::string* err) {
    if (!local_private || !peer_public || !out) return false;

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new(local_private, nullptr), EVP_PKEY_CTX_free);
    if (!dctx) {
        if (err) *err = "x25519_derive_ctx_create_failed";
        return false;
    }
    if (EVP_PKEY_derive_init(dctx.get()) <= 0) {
        if (err) *err = "x25519_derive_init_failed";
        return false;
    }
    if (EVP_PKEY_derive_set_peer(dctx.get(), peer_public) <= 0) {
        if (err) *err = "x25519_set_peer_failed";
        return false;
    }

    std::size_t n = 0;
    if (EVP_PKEY_derive(dctx.get(), nullptr, &n) <= 0 || n == 0) {
        if (err) *err = "x25519_derive_len_failed";
        return false;
    }

    out->assign(n, 0);
    if (EVP_PKEY_derive(dctx.get(), out->data(), &n) <= 0) {
        if (err) *err = "x25519_derive_failed";
        return false;
    }
    out->resize(n);
    return true;
}

static bool hkdf_sha256(
    const std::vector<std::uint8_t>& ikm,
    const std::vector<std::uint8_t>& salt,
    const std::vector<std::uint8_t>& info,
    std::size_t out_len,
    std::vector<std::uint8_t>* out,
    std::string* err) {
    if (!out) return false;

    EvpPkeyCtxPtr hctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    if (!hctx) {
        if (err) *err = "hkdf_ctx_create_failed";
        return false;
    }
    if (EVP_PKEY_derive_init(hctx.get()) <= 0) {
        if (err) *err = "hkdf_init_failed";
        return false;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(hctx.get(), EVP_sha256()) <= 0) {
        if (err) *err = "hkdf_set_md_failed";
        return false;
    }
    if (!salt.empty() && EVP_PKEY_CTX_set1_hkdf_salt(hctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0) {
        if (err) *err = "hkdf_set_salt_failed";
        return false;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(hctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0) {
        if (err) *err = "hkdf_set_key_failed";
        return false;
    }
    if (!info.empty() && EVP_PKEY_CTX_add1_hkdf_info(hctx.get(), info.data(), static_cast<int>(info.size())) <= 0) {
        if (err) *err = "hkdf_set_info_failed";
        return false;
    }

    out->assign(out_len, 0);
    std::size_t n = out_len;
    if (EVP_PKEY_derive(hctx.get(), out->data(), &n) <= 0) {
        if (err) *err = "hkdf_derive_failed";
        return false;
    }
    out->resize(n);
    return true;
}

static bool aes_256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& iv,
    const std::vector<std::uint8_t>& aad,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>* out,
    std::string* err) {
    if (!out) return false;
    if (key.size() != 32) {
        if (err) *err = "aes256gcm_bad_key_len";
        return false;
    }
    if (iv.empty()) {
        if (err) *err = "aes256gcm_bad_iv_len";
        return false;
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        if (err) *err = "aes256gcm_ctx_create_failed";
        return false;
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        if (err) *err = "aes256gcm_init_failed";
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        if (err) *err = "aes256gcm_set_ivlen_failed";
        return false;
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        if (err) *err = "aes256gcm_set_key_failed";
        return false;
    }

    int n = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), static_cast<int>(aad.size())) != 1) {
            if (err) *err = "aes256gcm_aad_failed";
            return false;
        }
    }

    std::vector<std::uint8_t> ct(plaintext.size() + 16, 0);
    int total = 0;

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ct.data(), &n, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            if (err) *err = "aes256gcm_encrypt_failed";
            return false;
        }
        total += n;
    }

    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + total, &n) != 1) {
        if (err) *err = "aes256gcm_final_failed";
        return false;
    }
    total += n;

    unsigned char tag[16] = {0};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        if (err) *err = "aes256gcm_get_tag_failed";
        return false;
    }

    ct.resize(static_cast<std::size_t>(total) + 16);
    std::memcpy(ct.data() + total, tag, 16);
    *out = std::move(ct);
    return true;
}

static std::vector<std::uint8_t> to_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

} // namespace

bool build_pq_open_envelope_x25519_v1(
    const std::string& share_token,
    const std::string& file_name,
    const std::string& recipient_device_id,
    const std::string& recipient_public_key_b64,
    const std::vector<std::uint8_t>& plaintext,
    const std::string& aad_json_utf8,
    const PqOpenSnapshotV1& snapshot,
    PqOpenEnvelopeV1* out,
    std::string* err) {
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    std::vector<std::uint8_t> recipient_pub_raw;
    if (!b64_decode(recipient_public_key_b64, &recipient_pub_raw)) {
        if (err) *err = "recipient_public_key_b64_invalid";
        return false;
    }

    EVP_PKEY* eph_raw = nullptr;
    if (!make_x25519_ephemeral(&eph_raw, err)) return false;
    EvpPkeyPtr eph(eph_raw, EVP_PKEY_free);

    EVP_PKEY* peer_raw = nullptr;
    if (!import_x25519_public_raw(recipient_pub_raw, &peer_raw, err)) return false;
    EvpPkeyPtr peer(peer_raw, EVP_PKEY_free);

    std::vector<std::uint8_t> shared_secret;
    if (!derive_x25519_shared_secret(eph.get(), peer.get(), &shared_secret, err)) return false;

    std::vector<std::uint8_t> eph_pub_raw;
    if (!export_x25519_public_raw(eph.get(), &eph_pub_raw, err)) return false;

    std::vector<std::uint8_t> hkdf_salt;
    if (!random_bytes(32, &hkdf_salt)) {
        if (err) *err = "random_hkdf_salt_failed";
        return false;
    }

    const std::vector<std::uint8_t> hkdf_info = to_bytes("pqnas-share-open-x25519-wrap-v1");
    std::vector<std::uint8_t> wrap_key;
    if (!hkdf_sha256(shared_secret, hkdf_salt, hkdf_info, 32, &wrap_key, err)) return false;

    std::vector<std::uint8_t> cek;
    if (!random_bytes(32, &cek)) {
        if (err) *err = "random_cek_failed";
        return false;
    }

    std::vector<std::uint8_t> aad = to_bytes(aad_json_utf8);

    std::vector<std::uint8_t> wrap_iv;
    if (!random_bytes(12, &wrap_iv)) {
        if (err) *err = "random_wrap_iv_failed";
        return false;
    }

    std::vector<std::uint8_t> wrapped_cek;
    if (!aes_256_gcm_encrypt(wrap_key, wrap_iv, aad, cek, &wrapped_cek, err)) return false;

    std::vector<std::uint8_t> payload_iv;
    if (!random_bytes(12, &payload_iv)) {
        if (err) *err = "random_payload_iv_failed";
        return false;
    }

    std::vector<std::uint8_t> ciphertext;
    if (!aes_256_gcm_encrypt(cek, payload_iv, aad, plaintext, &ciphertext, err)) return false;

    PqOpenEnvelopeV1 env;
    env.version = 1;
    env.mode = "x25519_aes256gcm_v1";
    env.share_token = share_token;
    env.file_name = file_name;
    env.mime_type = "application/octet-stream";
    env.recipient_device_id = recipient_device_id;
    env.aad_b64 = b64_encode(aad);
    env.snapshot = snapshot;

    env.wrapped_key.mode = "x25519_hkdf_sha256_aes256gcm_v1";
    env.wrapped_key.recipient_device_id = recipient_device_id;
    env.wrapped_key.kem_alg = "X25519";
    env.wrapped_key.sender_public_key_b64 = b64_encode(eph_pub_raw);
    env.wrapped_key.kem_ciphertext_b64.clear();
    env.wrapped_key.hkdf_salt_b64 = b64_encode(hkdf_salt);
    env.wrapped_key.hkdf_info_b64 = b64_encode(hkdf_info);
    env.wrapped_key.wrap_iv_b64 = b64_encode(wrap_iv);
    env.wrapped_key.wrapped_cek_b64 = b64_encode(wrapped_cek);

    env.payload.enc_alg = "AES-256-GCM";
    env.payload.iv_b64 = b64_encode(payload_iv);
    env.payload.ciphertext_b64 = b64_encode(ciphertext);

    *out = std::move(env);
    return true;
}

bool build_pq_open_envelope_mlkem768_v1(
    const std::string& share_token,
    const std::string& file_name,
    const std::string& recipient_device_id,
    const std::string& recipient_public_key_b64,
    const std::vector<std::uint8_t>& plaintext,
    const std::string& aad_json_utf8,
    const PqOpenSnapshotV1& snapshot,
    PqOpenEnvelopeV1* out,
    std::string* err) {
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    std::vector<std::uint8_t> recipient_pub_raw;
    if (!b64_decode(recipient_public_key_b64, &recipient_pub_raw)) {
        if (err) *err = "recipient_public_key_b64_invalid";
        return false;
    }

    MlKem768EncapResultV1 encap;
    std::string mlkem_err;
    if (!mlkem768_encapsulate_v1(recipient_pub_raw, &encap, &mlkem_err)) {
        if (err) *err = mlkem_err.empty() ? "mlkem768_encapsulate_failed" : mlkem_err;
        return false;
    }

    std::vector<std::uint8_t> hkdf_salt;
    if (!random_bytes(32, &hkdf_salt)) {
        if (err) *err = "random_hkdf_salt_failed";
        return false;
    }

    const std::vector<std::uint8_t> hkdf_info = to_bytes("pqnas-share-open-mlkem768-wrap-v1");
    std::vector<std::uint8_t> wrap_key;
    if (!hkdf_sha256(encap.shared_secret, hkdf_salt, hkdf_info, 32, &wrap_key, err)) return false;

    std::vector<std::uint8_t> cek;
    if (!random_bytes(32, &cek)) {
        if (err) *err = "random_cek_failed";
        return false;
    }

    std::vector<std::uint8_t> aad = to_bytes(aad_json_utf8);

    std::vector<std::uint8_t> wrap_iv;
    if (!random_bytes(12, &wrap_iv)) {
        if (err) *err = "random_wrap_iv_failed";
        return false;
    }

    std::vector<std::uint8_t> wrapped_cek;
    if (!aes_256_gcm_encrypt(wrap_key, wrap_iv, aad, cek, &wrapped_cek, err)) return false;

    std::vector<std::uint8_t> payload_iv;
    if (!random_bytes(12, &payload_iv)) {
        if (err) *err = "random_payload_iv_failed";
        return false;
    }

    std::vector<std::uint8_t> ciphertext;
    if (!aes_256_gcm_encrypt(cek, payload_iv, aad, plaintext, &ciphertext, err)) return false;

    PqOpenEnvelopeV1 env;
    env.version = 1;
    env.mode = "mlkem768_aes256gcm_v1";
    env.share_token = share_token;
    env.file_name = file_name;
    env.mime_type = "application/octet-stream";
    env.recipient_device_id = recipient_device_id;
    env.aad_b64 = b64_encode(aad);
    env.snapshot = snapshot;

    env.wrapped_key.mode = "mlkem768_hkdf_sha256_aes256gcm_v1";
    env.wrapped_key.recipient_device_id = recipient_device_id;
    env.wrapped_key.kem_alg = "ML-KEM-768";
    env.wrapped_key.sender_public_key_b64.clear();
    env.wrapped_key.kem_ciphertext_b64 = b64_encode(encap.ciphertext);
    env.wrapped_key.hkdf_salt_b64 = b64_encode(hkdf_salt);
    env.wrapped_key.hkdf_info_b64 = b64_encode(hkdf_info);
    env.wrapped_key.wrap_iv_b64 = b64_encode(wrap_iv);
    env.wrapped_key.wrapped_cek_b64 = b64_encode(wrapped_cek);

    env.payload.enc_alg = "AES-256-GCM";
    env.payload.iv_b64 = b64_encode(payload_iv);
    env.payload.ciphertext_b64 = b64_encode(ciphertext);

    *out = std::move(env);
    return true;
}

bool openssl_has_mlkem_v1() {
    return OpenSSL_version_num() >= 0x30500000L;
}

} // namespace pqnas