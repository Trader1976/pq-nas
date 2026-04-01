#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pqnas {

    struct PqOpenSnapshotV1 {
        std::uint64_t size_bytes = 0;
        std::int64_t mtime_epoch = 0;
        std::string sha256_hex;
    };

    struct PqWrappedKeyV1 {
        std::string mode;                 // "mlkem768_aes256gcm_v1"
        std::string recipient_device_id;
        std::string kem_alg;
        std::string sender_public_key_b64;
        std::string kem_ciphertext_b64;       // ML-KEM ciphertext for pq decapsulation mode
        std::string hkdf_salt_b64;
        std::string hkdf_info_b64;
        std::string wrap_iv_b64;
        std::string wrapped_cek_b64;      // AES-GCM(ciphertext||tag) of the random CEK
    };

    struct PqEncryptedPayloadV1 {
        std::string enc_alg;              // "AES-256-GCM"
        std::string iv_b64;
        std::string ciphertext_b64;       // AES-GCM(ciphertext||tag)
    };

    struct PqOpenEnvelopeV1 {
        int version = 1;
        std::string mode;                 // "x25519_aes256gcm_v1"
        std::string share_token;
        std::string file_name;
        std::string mime_type;            // keep "application/octet-stream" for MVP
        std::string recipient_device_id;
        std::string aad_b64;              // same AAD used for wrapped CEK + payload
        PqOpenSnapshotV1 snapshot;
        PqWrappedKeyV1 wrapped_key;
        PqEncryptedPayloadV1 payload;
    };

    bool build_pq_open_envelope_x25519_v1(
        const std::string& share_token,
        const std::string& file_name,
        const std::string& recipient_device_id,
        const std::string& recipient_public_key_b64,
        const std::vector<std::uint8_t>& plaintext,
        const std::string& aad_json_utf8,
        const PqOpenSnapshotV1& snapshot,
        PqOpenEnvelopeV1* out,
        std::string* err);

    bool build_pq_open_envelope_mlkem768_v1(
        const std::string& share_token,
        const std::string& file_name,
        const std::string& recipient_device_id,
        const std::string& recipient_public_key_b64,
        const std::vector<std::uint8_t>& plaintext,
        const std::string& aad_json_utf8,
        const PqOpenSnapshotV1& snapshot,
        PqOpenEnvelopeV1* out,
        std::string* err);

    bool pq_open_envelope_mlkem768_selftest_v1(std::string* err);

} // namespace pqnas