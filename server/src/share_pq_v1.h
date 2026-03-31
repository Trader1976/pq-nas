#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace pqnas {

struct PqShareSnapshotV1 {
    std::uint64_t size_bytes = 0;
    std::int64_t mtime_epoch = 0;
    std::string sha256_hex;
};

struct PqShareManifestV1 {
    int version = 1;
    std::string share_token;
    std::string kind; // "pq_recipient_enrolled_v1"
    std::string owner_fp;
    std::string rel_path;
    std::string created_at;
    std::string expires_at;
    std::string state; // "pending_enrollment" | "active" | "revoked"
    PqShareSnapshotV1 snapshot;
    std::vector<std::string> recipient_device_ids;
    std::string kem_alg;
    std::string sig_alg;
    std::string crypto_backend;
};

struct PqShareInviteV1 {
    int version = 1;
    std::string invite_id;
    std::string share_token;
    std::string owner_fp;
    std::string state; // "pending" | "claimed" | "revoked"
    std::string created_at;
    std::string expires_at;
    int max_claims = 1;
    int claim_count = 0;
    std::string claimed_recipient_device_id;
    std::string label_hint;
};

struct PqShareRecipientDeviceV1 {
    int version = 1;
    std::string owner_fp;
    std::string recipient_device_id;
    std::string label;
    std::string note;
    std::string state; // "active" | "revoked"
    std::string created_at;
    std::string updated_at;
    std::string last_used_at;
    std::string registered_via; // "invite"
    std::string invite_id;
    std::string kem_alg;
    std::string key_id;
    std::string public_key_b64;
};

struct PqShareRecipientSessionV1 {
    int version = 1;
    std::string session_id;
    std::string owner_fp;
    std::string recipient_device_id;
    std::string created_at;
    std::string expires_at;
    std::string last_used_at;
    std::string state; // "active" | "revoked"
};

struct PqShareCreateResultV1 {
    PqShareManifestV1 manifest;
    PqShareInviteV1 invite;
};

class SharePqStoreV1 {
public:
    explicit SharePqStoreV1(std::filesystem::path base_cfg_dir);

    bool load_manifest(const std::string& token, PqShareManifestV1* out, std::string* err) const;
    bool save_manifest(const PqShareManifestV1& m, std::string* err);
    bool delete_manifest(const std::string& token, std::string* err);

    bool load_invite(const std::string& invite_id, PqShareInviteV1* out, std::string* err) const;
    bool save_invite(const PqShareInviteV1& i, std::string* err);
    bool delete_invite(const std::string& invite_id, std::string* err);
    bool revoke_invites_for_share(const std::string& share_token, std::string* err);

    bool load_pending_invite_for_share(const std::string& share_token,
                                   PqShareInviteV1* out,
                                   std::string* err) const;
    bool load_latest_invite_for_share(const std::string& share_token,
                                      PqShareInviteV1* out,
                                      std::string* err) const;
    bool load_recipient_device(const std::string& owner_fp,
                               const std::string& recipient_device_id,
                               PqShareRecipientDeviceV1* out,
                               std::string* err) const;
    bool save_recipient_device(const PqShareRecipientDeviceV1& d, std::string* err);
    bool revoke_recipient_device(const std::string& owner_fp,
                                 const std::string& recipient_device_id,
                                 std::string* err);

    bool load_session(const std::string& session_id, PqShareRecipientSessionV1* out, std::string* err) const;
    bool save_session(const PqShareRecipientSessionV1& s, std::string* err);
    bool touch_session(const std::string& session_id, const std::string& now_iso, std::string* err);

    bool file_snapshot_from_abs_path(const std::filesystem::path& abs,
                                     PqShareSnapshotV1* out,
                                     std::string* err) const;
    bool verify_snapshot(const std::filesystem::path& abs,
                         const PqShareSnapshotV1& snap,
                         bool* out_match,
                         std::string* err) const;

    bool create_recipient_enrolled_share(const std::string& share_token,
                                         const std::string& owner_fp,
                                         const std::string& rel_path,
                                         const std::string& created_at,
                                         const std::string& expires_at,
                                         const std::filesystem::path& abs_path,
                                         long long invite_expires_sec,
                                         const std::string& recipient_label_hint,
                                         PqShareCreateResultV1* out,
                                         std::string* err);

    std::string invite_url_path(const std::string& invite_id) const;

    static std::string now_iso_utc_local();
    static std::string add_seconds_iso_utc_local(long long seconds);
    static bool iso_expired_local(const std::string& iso);
    static std::string random_id_b64url_local(std::size_t nbytes);
    static bool sha256_file_hex_local(const std::filesystem::path& abs,
                                      std::string* out_hex,
                                      std::string* err);
    bool find_active_recipient_device_by_public_key(
    const std::string& owner_fp,
    const std::string& kem_alg,
    const std::string& public_key_b64,
    PqShareRecipientDeviceV1* out,
    std::string* err) const;
    bool list_recipient_devices_for_owner(
    const std::string& owner_fp,
    std::vector<PqShareRecipientDeviceV1>* out,
    std::string* err) const;

private:
    mutable std::mutex mu_;
    std::filesystem::path base_cfg_dir_;

    std::filesystem::path manifests_dir() const;
    std::filesystem::path invites_dir() const;
    std::filesystem::path recipients_dir() const;
    std::filesystem::path sessions_dir() const;

    std::filesystem::path manifest_path(const std::string& token) const;
    std::filesystem::path invite_path(const std::string& invite_id) const;
    std::filesystem::path recipient_path(const std::string& owner_fp,
                                         const std::string& recipient_device_id) const;
    std::filesystem::path session_path(const std::string& session_id) const;

    static bool write_json_atomic_local(const std::filesystem::path& path,
                                        const std::string& text,
                                        std::string* err);
    static bool read_text_file_local(const std::filesystem::path& path,
                                     std::string* out,
                                     std::string* err);
};

} // namespace pqnas