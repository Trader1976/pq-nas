#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

// Durable Drop Zone link metadata.
//
// This struct represents the owner-created upload link itself:
// - who owns it
// - where uploads should land
// - expiry / size limits
// - counters for completed uploads
//
// Security note:
// token_hash stores only a hash of the public URL token. The raw token should
// only be returned at creation time and should not be persisted.
struct DropZoneRec {
    std::string id;
    std::string token_hash;

    std::string owner_fp;

    std::string name;
    std::string destination_path;

    // Empty means no password is required.
    // Non-empty should contain a password hash, never the plaintext password.
    std::string password_hash;

    std::int64_t created_epoch = 0;
    std::int64_t expires_epoch = 0;
    std::int64_t last_used_epoch = 0;

    // 0 means "no configured limit" at this layer.
    // Route/service code is still expected to apply global safety caps.
    std::uint64_t max_file_bytes = 0;
    std::uint64_t max_total_bytes = 0;

    // Denormalized counters maintained when record_upload() succeeds.
    std::uint64_t bytes_uploaded = 0;
    std::uint64_t upload_count = 0;

    bool disabled = false;
};

// Durable metadata for one completed upload.
//
// This is not the file content itself. File bytes are stored in the owner's
// destination folder. This record gives Drop Zone history, counters, and future
// hooks for scanning/quarantine workflows.
struct DropZoneUploadRec {
    std::string id;
    std::string drop_zone_id;

    // original_filename is what the uploader/browser provided.
    // stored_filename is the sanitized/collision-resolved filename actually
    // written on disk.
    std::string original_filename;
    std::string stored_filename;

    // Owner-side relative path where the file landed.
    //
    // Important privacy rule:
    // This may be useful for owner/admin views, but public endpoints should not
    // expose stored_path. Public views should normally show only stored_filename,
    // size_bytes, created_epoch, and optional uploader_name.
    std::string stored_path;

    std::uint64_t size_bytes = 0;
    std::string sha256;

    // Optional public-supplied metadata.
    std::string uploader_name;
    std::string uploader_message;

    // Audit/abuse-investigation metadata.
    // Route code should sanitize or limit values before persisting if needed.
    std::string remote_ip;
    std::string user_agent;

    std::int64_t created_epoch = 0;

    // Reserved for malware scanning / quarantine integration.
    // Current default means the file has landed but no scanner has processed it.
    std::string scan_status = "not_scanned";
};

// SQLite-backed persistence layer for Drop Zone metadata.
//
// Responsibilities:
// - open/init the Drop Zone SQLite database
// - create and list Drop Zone links
// - look up links by id or token hash
// - disable links
// - atomically record completed uploads and update counters
//
// Non-responsibilities:
// - HTTP routing
// - authentication / authorization decisions
// - public/private JSON shaping
// - path normalization and symlink safety
// - writing uploaded file bytes
//
// Those decisions belong in the route/service layer. Keeping this class narrow
// makes it easier to audit: this is a small storage/index API, not a policy
// engine.
class DropZoneIndex {
public:
    explicit DropZoneIndex(const std::filesystem::path& db_path);
    ~DropZoneIndex();

    DropZoneIndex(const DropZoneIndex&) = delete;
    DropZoneIndex& operator=(const DropZoneIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool insert(const DropZoneRec& rec, std::string* err);

    std::optional<DropZoneRec> get_by_id(const std::string& id,
                                         std::string* err);

    std::optional<DropZoneRec> get_by_token_hash(const std::string& token_hash,
                                                 std::string* err);

    std::vector<DropZoneRec> list_owner(const std::string& owner_fp,
                                        bool include_disabled,
                                        std::size_t limit,
                                        std::string* err);

    // Owner-scoped disable/enable.
    // The implementation enforces owner_fp in SQL so a caller cannot disable
    // another user's Drop Zone by id alone.
    bool set_disabled(const std::string& id,
                      const std::string& owner_fp,
                      bool disabled,
                      std::string* err);

    // Returns completed upload records for a Drop Zone.
    //
    // This returns full internal records. Public routes must project these down
    // to safe fields and must not expose stored_path, remote_ip, user_agent,
    // sha256, or uploader_message unless deliberately designing an owner/admin
    // endpoint.
    std::vector<DropZoneUploadRec> list_uploads(const std::string& drop_zone_id,
                                                std::size_t limit,
                                                std::string* err);

    // Atomically inserts one upload record and updates Drop Zone counters.
    //
    // Call this only after the uploaded file has been successfully written to
    // its final destination. If this fails, route code should remove the just-
    // written file so disk state and DB state do not diverge.
    bool record_upload(const DropZoneUploadRec& rec, std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;

    // Single connection + mutex model.
    //
    // SQLite also has busy_timeout/WAL enabled in open(), but this mutex keeps
    // this object internally serialized and avoids using one sqlite3* from
    // multiple threads at the same time.
    mutable std::mutex mu_;
};

} // namespace pqnas