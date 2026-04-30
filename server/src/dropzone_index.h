#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct DropZoneRec {
    std::string id;
    std::string token_hash;

    std::string owner_fp;

    std::string name;
    std::string destination_path;

    std::string password_hash;

    std::int64_t created_epoch = 0;
    std::int64_t expires_epoch = 0;
    std::int64_t last_used_epoch = 0;

    std::uint64_t max_file_bytes = 0;
    std::uint64_t max_total_bytes = 0;
    std::uint64_t bytes_uploaded = 0;
    std::uint64_t upload_count = 0;

    bool disabled = false;
};

struct DropZoneUploadRec {
    std::string id;
    std::string drop_zone_id;

    std::string original_filename;
    std::string stored_filename;
    std::string stored_path;

    std::uint64_t size_bytes = 0;
    std::string sha256;

    std::string uploader_name;
    std::string uploader_message;

    std::string remote_ip;
    std::string user_agent;

    std::int64_t created_epoch = 0;
    std::string scan_status = "not_scanned";
};

    class DropZoneIndex {
    public:
        explicit DropZoneIndex(const std::filesystem::path& db_path);
        ~DropZoneIndex();

        DropZoneIndex(const DropZoneIndex&) = delete;
        DropZoneIndex& operator=(const DropZoneIndex&) = delete;

        bool open(std::string* err);
        bool init_schema(std::string* err);

        bool insert(const DropZoneRec& rec, std::string* err);

        std::optional<DropZoneRec> get_by_id(const std::string& id, std::string* err);
        std::optional<DropZoneRec> get_by_token_hash(const std::string& token_hash, std::string* err);

        std::vector<DropZoneRec> list_owner(const std::string& owner_fp,
                                            bool include_disabled,
                                            std::size_t limit,
                                            std::string* err);

        bool set_disabled(const std::string& id,
                          const std::string& owner_fp,
                          bool disabled,
                          std::string* err);

        std::vector<DropZoneUploadRec> list_uploads(const std::string& drop_zone_id,
                                            std::size_t limit,
                                            std::string* err);

        bool record_upload(const DropZoneUploadRec& rec, std::string* err);

    private:
        std::filesystem::path db_path_;
        sqlite3* db_ = nullptr;
        mutable std::mutex mu_;
    };

} // namespace pqnas