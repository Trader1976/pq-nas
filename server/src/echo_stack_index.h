#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct EchoStackItemRec {
    std::string id;
    std::string owner_fp;

    std::string url;
    std::string final_url;
    std::string title;
    std::string description;
    std::string site_name;
    std::string favicon_url;
    std::string preview_image_url;

    std::string tags_text;
    std::string collection;
    std::string notes;

    std::string read_state = "unread";
    bool favorite = false;

    // Archive fields are present in v1, but archive execution comes later.
    std::string archive_status = "none"; // none | queued | archiving | archived | failed
    std::string archive_error;
    std::string archive_rel_dir;
    std::uint64_t archive_bytes = 0;

    std::int64_t created_epoch = 0;
    std::int64_t updated_epoch = 0;
    std::int64_t archived_epoch = 0;
};

class EchoStackIndex {
public:
    explicit EchoStackIndex(const std::filesystem::path& db_path);
    ~EchoStackIndex();

    EchoStackIndex(const EchoStackIndex&) = delete;
    EchoStackIndex& operator=(const EchoStackIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool insert(const EchoStackItemRec& rec, std::string* err);

    std::optional<EchoStackItemRec> get_owner_item(const std::string& owner_fp,
                                                   const std::string& id,
                                                   std::string* err);

    std::vector<EchoStackItemRec> list_owner(const std::string& owner_fp,
                                             const std::string& query,
                                             std::size_t limit,
                                             std::string* err);

    bool update_mutable(const EchoStackItemRec& rec, std::string* err);

    bool delete_owner_item(const std::string& owner_fp,
                           const std::string& id,
                           std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
    mutable std::mutex mu_;
};

} // namespace pqnas
