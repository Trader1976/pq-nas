#pragma once

#include "echo_stack_index.h"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct EchoStackContentSearchHit {
    std::string item_id;
    std::string url;
    std::string final_url;
    std::string title;
    std::string description;
    std::string tags_text;
    std::string collection;
    std::string source_file;
    std::string snippet;
    double score = 0.0;
    std::int64_t indexed_epoch = 0;
};

class EchoStackContentIndex {
public:
    explicit EchoStackContentIndex(const std::filesystem::path& db_path);
    ~EchoStackContentIndex();

    EchoStackContentIndex(const EchoStackContentIndex&) = delete;
    EchoStackContentIndex& operator=(const EchoStackContentIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool upsert(const EchoStackItemRec& item,
                const std::string& body_text,
                const std::string& source_file,
                std::int64_t indexed_epoch,
                std::string* err);

    bool remove_owner_item(const std::string& owner_fp,
                           const std::string& item_id,
                           std::string* err);

    bool clear_owner(const std::string& owner_fp, std::string* err);

    std::vector<EchoStackContentSearchHit> search_owner(
        const std::string& owner_fp,
        const std::string& query,
        std::size_t limit,
        std::string* err
    );

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
    mutable std::mutex mu_;
};

} // namespace pqnas
