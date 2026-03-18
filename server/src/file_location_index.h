#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

    struct FileLocationRecord {
        std::string fp;
        std::string logical_rel_path;
        std::string current_pool;
        std::string physical_path;
        std::string tier_state;
        std::uint64_t size_bytes = 0;
        std::int64_t mtime_epoch = 0;
        std::int64_t created_epoch = 0;
        std::int64_t updated_epoch = 0;
        std::int64_t version = 1;
    };

	struct FileLocationTierSummary {
    std::uint64_t landing_files = 0;
    std::uint64_t landing_bytes = 0;
    std::uint64_t migrating_files = 0;
    std::uint64_t migrating_bytes = 0;
    std::uint64_t capacity_files = 0;
    std::uint64_t capacity_bytes = 0;
    std::uint64_t total_files = 0;
    std::uint64_t total_bytes = 0;
	};

    struct LogicalListItem {
        std::string name;
        std::string type;          // "file" or "dir"
        std::uint64_t size_bytes = 0;
        std::int64_t mtime_epoch = 0;
    };

    std::vector<LogicalListItem> list_immediate_children(const std::string& fp,
                                                         const std::string& dir_rel,
                                                         std::string* err);

class FileLocationIndex {
public:
    explicit FileLocationIndex(const std::filesystem::path& db_path);
    ~FileLocationIndex();

    FileLocationIndex(const FileLocationIndex&) = delete;
    FileLocationIndex& operator=(const FileLocationIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    std::optional<FileLocationRecord> get(const std::string& fp,
                                          const std::string& logical_rel_path,
                                          std::string* err);

    std::vector<LogicalListItem> list_immediate_children(const std::string& fp,
                                                         const std::string& rel_dir_norm,
                                                         std::string* err);

bool rename_one(const std::string& fp,
                const std::string& from_logical_rel_path,
                const std::string& to_logical_rel_path,
                const std::string& expected_old_physical_path,
                const std::string& new_physical_path,
                std::int64_t now_epoch,
                std::string* err);

bool rename_subtree(const std::string& fp,
                    const std::string& from_logical_prefix,
                    const std::string& to_logical_prefix,
                    std::int64_t now_epoch,
                    std::string* err);

    bool rename_logical_prefix(const std::string& fp,
                           const std::string& from_prefix,
                           const std::string& to_prefix,
                           std::string* err);

	std::vector<FileLocationRecord> list_subtree_records(const std::string& fp,
                                                     const std::string& logical_prefix,
                                                     std::string* err);

	bool logical_dir_exists(const std::string& fp,
                        	const std::string& logical_prefix,
                        	std::string* err);

	bool erase_subtree(const std::string& fp,
                   	const std::string& logical_prefix,
                   	std::string* err);

    bool upsert_landing_file(const FileLocationRecord& rec, std::string* err);

    bool erase(const std::string& fp,
               const std::string& logical_rel_path,
               std::string* err);

	bool logical_file_exists_exact(const std::string& fp,
                               const std::string& logical_rel_path,
                               std::string* err);

    bool switch_to_capacity(const std::string& fp,
                            const std::string& logical_rel_path,
                            const std::string& expected_src_physical_path,
                            const std::string& new_pool,
                            const std::string& new_physical_path,
                            std::int64_t new_mtime_epoch,
                            std::string* err);

    bool mark_migrating(const std::string& fp,
                    const std::string& logical_rel_path,
                    const std::string& expected_src_physical_path,
                    std::string* err);

	bool mark_landing_again(const std::string& fp,
                        const std::string& logical_rel_path,
                        const std::string& expected_src_physical_path,
                        std::string* err);

	bool get_tier_summary(FileLocationTierSummary* out, std::string* err);

    std::vector<FileLocationRecord> list_landing_candidates(std::size_t limit,
                                                            std::string* err);

	std::vector<FileLocationRecord> list_stuck_migrating_candidates(std::int64_t older_than_epoch,
                                                                std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
};


} // namespace pqnas