#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct GalleryMetaRec {
    std::string scope_type;        // "user" | "workspace"
    std::string scope_id;          // user fp_hex or workspace_id
    std::string logical_rel_path;  // normalized logical file path inside the scope
    std::string item_type;         // "file" (v1), reserved for future

    int rating = 0;                // 0..5
    std::string tags_text;         // searchable freeform tags/metadata
    std::string notes_text;        // optional notes/caption

    std::uint64_t size_bytes = 0;
    std::int64_t mtime_epoch = 0;
    std::int64_t created_epoch = 0;
    std::int64_t updated_epoch = 0;
};

class GalleryMetaIndex {
public:
    explicit GalleryMetaIndex(const std::filesystem::path& db_path);
    ~GalleryMetaIndex();

    GalleryMetaIndex(const GalleryMetaIndex&) = delete;
    GalleryMetaIndex& operator=(const GalleryMetaIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    std::optional<GalleryMetaRec> get(const std::string& scope_type,
                                      const std::string& scope_id,
                                      const std::string& logical_rel_path,
                                      std::string* err);

    bool upsert(const GalleryMetaRec& rec, std::string* err);

    bool patch(const std::string& scope_type,
               const std::string& scope_id,
               const std::string& logical_rel_path,
               const std::optional<int>& rating,
               const std::optional<std::string>& tags_text,
               const std::optional<std::string>& notes_text,
               std::int64_t now_epoch,
               std::string* err);

    // Updates cached file facts only when a metadata row already exists.
    // This keeps overwrite-at-same-path metadata fresh without creating rows
    // for every uploaded file.
    bool touch_file_facts(const std::string& scope_type,
                          const std::string& scope_id,
                          const std::string& logical_rel_path,
                          std::uint64_t size_bytes,
                          std::int64_t mtime_epoch,
                          std::int64_t now_epoch,
                          std::string* err);

    bool rename_one(const std::string& scope_type,
                    const std::string& scope_id,
                    const std::string& from_rel,
                    const std::string& to_rel,
                    std::int64_t now_epoch,
                    std::string* err);

    bool rename_subtree(const std::string& scope_type,
                        const std::string& scope_id,
                        const std::string& from_prefix,
                        const std::string& to_prefix,
                        std::int64_t now_epoch,
                        std::string* err);

    bool erase(const std::string& scope_type,
               const std::string& scope_id,
               const std::string& logical_rel_path,
               std::string* err);

    // Removes exact prefix row and all descendants below prefix/.
    // Empty prefix removes all rows for the scope.
    bool erase_subtree(const std::string& scope_type,
                       const std::string& scope_id,
                       const std::string& logical_prefix,
                       std::string* err);

    // Returns rows exactly at prefix or beneath prefix/.
    // Empty prefix returns all rows in the scope.
    std::vector<GalleryMetaRec> list_under_prefix(const std::string& scope_type,
                                                  const std::string& scope_id,
                                                  const std::string& logical_prefix,
                                                  std::size_t limit,
                                                  std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
};

// Process-global pointer for route helpers, same usage pattern as file_location_index.
void set_gallery_meta_index(GalleryMetaIndex* idx);
GalleryMetaIndex* get_gallery_meta_index();

} // namespace pqnas