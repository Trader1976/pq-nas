#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace pqnas {

struct GalleryAlbumRec {
    std::string album_id;
    std::string scope_type;   // "user" | "workspace"
    std::string scope_id;     // user fp_hex or workspace_id
    std::string name;
    std::string description;
    std::string cover_logical_rel_path;

    std::int64_t created_epoch = 0;
    std::int64_t updated_epoch = 0;
    std::uint64_t item_count = 0;
};

struct GalleryAlbumItemRec {
    std::string album_id;
    std::string scope_type;
    std::string scope_id;
    std::string logical_rel_path;
    std::int64_t added_epoch = 0;
    std::int64_t sort_order = 0;
};

class GalleryAlbumsIndex {
public:
    explicit GalleryAlbumsIndex(const std::filesystem::path& db_path);
    ~GalleryAlbumsIndex();

    GalleryAlbumsIndex(const GalleryAlbumsIndex&) = delete;
    GalleryAlbumsIndex& operator=(const GalleryAlbumsIndex&) = delete;

    bool open(std::string* err);
    bool init_schema(std::string* err);

    bool create_album(const GalleryAlbumRec& rec, std::string* err);

    std::optional<GalleryAlbumRec> get_album(const std::string& scope_type,
                                             const std::string& scope_id,
                                             const std::string& album_id,
                                             std::string* err);

    std::vector<GalleryAlbumRec> list_albums(const std::string& scope_type,
                                             const std::string& scope_id,
                                             std::size_t limit,
                                             std::string* err);

    bool rename_album(const std::string& scope_type,
                      const std::string& scope_id,
                      const std::string& album_id,
                      const std::string& name,
                      const std::string& description,
                      std::int64_t now_epoch,
                      std::string* err);

    bool set_album_cover(const std::string& scope_type,
                     const std::string& scope_id,
                     const std::string& album_id,
                     const std::string& logical_rel_path,
                     std::int64_t now_epoch,
                     std::string* err);

    bool delete_album(const std::string& scope_type,
                      const std::string& scope_id,
                      const std::string& album_id,
                      std::string* err);

    bool add_items(const std::string& scope_type,
                   const std::string& scope_id,
                   const std::string& album_id,
                   const std::vector<std::string>& logical_rel_paths,
                   std::int64_t now_epoch,
                   std::string* err);

    std::vector<GalleryAlbumItemRec> list_items(const std::string& scope_type,
                                                const std::string& scope_id,
                                                const std::string& album_id,
                                                std::size_t limit,
                                                std::string* err);

    bool remove_items(const std::string& scope_type,
                      const std::string& scope_id,
                      const std::string& album_id,
                      const std::vector<std::string>& logical_rel_paths,
                      std::string* err);

private:
    std::filesystem::path db_path_;
    sqlite3* db_ = nullptr;
};

void set_gallery_albums_index(GalleryAlbumsIndex* idx);
GalleryAlbumsIndex* get_gallery_albums_index();

} // namespace pqnas