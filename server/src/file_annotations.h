#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace pqnas {

struct FileNoteRec {
    std::string scope_type;
    std::string scope_id;
    std::string logical_rel_path;
    std::string item_kind;
    std::string description;
    std::string updated_by_fp;
    std::int64_t created_at_epoch = 0;
    std::int64_t updated_at_epoch = 0;
};

class FileAnnotationsStore {
public:
    explicit FileAnnotationsStore(std::filesystem::path db_path);

    bool init(std::string* err = nullptr) const;

    std::optional<FileNoteRec> get_note(const std::string& scope_type,
                                        const std::string& scope_id,
                                        const std::string& logical_rel_path,
                                        std::string* err = nullptr) const;

    bool upsert_note(const FileNoteRec& rec, std::string* err = nullptr) const;

private:
    std::filesystem::path db_path_;
};

} // namespace pqnas
