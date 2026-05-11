#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pqnas {

struct FileLockRec {
    std::string scope_type;       // user | workspace
    std::string scope_id;         // user fp | workspace_id
    std::string logical_rel_path;
    std::string item_kind;        // file | dir | unknown

    std::string locked_by_fp;
    std::string note;

    std::int64_t created_at_epoch = 0;
    std::int64_t updated_at_epoch = 0;
    std::int64_t expires_at_epoch = 0; // 0 = manual/no expiry
};

class FileLocksStore {
public:
    explicit FileLocksStore(std::filesystem::path db_path);

    bool init(std::string* err = nullptr) const;

    std::optional<FileLockRec> get_lock(const std::string& scope_type,
                                        const std::string& scope_id,
                                        const std::string& logical_rel_path,
                                        std::string* err = nullptr) const;

    bool upsert_lock(const FileLockRec& rec, std::string* err = nullptr) const;

    bool delete_lock(const std::string& scope_type,
                     const std::string& scope_id,
                     const std::string& logical_rel_path,
                     std::string* err = nullptr) const;

    std::vector<FileLockRec> list_locks_for_scope(const std::string& scope_type,
                                                  const std::string& scope_id,
                                                  std::string* err = nullptr) const;

    bool delete_expired(std::int64_t now_epoch, std::string* err = nullptr) const;

    // Finds a live lock that conflicts with logical_rel_path.
    //
    // Conflict rules:
    // - exact path lock blocks that path
    // - parent folder lock blocks children
    // - child lock blocks destructive subtree operations on the parent
    std::optional<FileLockRec> find_live_conflict(const std::string& scope_type,
                                                  const std::string& scope_id,
                                                  const std::string& logical_rel_path,
                                                  std::int64_t now_epoch,
                                                  std::string* err = nullptr) const;

private:
    std::filesystem::path db_path_;
};

bool file_lock_is_live(const FileLockRec& rec, std::int64_t now_epoch);

} // namespace pqnas
