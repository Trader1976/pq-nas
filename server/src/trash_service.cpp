#include "trash_service.h"

#include "runtime_paths.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <random>
#include <sstream>
#include <system_error>
#include <ctime>
#include <utility>

namespace pqnas {
namespace {

static constexpr std::int64_t k_default_trash_retention_seconds = 30LL * 24LL * 60LL * 60LL;

static std::int64_t now_epoch_local() {
    using namespace std::chrono;
    return static_cast<std::int64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

static std::string random_hex_local(std::size_t nbytes) {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    static const char* kHex = "0123456789abcdef";

    std::string out;
    out.reserve(nbytes * 2);

    for (std::size_t i = 0; i < nbytes; ++i) {
        const unsigned v = static_cast<unsigned>(rng() & 0xFFu);
        out.push_back(kHex[(v >> 4) & 0x0Fu]);
        out.push_back(kHex[v & 0x0Fu]);
    }

    return out;
}

static std::string make_trash_id_local() {
    std::ostringstream oss;
    oss << "trash_"
        << static_cast<long long>(now_epoch_local())
        << "_"
        << random_hex_local(8);
    return oss.str();
}

static std::string isoish_stamp_local() {
    std::time_t tt = static_cast<std::time_t>(now_epoch_local());
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "%04d%02d%02d-%02d%02d%02d",
                  tm.tm_year + 1900,
                  tm.tm_mon + 1,
                  tm.tm_mday,
                  tm.tm_hour,
                  tm.tm_min,
                  tm.tm_sec);
    return std::string(buf);
}

static bool ensure_parent_dir_local(const std::filesystem::path& p, std::string* err) {
    if (err) err->clear();
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }
    return true;
}

static bool remove_path_recursive_local(const std::filesystem::path& p, std::string* err) {
    if (err) err->clear();
    std::error_code ec;

    auto st = std::filesystem::symlink_status(p, ec);
    if (ec) {
        if (err) *err = "symlink_status failed: " + ec.message();
        return false;
    }
    if (!std::filesystem::exists(st)) {
        return true;
    }
    if (std::filesystem::is_symlink(st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }

    if (std::filesystem::is_directory(st)) {
        std::filesystem::remove_all(p, ec);
    } else {
        std::filesystem::remove(p, ec);
    }

    if (ec) {
        if (err) *err = "remove failed: " + ec.message();
        return false;
    }
    return true;
}

static bool copy_file_local(const std::filesystem::path& src,
                            const std::filesystem::path& dst,
                            std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    auto st = std::filesystem::symlink_status(src, ec);
    if (ec) {
        if (err) *err = "source stat failed: " + ec.message();
        return false;
    }
    if (!std::filesystem::exists(st) || !std::filesystem::is_regular_file(st)) {
        if (err) *err = "source is not a regular file";
        return false;
    }

    if (!ensure_parent_dir_local(dst, err)) return false;

    std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        if (err) *err = "copy_file failed: " + ec.message();
        return false;
    }

    return true;
}

static bool copy_tree_local(const std::filesystem::path& src,
                            const std::filesystem::path& dst,
                            std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    auto root_st = std::filesystem::symlink_status(src, ec);
    if (ec) {
        if (err) *err = "source stat failed: " + ec.message();
        return false;
    }
    if (!std::filesystem::exists(root_st)) {
        if (err) *err = "source not found";
        return false;
    }
    if (std::filesystem::is_symlink(root_st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }
    if (!std::filesystem::is_directory(root_st)) {
        if (err) *err = "source is not a directory";
        return false;
    }

    std::filesystem::create_directories(dst, ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    for (std::filesystem::recursive_directory_iterator it(
             src, std::filesystem::directory_options::skip_permission_denied, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        const auto cur = it->path();

        std::error_code ec2;
        auto st = std::filesystem::symlink_status(cur, ec2);
        if (ec2) {
            if (err) *err = "tree stat failed: " + ec2.message();
            return false;
        }
        if (std::filesystem::is_symlink(st)) {
            if (err) *err = "symlinks not supported";
            return false;
        }

        const auto rel = std::filesystem::relative(cur, src, ec2);
        if (ec2) {
            if (err) *err = "relative path failed: " + ec2.message();
            return false;
        }

        const auto dst_cur = dst / rel;

        if (std::filesystem::is_directory(st)) {
            std::filesystem::create_directories(dst_cur, ec2);
            if (ec2) {
                if (err) *err = "create_directories failed: " + ec2.message();
                return false;
            }
        } else if (std::filesystem::is_regular_file(st)) {
            if (!copy_file_local(cur, dst_cur, err)) return false;
        } else {
            if (err) *err = "unsupported file type in tree";
            return false;
        }
    }

    if (ec) {
        if (err) *err = "tree walk failed: " + ec.message();
        return false;
    }

    return true;
}

static bool move_path_local(const std::filesystem::path& src,
                            const std::filesystem::path& dst,
                            std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    auto st = std::filesystem::symlink_status(src, ec);
    if (ec) {
        if (err) *err = "source stat failed: " + ec.message();
        return false;
    }
    if (!std::filesystem::exists(st)) {
        if (err) *err = "source not found";
        return false;
    }
    if (std::filesystem::is_symlink(st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }

    if (!ensure_parent_dir_local(dst, err)) return false;

    std::filesystem::rename(src, dst, ec);
    if (!ec) return true;

    // Fallback for cross-device or other rename failures: copy then remove source.
    std::string cerr;
    if (std::filesystem::is_directory(st)) {
        if (!copy_tree_local(src, dst, &cerr)) {
            if (err) *err = "rename failed: " + ec.message() + "; copy fallback failed: " + cerr;
            return false;
        }
    } else if (std::filesystem::is_regular_file(st)) {
        if (!copy_file_local(src, dst, &cerr)) {
            if (err) *err = "rename failed: " + ec.message() + "; copy fallback failed: " + cerr;
            return false;
        }
    } else {
        if (err) *err = "unsupported file type";
        return false;
    }

    std::string derr;
    if (!remove_path_recursive_local(src, &derr)) {
        if (err) *err = "copy fallback succeeded but source cleanup failed: " + derr;
        return false;
    }

    return true;
}

static std::filesystem::path build_conflict_rename_target_local(const std::filesystem::path& dst) {
    const auto parent = dst.parent_path();
    const auto stem = dst.stem().string();
    const auto ext = dst.extension().string();

    if (ext.empty()) {
        return parent / (dst.filename().string() + " (restored " + isoish_stamp_local() + ")");
    }

    return parent / (stem + " (restored " + isoish_stamp_local() + ")" + ext);
}

static std::string trash_rel_payload_path_local(const std::string& scope_type,
                                                const std::string& scope_id,
                                                const std::string& trash_id) {
    std::filesystem::path rel;
    if (scope_type == "workspace") {
        rel /= "workspaces";
    } else {
        rel /= "users";
    }
    rel /= scope_id;
    rel /= trash_id;
    rel /= "payload";
    return rel.generic_string();
}

} // namespace

TrashService::TrashService(TrashIndex* index)
    : index_(index) {}

void TrashService::set_restore_reindexer(RestoreReindexFn fn) {
    restore_reindexer_ = std::move(fn);
}

void TrashService::set_restore_unindexer(RestoreUnindexFn fn) {
    restore_unindexer_ = std::move(fn);
}
bool TrashService::infer_storage_root_for_logical_path(const std::filesystem::path& payload_abs_path,
                                                       const std::string& logical_rel_path,
                                                       std::filesystem::path* out_storage_root,
                                                       std::string* err) {
    if (err) err->clear();
    if (!out_storage_root) {
        if (err) *err = "null out_storage_root";
        return false;
    }
    if (logical_rel_path.empty()) {
        if (err) *err = "empty logical_rel_path";
        return false;
    }

    std::filesystem::path root = payload_abs_path.lexically_normal();
    const std::filesystem::path rel(logical_rel_path);

    for (const auto& part : rel) {
        (void)part;
        const auto parent = root.parent_path();
        if (parent.empty() || parent == root) {
            if (err) *err = "failed to derive storage_root";
            return false;
        }
        root = parent;
    }

    *out_storage_root = root;
    return true;
}

bool TrashService::scan_payload_tree(const std::filesystem::path& abs_path,
                                     std::uint64_t* out_file_count,
                                     std::uint64_t* out_size_bytes,
                                     std::string* err) {
    if (err) err->clear();
    if (out_file_count) *out_file_count = 0;
    if (out_size_bytes) *out_size_bytes = 0;
    if (!out_file_count || !out_size_bytes) {
        if (err) *err = "null out parameter";
        return false;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs_path, ec);
    if (ec) {
        if (err) *err = "symlink_status failed: " + ec.message();
        return false;
    }
    if (!std::filesystem::exists(st)) {
        if (err) *err = "path not found";
        return false;
    }
    if (std::filesystem::is_symlink(st)) {
        if (err) *err = "symlinks not supported";
        return false;
    }

    if (std::filesystem::is_regular_file(st)) {
        *out_file_count = 1;
        const auto sz = std::filesystem::file_size(abs_path, ec);
        if (ec) {
            if (err) *err = "file_size failed: " + ec.message();
            return false;
        }
        *out_size_bytes = static_cast<std::uint64_t>(sz);
        return true;
    }

    if (!std::filesystem::is_directory(st)) {
        if (err) *err = "unsupported path type";
        return false;
    }

    std::uint64_t files = 0;
    std::uint64_t bytes = 0;

    for (std::filesystem::recursive_directory_iterator it(
             abs_path, std::filesystem::directory_options::skip_permission_denied, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        std::error_code ec2;
        auto ent_st = std::filesystem::symlink_status(it->path(), ec2);
        if (ec2) {
            if (err) *err = "tree stat failed: " + ec2.message();
            return false;
        }

        if (std::filesystem::is_symlink(ent_st)) {
            if (err) *err = "symlinks not supported";
            return false;
        }

        if (std::filesystem::is_regular_file(ent_st)) {
            const auto sz = std::filesystem::file_size(it->path(), ec2);
            if (ec2) {
                if (err) *err = "file_size failed: " + ec2.message();
                return false;
            }
            ++files;
            bytes += static_cast<std::uint64_t>(sz);
        }
    }

    if (ec) {
        if (err) *err = "tree walk failed: " + ec.message();
        return false;
    }

    *out_file_count = files;
    *out_size_bytes = bytes;
    return true;
}

bool TrashService::move_to_trash(const MoveToTrashParams& p,
                                 MoveToTrashResult* out,
                                 std::string* err) {
    if (err) err->clear();
    if (out) *out = MoveToTrashResult{};

    if (!index_) {
        if (err) *err = "trash index missing";
        return false;
    }
    if (p.scope_type != "user" && p.scope_type != "workspace") {
        if (err) *err = "invalid scope_type";
        return false;
    }
    if (p.scope_id.empty()) {
        if (err) *err = "empty scope_id";
        return false;
    }
    if (p.item_type != "file" && p.item_type != "dir") {
        if (err) *err = "invalid item_type";
        return false;
    }
    if (p.original_rel_path.empty()) {
        if (err) *err = "empty original_rel_path";
        return false;
    }
    if (p.payload_abs_path.empty()) {
        if (err) *err = "empty payload_abs_path";
        return false;
    }
    if (p.storage_root.empty()) {
        if (err) *err = "empty storage_root";
        return false;
    }

    const auto storage_root = p.storage_root.lexically_normal();
    const auto trash_root = pqnas_trash_root_for_storage_root(storage_root);
    const std::string trash_id = make_trash_id_local();
    const std::string trash_rel = trash_rel_payload_path_local(p.scope_type, p.scope_id, trash_id);
    const auto trash_payload_abs = (trash_root / std::filesystem::path(trash_rel)).lexically_normal();

    std::uint64_t file_count = p.file_count;
    std::uint64_t size_bytes = p.size_bytes;
    if (file_count == 0 && size_bytes == 0) {
        if (!scan_payload_tree(p.payload_abs_path, &file_count, &size_bytes, err)) {
            return false;
        }
    }

    std::error_code ec;
    auto dst_st = std::filesystem::symlink_status(trash_payload_abs, ec);
    if (!ec && std::filesystem::exists(dst_st)) {
        if (err) *err = "trash destination already exists";
        return false;
    }

    std::string merr;
    if (!move_path_local(p.payload_abs_path, trash_payload_abs, &merr)) {
        if (err) *err = merr;
        return false;
    }

    const std::int64_t deleted_epoch = (p.deleted_epoch > 0) ? p.deleted_epoch : now_epoch_local();
    const std::int64_t retention_seconds =
        (p.retention_seconds > 0) ? p.retention_seconds : k_default_trash_retention_seconds;

    TrashItemRec rec;
    rec.trash_id = trash_id;
    rec.scope_type = p.scope_type;
    rec.scope_id = p.scope_id;
    rec.deleted_by_fp = p.deleted_by_fp;
    rec.origin_app = p.origin_app;
    rec.item_type = p.item_type;
    rec.original_rel_path = p.original_rel_path;
    rec.storage_root = storage_root.string();
    rec.trash_rel_path = trash_rel;
    rec.payload_physical_path = trash_payload_abs.string();
    rec.source_pool = p.source_pool;
    rec.source_tier_state = p.source_tier_state;
    rec.size_bytes = size_bytes;
    rec.file_count = file_count;
    rec.deleted_epoch = deleted_epoch;
    rec.purge_after_epoch = deleted_epoch + retention_seconds;
    rec.restore_status = "trashed";
    rec.status_updated_epoch = deleted_epoch;

    std::string ierr;
    if (!index_->insert(rec, &ierr)) {
        std::string rerr;
        if (!move_path_local(trash_payload_abs, p.payload_abs_path, &rerr)) {
            if (err) *err = "trash insert failed: " + ierr + "; rollback move failed: " + rerr;
            return false;
        }
        if (err) *err = "trash insert failed: " + ierr;
        return false;
    }

    if (out) {
        out->trash_id = trash_id;
        out->trash_root = trash_root;
        out->payload_abs_path = trash_payload_abs;
        out->trash_rel_path = trash_rel;
        out->size_bytes = size_bytes;
        out->file_count = file_count;
    }

    return true;
}

bool TrashService::restore_from_trash(const RestoreParams& p,
                                      RestoreResult* out,
                                      std::string* err) {
    if (err) err->clear();
    if (out) *out = RestoreResult{};

    if (!index_) {
        if (err) *err = "trash index missing";
        return false;
    }
    if (p.trash_id.empty()) {
        if (err) *err = "empty trash_id";
        return false;
    }
    if (p.restore_abs_path.empty()) {
        if (err) *err = "empty restore_abs_path";
        return false;
    }

    std::string gerr;
    auto rec_opt = index_->get(p.trash_id, &gerr);
    if (!gerr.empty()) {
        if (err) *err = gerr;
        return false;
    }
    if (!rec_opt.has_value()) {
        if (err) *err = "trash item not found";
        return false;
    }

    const auto& rec = *rec_opt;
    if (rec.restore_status != "trashed") {
        if (err) *err = "trash item is not active";
        return false;
    }

    const auto src_abs = std::filesystem::path(rec.payload_physical_path);
    auto dst_abs = p.restore_abs_path.lexically_normal();

    std::error_code ec;
    auto dst_st = std::filesystem::symlink_status(dst_abs, ec);
    if (!ec && std::filesystem::exists(dst_st)) {
        if (!p.rename_if_conflict) {
            if (err) *err = "restore destination exists";
            return false;
        }
        dst_abs = build_conflict_rename_target_local(dst_abs);
    }

    std::string merr;
    if (!move_path_local(src_abs, dst_abs, &merr)) {
        if (err) *err = merr;
        return false;
    }

    std::string restored_rel_path = rec.original_rel_path;
    if (!p.restore_root_abs.empty()) {
        std::error_code rec_ec;
        auto rel = std::filesystem::relative(dst_abs, p.restore_root_abs.lexically_normal(), rec_ec);
        if (!rec_ec && !rel.empty()) {
            restored_rel_path = rel.generic_string();
        }
    }

    // NEW: recreate live metadata before marking trash row restored
    if (restore_reindexer_) {
        std::string rixerr;
        if (!restore_reindexer_(rec, dst_abs, restored_rel_path, &rixerr)) {
            std::string rollback_err;
            if (!move_path_local(dst_abs, src_abs, &rollback_err)) {
                if (err) *err = "restore reindex failed: " + rixerr +
                                "; rollback move failed: " + rollback_err;
                return false;
            }
            if (err) *err = "restore reindex failed: " + rixerr;
            return false;
        }
    }

    const std::int64_t now_ts = now_epoch_local();
    std::string serr;
    if (!index_->set_restore_status(p.trash_id, "restored", now_ts, &serr)) {
        if (restore_unindexer_) {
            restore_unindexer_(rec, restored_rel_path);
        }

        std::string rerr;
        if (!move_path_local(dst_abs, src_abs, &rerr)) {
            if (err) *err = "restore status update failed: " + serr + "; rollback move failed: " + rerr;
            return false;
        }
        if (err) *err = "restore status update failed: " + serr;
        return false;
    }

    if (out) {
        out->trash_id = rec.trash_id;
        out->item_type = rec.item_type;
        out->restored_abs_path = dst_abs;
        out->size_bytes = rec.size_bytes;
        out->file_count = rec.file_count;
        out->renamed = (dst_abs != p.restore_abs_path.lexically_normal());
    }

    return true;
}

bool TrashService::purge_from_trash(const PurgeParams& p,
                                    PurgeResult* out,
                                    std::string* err) {
    if (err) err->clear();
    if (out) *out = PurgeResult{};

    if (!index_) {
        if (err) *err = "trash index missing";
        return false;
    }
    if (p.trash_id.empty()) {
        if (err) *err = "empty trash_id";
        return false;
    }

    std::string gerr;
    auto rec_opt = index_->get(p.trash_id, &gerr);
    if (!gerr.empty()) {
        if (err) *err = gerr;
        return false;
    }
    if (!rec_opt.has_value()) {
        if (err) *err = "trash item not found";
        return false;
    }

    const auto& rec = *rec_opt;
    if (rec.restore_status != "trashed") {
        if (err) *err = "trash item is not active";
        return false;
    }

    std::string derr;
    if (!remove_path_recursive_local(std::filesystem::path(rec.payload_physical_path), &derr)) {
        if (err) *err = derr;
        return false;
    }

    const std::int64_t now_ts = now_epoch_local();
    std::string serr;
    if (!index_->set_restore_status(p.trash_id, "purged", now_ts, &serr)) {
        if (err) *err = serr;
        return false;
    }

    if (out) {
        out->trash_id = rec.trash_id;
        out->size_bytes = rec.size_bytes;
        out->file_count = rec.file_count;
    }

    return true;
}

} // namespace pqnas