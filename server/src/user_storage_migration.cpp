#include "user_storage_migration.h"
#include "pqnas_util.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <system_error>
#include <sys/wait.h>
#include <unistd.h>

using json = nlohmann::json;

namespace pqnas {
namespace {

static bool is_safe_rel_path_local(const std::string& rel) {
    if (rel.empty()) return false;
    if (rel.find('\0') != std::string::npos) return false;
    std::filesystem::path p(rel);
    if (p.is_absolute() || p.has_root_path()) return false;
    for (const auto& part : p) {
        const auto s = part.string();
        if (s.empty() || s == "." || s == "..") return false;
    }
    return true;
}

static std::string default_root_rel_for_fp(const std::string& fp_hex) {
    return std::string("users/") + fp_hex;
}

static std::filesystem::path default_data_root_from_users_path(const std::string& users_path) {
    const std::filesystem::path p(users_path);
    return p.parent_path().parent_path() / "data";
}

static bool load_pool_mount_from_pools_json(const std::string& users_path,
                                            const std::string& pool_id,
                                            std::filesystem::path* out_mount,
                                            std::string* err) {
    if (err) err->clear();
    if (!out_mount) {
        if (err) *err = "null out_mount";
        return false;
    }

    const std::filesystem::path pools_path =
        std::filesystem::path(users_path).parent_path() / "pools.json";

    std::ifstream f(pools_path);
    if (!f.good()) {
        if (err) *err = "failed to open pools.json: " + pools_path.string();
        return false;
    }

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        if (err) *err = std::string("failed to parse pools.json: ") + e.what();
        return false;
    }

    if (!j.is_object() || !j.contains("pools") || !j["pools"].is_object()) {
        if (err) *err = "invalid pools.json format";
        return false;
    }

    for (auto it = j["pools"].begin(); it != j["pools"].end(); ++it) {
        const std::string mount = it.key();
        const auto& meta = it.value();
        if (!meta.is_object()) continue;
        if (meta.value("pool_id", "") == pool_id) {
            *out_mount = std::filesystem::path(mount);
            return true;
        }
    }

    if (err) *err = "pool_id not found in pools.json: " + pool_id;
    return false;
}

static bool resolve_data_root_for_pool_id(const std::string& users_path,
                                          const std::string& pool_id,
                                          std::filesystem::path* out_root,
                                          std::string* err) {
    if (err) err->clear();
    if (!out_root) {
        if (err) *err = "null out_root";
        return false;
    }

    if (pool_id.empty() || pool_id == "default") {
        *out_root = default_data_root_from_users_path(users_path);
        return true;
    }

    std::filesystem::path mount;
    if (!load_pool_mount_from_pools_json(users_path, pool_id, &mount, err)) {
        return false;
    }

    *out_root = mount / "data";
    return true;
}

static bool ensure_dir_exists_strict(const std::filesystem::path& p, std::string* err) {
    if (err) err->clear();
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }
    return true;
}

static std::uint64_t file_size_safe(const std::filesystem::path& p) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) return 0;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) return 0;
    return static_cast<std::uint64_t>(sz);
}

static std::uint64_t compute_tree_bytes(const std::filesystem::path& root) {
    std::uint64_t total = 0;
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return 0;

    for (std::filesystem::recursive_directory_iterator it(root, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        std::error_code ec2;
        if (it->is_regular_file(ec2) && !ec2) {
            total += file_size_safe(it->path());
        }
    }
    return total;
}

static bool run_rsync_copy(const std::filesystem::path& src,
                           const std::filesystem::path& dst,
                           std::string* err) {
    if (err) err->clear();

    const std::string src_s = src.string() + "/";
    const std::string dst_s = dst.string() + "/";

    pid_t pid = fork();
    if (pid < 0) {
        if (err) *err = "fork failed";
        return false;
    }

    if (pid == 0) {
        const char* argv[] = {
            "rsync",
            "-aHAX",
            "--numeric-ids",
            "--",
            src_s.c_str(),
            dst_s.c_str(),
            nullptr
        };

        execvp("rsync", const_cast<char* const*>(argv));
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        if (err) *err = "waitpid failed";
        return false;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (err) *err = "rsync failed rc=" + std::to_string(WEXITSTATUS(status));
        return false;
    }

    return true;
}

} // namespace

bool resolve_user_storage_migration(const UsersRegistry& users,
                                    const std::string& users_path,
                                    const std::string& fp_hex,
                                    const std::string& target_pool_id,
                                    UserStorageMigrationPlan* out,
                                    std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    auto uopt = users.get(fp_hex);
    if (!uopt.has_value()) {
        if (err) *err = "user_missing";
        return false;
    }
    const auto& u = *uopt;

    if (u.storage_state != "allocated") {
        if (err) *err = "storage_unallocated";
        return false;
    }

    UserStorageMigrationPlan p;
    p.fingerprint = fp_hex;
    p.from_pool_id = u.storage_pool_id.empty() ? "default" : u.storage_pool_id;
    p.to_pool_id = target_pool_id.empty() ? "default" : target_pool_id;
    p.root_rel = (!u.root_rel.empty() && is_safe_rel_path_local(u.root_rel))
        ? u.root_rel
        : default_root_rel_for_fp(fp_hex);

    if (!resolve_data_root_for_pool_id(users_path, p.from_pool_id, &p.src_data_root, err)) {
        return false;
    }
    if (!resolve_data_root_for_pool_id(users_path, p.to_pool_id, &p.dst_data_root, err)) {
        return false;
    }

    p.src_user_dir = p.src_data_root / p.root_rel;
    p.dst_user_dir = p.dst_data_root / p.root_rel;

    *out = p;
    return true;
}

bool ensure_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err) {
    if (!ensure_dir_exists_strict(plan.dst_user_dir.parent_path(), err)) return false;
    if (!ensure_dir_exists_strict(plan.dst_user_dir, err)) return false;
    return true;
}

bool run_user_storage_migration_copy(const UserStorageMigrationPlan& plan,
                                     std::string* err) {
    return run_rsync_copy(plan.src_user_dir, plan.dst_user_dir, err);
}

bool verify_user_storage_migration_destination(const UserStorageMigrationPlan& plan,
                                               std::string* err) {
    if (err) err->clear();

    {
        std::error_code ec;
        auto st = std::filesystem::status(plan.dst_user_dir, ec);
        if (ec || !std::filesystem::exists(st) || !std::filesystem::is_directory(st)) {
            if (err) *err = "destination user dir missing after copy: " + plan.dst_user_dir.string();
            return false;
        }
    }

    const auto src_bytes = compute_tree_bytes(plan.src_user_dir);
    const auto dst_bytes = compute_tree_bytes(plan.dst_user_dir);
    if (src_bytes != dst_bytes) {
        if (err) {
            *err = "byte totals differ: src=" + std::to_string(src_bytes) +
                   " dst=" + std::to_string(dst_bytes);
        }
        return false;
    }

    return true;
}

bool switch_user_storage_migration_metadata(UsersRegistry& users,
                                           const std::string& users_path,
                                           const std::string& actor_fp,
                                           const UserStorageMigrationPlan& plan,
                                           std::string* err) {
    if (err) err->clear();

    auto uopt = users.get(plan.fingerprint);
    if (!uopt.has_value()) {
        if (err) *err = "user_missing_after_copy";
        return false;
    }

    auto u = *uopt;
    const std::string current_pool_id = u.storage_pool_id.empty() ? "default" : u.storage_pool_id;

    // Compare-before-commit guard:
    // only switch if metadata still matches the source pool resolved when worker started.
    if (current_pool_id != plan.from_pool_id) {
        if (err) {
            *err = "source pool changed before metadata switch: expected=" +
                   plan.from_pool_id + " actual=" + current_pool_id;
        }
        return false;
    }

    u.storage_pool_id = (plan.to_pool_id == "default") ? "" : plan.to_pool_id;
    u.root_rel = plan.root_rel;
    u.storage_set_by = actor_fp;
    u.storage_set_at = pqnas::now_iso_utc();

    if (!users.upsert(u)) {
        if (err) *err = "users.upsert failed";
        return false;
    }
    if (!users.save(users_path)) {
        if (err) *err = "users.save failed";
        return false;
    }

    return true;
}

bool migrate_user_storage_sync(UsersRegistry& users,
                               const std::string& users_path,
                               const std::string& actor_fp,
                               const std::string& fp_hex,
                               const std::string& target_pool_id,
                               UserStorageMigrationResult* out) {
    UserStorageMigrationResult r;

    std::string err;
    if (!resolve_user_storage_migration(users, users_path, fp_hex, target_pool_id, &r.plan, &err)) {
        r.ok = false;
        r.error = "resolve_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    if (r.plan.from_pool_id == r.plan.to_pool_id) {
        r.ok = false;
        r.error = "same_pool";
        r.detail = "source and destination pool are the same";
        if (out) *out = r;
        return false;
    }

    if (!ensure_user_storage_migration_destination(r.plan, &err)) {
        r.ok = false;
        r.error = "mkdir_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    if (!run_user_storage_migration_copy(r.plan, &err)) {
        r.ok = false;
        r.error = "copy_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }
    r.copied = true;

    if (!verify_user_storage_migration_destination(r.plan, &err)) {
        r.ok = false;
        r.error = "verify_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }
    r.verified = true;

    if (!switch_user_storage_migration_metadata(users, users_path, actor_fp, r.plan, &err)) {
        r.ok = false;
        r.error = "metadata_switch_failed";
        r.detail = err;
        if (out) *out = r;
        return false;
    }

    r.metadata_updated = true;
    r.ok = true;
    if (out) *out = r;
    return true;
}

} // namespace pqnas