#include "routes_workspaces_files.h"

#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <system_error>
#include <array>
#include <openssl/evp.h>
#include <vector>
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

#include "audit_fields.h"
#include "storage_resolver.h"
#include "user_quota.h"

namespace pqnas {
    static std::string hex_encode_lower_local(const unsigned char* data, std::size_t len) {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.resize(len * 2);
        for (std::size_t i = 0; i < len; ++i) {
            const unsigned char b = data[i];
            out[i * 2 + 0] = kHex[(b >> 4) & 0x0F];
            out[i * 2 + 1] = kHex[b & 0x0F];
        }
        return out;
    }

    static bool sha256_file_local(const std::filesystem::path& p, std::string* out_hex, std::string* err) {
        std::ifstream f(p, std::ios::binary);
        if (!f.good()) {
            if (err) *err = "cannot open file";
            return false;
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            if (err) *err = "EVP_MD_CTX_new failed";
            return false;
        }

        struct CtxGuard {
            EVP_MD_CTX* c;
            ~CtxGuard() { if (c) EVP_MD_CTX_free(c); }
        } guard{ctx};

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            if (err) *err = "EVP_DigestInit_ex failed";
            return false;
        }

        std::array<char, 64 * 1024> buf{};
        while (f.good()) {
            f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize n = f.gcount();
            if (n > 0) {
                if (EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) != 1) {
                    if (err) *err = "EVP_DigestUpdate failed";
                    return false;
                }
            }
        }

        if (!f.eof()) {
            if (err) *err = "read failed";
            return false;
        }

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
            if (err) *err = "EVP_DigestFinal_ex failed";
            return false;
        }

        if (out_hex) *out_hex = hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
        return true;
    }

namespace {
static constexpr std::uint64_t k_edit_lease_default_sec_local = 60;
static constexpr std::uint64_t k_edit_lease_min_sec_local = 15;
static constexpr std::uint64_t k_edit_lease_max_sec_local = 300;
static constexpr std::uint64_t k_text_edit_max_bytes_local = 2 * 1024 * 1024;
std::string random_urlsafe_token(std::size_t n);

struct WorkspaceEditLeaseRec {
    std::string workspace_id;
    std::string path;          // normalized relative path
    std::string holder_fp;
    std::string session_id;
    std::string mode;          // "edit"

    std::uint64_t acquired_epoch = 0;
    std::uint64_t last_seen_epoch = 0;
    std::uint64_t expires_epoch = 0;

    std::string acquired_at;
    std::string last_seen_at;
    std::string expires_at;
};

std::string sha256_hex_string_local(const std::string& s, std::string* err) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        if (err) *err = "EVP_MD_CTX_new failed";
        return {};
    }

    struct CtxGuard {
        EVP_MD_CTX* c;
        ~CtxGuard() { if (c) EVP_MD_CTX_free(c); }
    } guard{ctx};

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (err) *err = "EVP_DigestInit_ex failed";
        return {};
    }

    if (!s.empty()) {
        if (EVP_DigestUpdate(ctx, s.data(), s.size()) != 1) {
            if (err) *err = "EVP_DigestUpdate failed";
            return {};
        }
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        if (err) *err = "EVP_DigestFinal_ex failed";
        return {};
    }

    return hex_encode_lower_local(md, static_cast<std::size_t>(md_len));
}

std::filesystem::path workspace_edit_lock_dir_local(const std::filesystem::path& ws_root) {
    return ws_root / ".pqnas" / "edit_locks";
}

std::filesystem::path workspace_edit_lock_path_local(const std::filesystem::path& ws_root,
                                                     const std::string& rel_norm,
                                                     std::string* err) {
    std::string key = sha256_hex_string_local(rel_norm, err);
    if (key.empty()) return {};
    return workspace_edit_lock_dir_local(ws_root) / (key + ".json");
}

json workspace_edit_lease_to_json_local(const WorkspaceEditLeaseRec& r) {
    return json{
        {"workspace_id", r.workspace_id},
        {"path", r.path},
        {"holder_fp", r.holder_fp},
        {"session_id", r.session_id},
        {"mode", r.mode},
        {"acquired_epoch", r.acquired_epoch},
        {"last_seen_epoch", r.last_seen_epoch},
        {"expires_epoch", r.expires_epoch},
        {"acquired_at", r.acquired_at},
        {"last_seen_at", r.last_seen_at},
        {"expires_at", r.expires_at}
    };
}

bool workspace_edit_lease_from_json_local(const json& j,
                                          WorkspaceEditLeaseRec* out,
                                          std::string* err) {
    if (!out) {
        if (err) *err = "out is null";
        return false;
    }
    if (!j.is_object()) {
        if (err) *err = "lease json is not object";
        return false;
    }

    out->workspace_id = j.value("workspace_id", "");
    out->path = j.value("path", "");
    out->holder_fp = j.value("holder_fp", "");
    out->session_id = j.value("session_id", "");
    out->mode = j.value("mode", "edit");

    out->acquired_epoch = (j.contains("acquired_epoch") && j["acquired_epoch"].is_number_unsigned())
        ? j["acquired_epoch"].get<std::uint64_t>() : 0;
    out->last_seen_epoch = (j.contains("last_seen_epoch") && j["last_seen_epoch"].is_number_unsigned())
        ? j["last_seen_epoch"].get<std::uint64_t>() : 0;
    out->expires_epoch = (j.contains("expires_epoch") && j["expires_epoch"].is_number_unsigned())
        ? j["expires_epoch"].get<std::uint64_t>() : 0;

    out->acquired_at = j.value("acquired_at", "");
    out->last_seen_at = j.value("last_seen_at", "");
    out->expires_at = j.value("expires_at", "");

    if (out->workspace_id.empty() || out->path.empty() || out->holder_fp.empty() || out->session_id.empty()) {
        if (err) *err = "lease json missing required fields";
        return false;
    }

    return true;
}

bool write_string_file_atomic_local(const std::filesystem::path& abs_path,
                                    const std::string& body,
                                    std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(abs_path.parent_path(), ec);
    if (ec) {
        if (err) *err = "create_directories failed: " + ec.message();
        return false;
    }

    const auto tmp = abs_path.parent_path() /
        (abs_path.filename().string() + ".tmp." + random_urlsafe_token(8));

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            if (err) *err = "open tmp failed";
            return false;
        }
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!f.good()) {
            f.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "write tmp failed";
            return false;
        }
        f.flush();
        if (!f.good()) {
            f.close();
            std::filesystem::remove(tmp, ec);
            if (err) *err = "flush tmp failed";
            return false;
        }
    }

    std::filesystem::rename(tmp, abs_path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        if (err) *err = "rename failed";
        return false;
    }

    return true;
}

bool read_json_file_local(const std::filesystem::path& abs_path, json* out, std::string* err) {
    if (!out) {
        if (err) *err = "out is null";
        return false;
    }

    std::ifstream f(abs_path, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    std::string body((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (!f.good() && !f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    json j = json::parse(body, nullptr, false);
    if (j.is_discarded()) {
        if (err) *err = "invalid json";
        return false;
    }

    *out = std::move(j);
    return true;
}

bool load_workspace_edit_lease_local(const std::filesystem::path& lock_abs,
                                     WorkspaceEditLeaseRec* out,
                                     bool* found,
                                     std::string* err) {
    if (found) *found = false;

    std::error_code ec;
    if (!std::filesystem::exists(lock_abs, ec)) {
        return true;
    }
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }

    json j;
    if (!read_json_file_local(lock_abs, &j, err)) return false;

    if (!workspace_edit_lease_from_json_local(j, out, err)) return false;

    if (found) *found = true;
    return true;
}

bool save_workspace_edit_lease_local(const std::filesystem::path& lock_abs,
                                     const WorkspaceEditLeaseRec& rec,
                                     std::string* err) {
    return write_string_file_atomic_local(lock_abs,
                                          workspace_edit_lease_to_json_local(rec).dump(2),
                                          err);
}

bool remove_workspace_edit_lease_local(const std::filesystem::path& lock_abs,
                                       std::string* err) {
    std::error_code ec;
    const bool removed = std::filesystem::remove(lock_abs, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }
    (void)removed;
    return true;
}
static bool read_file_bytes_all_local(const std::filesystem::path& p,
                                      std::string* out,
                                      std::string* err) {
    if (out) out->clear();

    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());

    if (!f.good() && !f.eof()) {
        if (err) *err = "read failed";
        return false;
    }

    if (out) *out = std::move(data);
    return true;
}

static bool looks_like_text_no_nul_prefix_local(const std::filesystem::path& p,
                                                std::string* err) {
    std::ifstream f(p, std::ios::binary);
    if (!f.good()) {
        if (err) *err = "cannot open file";
        return false;
    }

    char buf[4096];
    f.read(buf, sizeof(buf));
    const std::streamsize n = f.gcount();

    for (std::streamsize i = 0; i < n; ++i) {
        if (buf[i] == '\0') {
            if (err) *err = "contains NUL byte";
            return false;
        }
    }

    return true;
}

static std::string strip_utf8_bom_local(const std::string& s, bool* had_bom) {
    const bool bom =
        s.size() >= 3 &&
        static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF;

    if (had_bom) *had_bom = bom;
    return bom ? s.substr(3) : s;
}

static bool is_valid_utf8_local(const std::string& s) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
    const std::size_t n = s.size();

    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];

        if (c <= 0x7F) {
            ++i;
            continue;
        }

        if ((c >> 5) == 0x6) {
            if (i + 1 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            const unsigned int cp =
                ((c & 0x1F) << 6) |
                (p[i + 1] & 0x3F);
            if (cp < 0x80) return false;
            i += 2;
            continue;
        }

        if ((c >> 4) == 0xE) {
            if (i + 2 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            if ((p[i + 2] & 0xC0) != 0x80) return false;
            const unsigned int cp =
                ((c & 0x0F) << 12) |
                ((p[i + 1] & 0x3F) << 6) |
                (p[i + 2] & 0x3F);
            if (cp < 0x800) return false;
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;
            i += 3;
            continue;
        }

        if ((c >> 3) == 0x1E) {
            if (i + 3 >= n) return false;
            if ((p[i + 1] & 0xC0) != 0x80) return false;
            if ((p[i + 2] & 0xC0) != 0x80) return false;
            if ((p[i + 3] & 0xC0) != 0x80) return false;
            const unsigned int cp =
                ((c & 0x07) << 18) |
                ((p[i + 1] & 0x3F) << 12) |
                ((p[i + 2] & 0x3F) << 6) |
                (p[i + 3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) return false;
            i += 4;
            continue;
        }

        return false;
    }

    return true;
}

static std::uint64_t file_mtime_epoch_safe_local(const std::filesystem::path& p) {
    std::error_code ec;
    const auto ftime = std::filesystem::last_write_time(p, ec);
    if (ec) return 0;

    using namespace std::chrono;
    const auto sctp = time_point_cast<system_clock::duration>(
        ftime - std::filesystem::file_time_type::clock::now() + system_clock::now()
    );
    const auto sec = duration_cast<seconds>(sctp.time_since_epoch()).count();
    return sec > 0 ? static_cast<std::uint64_t>(sec) : 0;
}

static std::string guess_text_mime_from_name_local(const std::string& name) {
    std::string s = name;
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    const auto dot = s.rfind('.');
    const std::string ext = (dot == std::string::npos) ? "" : s.substr(dot + 1);

    if (ext == "txt" || ext == "log" || ext == "md" || ext == "ini" || ext == "conf")
        return "text/plain";
    if (ext == "json")
        return "application/json";
    if (ext == "html" || ext == "htm")
        return "text/html";
    if (ext == "css")
        return "text/css";
    if (ext == "js")
        return "application/javascript";
    if (ext == "xml")
        return "application/xml";
    if (ext == "csv")
        return "text/csv";

    return "text/plain";
}
static bool write_text_file_atomic_utf8_local(const std::filesystem::path& abs_path,
                                                      const std::string& text,
                                                      std::string* err) {
    if (!is_valid_utf8_local(text)) {
        if (err) *err = "text must be valid UTF-8";
        return false;
    }

    return write_string_file_atomic_local(abs_path, text, err);
}
bool workspace_edit_lease_is_active_local(const WorkspaceEditLeaseRec& rec,
                                          std::uint64_t now_epoch) {
    return !rec.holder_fp.empty() &&
           !rec.session_id.empty() &&
           rec.expires_epoch > now_epoch;
}

bool workspace_edit_lease_owned_by_local(const WorkspaceEditLeaseRec& rec,
                                         const std::string& actor_fp,
                                         const std::string& session_id) {
    return rec.holder_fp == actor_fp && rec.session_id == session_id;
}

json workspace_edit_lease_public_json_local(const WorkspaceEditLeaseRec& rec) {
    return json{
        {"workspace_id", rec.workspace_id},
        {"path", rec.path},
        {"holder_fp", rec.holder_fp},
        {"mode", rec.mode},
        {"acquired_epoch", rec.acquired_epoch},
        {"last_seen_epoch", rec.last_seen_epoch},
        {"expires_epoch", rec.expires_epoch},
        {"acquired_at", rec.acquired_at},
        {"last_seen_at", rec.last_seen_at},
        {"expires_at", rec.expires_at}
    };
}
std::string trim_copy_safe(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

std::filesystem::path default_data_root_from_users_path(const std::string& users_path) {
    const std::filesystem::path up(users_path);
    return up.parent_path().parent_path() / "data";
}

std::uint64_t dir_size_bytes_best_effort_local(const std::filesystem::path& root) {
    std::uint64_t total = 0;
    std::error_code ec;

    if (!std::filesystem::exists(root, ec)) return 0;
    ec.clear();

    for (std::filesystem::recursive_directory_iterator it(root, ec), end;
         it != end && !ec;
         it.increment(ec)) {
        if (ec) break;

        std::error_code ec2;
        if (it->is_regular_file(ec2) && !ec2) {
            std::error_code ec3;
            const auto sz = it->file_size(ec3);
            if (!ec3) total += static_cast<std::uint64_t>(sz);
        }
    }

    return total;
}

std::optional<WorkspaceMemberRec> enabled_member_for_actor(const WorkspaceRec& w,
                                                           const std::string& actor_fp) {
    const std::string fp = trim_copy_safe(actor_fp);
    if (fp.empty()) return std::nullopt;

    for (const auto& m : w.members) {
        if (m.fingerprint == fp && m.status == "enabled") {
            return m;
        }
    }

    return std::nullopt;
}
    std::size_t count_enabled_owners_local(const WorkspaceRec& w) {
    std::size_t n = 0;
    for (const auto& m : w.members) {
        if (m.status == "enabled" && m.role == "owner") ++n;
    }
    return n;
}
    std::optional<WorkspaceMemberRec> invited_member_for_actor(const WorkspaceRec& w,
                                                               const std::string& actor_fp) {
    const std::string fp = trim_copy_safe(actor_fp);
    if (fp.empty()) return std::nullopt;

    for (const auto& m : w.members) {
        if (m.fingerprint == fp && m.status == "invited") {
            return m;
        }
    }

    return std::nullopt;
}

    std::string iso_utc_from_epoch_sec(std::int64_t epoch_sec) {
    if (epoch_sec < 0) epoch_sec = 0;

    std::time_t tt = static_cast<std::time_t>(epoch_sec);
    std::tm tm{};

#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    if (!gmtime_r(&tt, &tm)) return "";
#endif

    char buf[32] = {0};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) return "";
    return std::string(buf);
}

json workspace_to_user_json(const WorkspaceRec& w,
                            const WorkspaceMemberRec& actor_member,
                            const std::string& users_path) {
    json out = json::object();

    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["notes"] = w.notes;
    out["status"] = w.status;

    out["role"] = actor_member.role;

    out["quota_bytes"] = w.quota_bytes;
    out["storage_state"] = w.storage_state;
    out["storage_pool_id"] = w.storage_pool_id;
    out["pool_id"] = w.storage_pool_id.empty() ? "default" : w.storage_pool_id;
    out["root_rel"] = w.root_rel;

    out["member_count"] = static_cast<unsigned long long>(w.members.size());

    std::uint64_t used_bytes = 0;
    if (w.storage_state == "allocated" && w.storage_pool_id.empty() && !w.root_rel.empty()) {
        const std::filesystem::path abs =
            default_data_root_from_users_path(users_path) / w.root_rel;
        used_bytes = dir_size_bytes_best_effort_local(abs);
    }
    out["storage_used_bytes"] = used_bytes;

    return out;
}
    json workspace_member_to_user_json(const WorkspaceMemberRec& m) {
    json out = json::object();

    out["fingerprint"] = m.fingerprint;
    out["role"] = m.role;
    out["status"] = m.status;
    out["added_at"] = m.added_at;
    out["added_by"] = m.added_by;
    out["responded_at"] = m.responded_at;
    out["responded_by"] = m.responded_by;

    return out;
}

    json workspace_invitation_to_user_json(const WorkspaceRec& w,
                                           const WorkspaceMemberRec& actor_member) {
    json out = json::object();

    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["notes"] = w.notes;
    out["status"] = actor_member.status;
    out["role"] = actor_member.role;
    out["added_at"] = actor_member.added_at;
    out["added_by"] = actor_member.added_by;

    return out;
}
std::filesystem::path workspace_dir_for_default_pool_only(const std::string& users_path,
                                                          const WorkspaceRec& w) {
    return default_data_root_from_users_path(users_path) / w.root_rel;
}
    std::string random_urlsafe_token(std::size_t n) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dist(0, 63);

    std::string out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kAlphabet[dist(gen)]);
    }
    return out;
}
bool resolve_workspace_edit_target_local(const WorkspaceFileRouteDeps& deps,
                                         const std::string& actor_fp,
                                         const std::string& workspace_id,
                                         const std::string& path_rel,
                                         bool require_write,
                                         WorkspaceMemberRec* out_member,
                                         std::string* out_rel_norm,
                                         std::filesystem::path* out_ws_root,
                                         std::filesystem::path* out_abs_path,
                                         std::string* out_err) {
    if (!deps.workspaces->load(deps.workspaces_path)) {
        if (out_err) *out_err = "failed to reload workspaces";
        return false;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        if (out_err) *out_err = "workspace not found";
        return false;
    }

    const WorkspaceRec& w = *wopt;

    if (w.status != "enabled") {
        if (out_err) *out_err = "workspace disabled";
        return false;
    }

    auto mopt = enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) {
        if (out_err) *out_err = "workspace access denied";
        return false;
    }

    if (require_write && !(mopt->role == "owner" || mopt->role == "editor")) {
        if (out_err) *out_err = "workspace write access denied";
        return false;
    }

    if (w.storage_state != "allocated") {
        if (out_err) *out_err = "workspace storage not allocated";
        return false;
    }

    if (!w.storage_pool_id.empty()) {
        if (out_err) *out_err = "pool not supported yet";
        return false;
    }

    std::string rel_norm;
    std::string nerr;
    if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
        if (out_err) *out_err = "invalid path";
        return false;
    }

    const std::filesystem::path ws_root =
        workspace_dir_for_default_pool_only(deps.users_path, w);

    std::filesystem::path abs_path;
    std::string perr;
    if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
        if (out_err) *out_err = "invalid path";
        return false;
    }

    std::error_code ec;
    auto st = std::filesystem::symlink_status(abs_path, ec);
    if (ec || !std::filesystem::exists(st) || std::filesystem::is_symlink(st) || !std::filesystem::is_regular_file(st)) {
        if (out_err) *out_err = "file not found";
        return false;
    }

    if (out_member) *out_member = *mopt;
    if (out_rel_norm) *out_rel_norm = rel_norm;
    if (out_ws_root) *out_ws_root = ws_root;
    if (out_abs_path) *out_abs_path = abs_path;
    return true;
}
bool any_file_ancestor_exists_physical(const std::filesystem::path& root,
                                           const std::string& rel_norm,
                                           std::string* found_rel) {
    if (found_rel) found_rel->clear();

    std::filesystem::path cur = root;
    std::filesystem::path relp(rel_norm);

    std::vector<std::filesystem::path> parts;
    for (const auto& p : relp) {
        if (!p.empty()) parts.push_back(p);
    }

    if (parts.size() <= 1) return false;

    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        cur /= parts[i];

        std::error_code ec;
        auto st = std::filesystem::status(cur, ec);
        if (ec) continue;

        if (std::filesystem::exists(st) && std::filesystem::is_regular_file(st)) {
            if (found_rel) {
                std::error_code ec2;
                *found_rel = cur.lexically_relative(root).string();
                if (ec2) *found_rel = cur.filename().string();
            }
            return true;
        }
    }

    return false;
}
} // namespace

void register_workspace_file_routes(httplib::Server& srv,
                                    const WorkspaceFileRouteDeps& deps) {
    srv.Get("/api/v4/workspaces",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        if (!deps.workspaces->load(deps.workspaces_path)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        json out;
        out["ok"] = true;
        out["actor_fp"] = actor_fp;
        out["workspaces"] = json::array();

        for (const auto& kv : deps.workspaces->snapshot()) {
            const auto& w = kv.second;

            if (w.status != "enabled") continue;

            auto mopt = enabled_member_for_actor(w, actor_fp);
            if (!mopt.has_value()) continue;

            out["workspaces"].push_back(
                workspace_to_user_json(w, *mopt, deps.users_path));
        }

        deps.reply_json(res, 200, out.dump());
    });

    srv.Get("/api/v4/workspaces/members",
        [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    if (!deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    const std::string workspace_id =
        req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

    if (workspace_id.empty()) {
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    const WorkspaceRec& w = *wopt;

    if (w.status != "enabled") {
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace disabled"}
        }.dump());
        return;
    }

    auto mopt = enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) {
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace access denied"}
        }.dump());
        return;
    }

    json out;
    out["ok"] = true;
    out["workspace_id"] = w.workspace_id;
    out["name"] = w.name;
    out["role"] = mopt->role;
    out["members"] = json::array();

    for (const auto& m : w.members) {
        out["members"].push_back(workspace_member_to_user_json(m));
    }

    deps.reply_json(res, 200, out.dump());
});
    srv.Post("/api/v4/workspaces/leave",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    auto audit_fail = [&](const std::string& workspace_id,
                          const std::string& reason,
                          int http,
                          const std::string& detail = "") {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
        f["reason"] = reason;
        f["http"] = std::to_string(http);
        if (!detail.empty()) f["detail"] = detail;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.leave_fail", "fail", f);
    };

    auto audit_ok = [&](const std::string& workspace_id) {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        f["workspace_id"] = workspace_id;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.leave_ok", "ok", f);
    };

    json j;
    try {
        j = req.body.empty() ? json::object() : json::parse(req.body);
    } catch (...) {
        audit_fail("", "bad_json", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        audit_fail("", "missing_workspace_id", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (!deps.workspaces->load(deps.workspaces_path)) {
        audit_fail(workspace_id, "workspaces_reload_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        audit_fail(workspace_id, "workspace_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    const WorkspaceRec& w = *wopt;

    if (w.status != "enabled") {
        audit_fail(workspace_id, "workspace_disabled", 403);
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace disabled"}
        }.dump());
        return;
    }

    auto mopt = enabled_member_for_actor(w, actor_fp);
    if (!mopt.has_value()) {
        audit_fail(workspace_id, "workspace_access_denied", 403);
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace access denied"}
        }.dump());
        return;
    }

    if (mopt->role == "owner" && count_enabled_owners_local(w) <= 1) {
        audit_fail(workspace_id, "last_enabled_owner_cannot_leave", 409);
        deps.reply_json(res, 409, json{
            {"ok", false},
            {"error", "last_owner_cannot_leave"},
            {"message", "You are the last enabled owner. Promote another owner first or delete the workspace."}
        }.dump());
        return;
    }

    const std::string now_iso =
        iso_utc_from_epoch_sec(deps.now_epoch_sec ? deps.now_epoch_sec() : 0);

    if (!deps.workspaces->set_member_status(workspace_id, actor_fp, "disabled", now_iso, actor_fp)) {
        audit_fail(workspace_id, "set_member_status_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to leave workspace"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_fail(workspace_id, "save_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    audit_ok(workspace_id);

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace_id", workspace_id},
        {"left", true},
        {"status", "disabled"}
    }.dump());
});
    srv.Get("/api/v4/workspaces/invitations",
        [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    if (!deps.workspaces->load(deps.workspaces_path)) {
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    json out;
    out["ok"] = true;
    out["actor_fp"] = actor_fp;
    out["invitations"] = json::array();

    for (const auto& kv : deps.workspaces->snapshot()) {
        const auto& w = kv.second;

        if (w.status != "enabled") continue;

        auto mopt = invited_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) continue;

        out["invitations"].push_back(
            workspace_invitation_to_user_json(w, *mopt));
    }

    deps.reply_json(res, 200, out.dump());
});
    srv.Post("/api/v4/workspaces/invitations/accept",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    auto audit_fail = [&](const std::string& workspace_id,
                          const std::string& reason,
                          int http,
                          const std::string& detail = "") {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
        f["reason"] = reason;
        f["http"] = std::to_string(http);
        if (!detail.empty()) f["detail"] = detail;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_accept_fail", "fail", f);
    };

    auto audit_ok = [&](const std::string& workspace_id) {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        f["workspace_id"] = workspace_id;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_accept_ok", "ok", f);
    };

    json j;
    try {
        j = req.body.empty() ? json::object() : json::parse(req.body);
    } catch (...) {
        audit_fail("", "bad_json", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        audit_fail("", "missing_workspace_id", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (!deps.workspaces->load(deps.workspaces_path)) {
        audit_fail(workspace_id, "workspaces_reload_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        audit_fail(workspace_id, "workspace_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    const WorkspaceRec& w = *wopt;
    if (w.status != "enabled") {
        audit_fail(workspace_id, "workspace_disabled", 403);
        deps.reply_json(res, 403, json{
            {"ok", false},
            {"error", "forbidden"},
            {"message", "workspace disabled"}
        }.dump());
        return;
    }

    auto mopt = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!mopt.has_value() || mopt->status != "invited") {
        audit_fail(workspace_id, "invitation_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace invitation not found"}
        }.dump());
        return;
    }

    const std::string now_iso =
        iso_utc_from_epoch_sec(deps.now_epoch_sec ? deps.now_epoch_sec() : 0);

    if (!deps.workspaces->set_member_status(workspace_id, actor_fp, "enabled", now_iso, actor_fp)) {
        audit_fail(workspace_id, "set_member_status_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to accept invitation"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_fail(workspace_id, "save_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    auto w2 = deps.workspaces->get(workspace_id);
    auto m2 = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!w2.has_value() || !m2.has_value()) {
        audit_fail(workspace_id, "reload_after_accept_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to reload accepted workspace"}
        }.dump());
        return;
    }

    audit_ok(workspace_id);

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace", workspace_to_user_json(*w2, *m2, deps.users_path)}
    }.dump());
});
    srv.Post("/api/v4/workspaces/invitations/decline",
         [&](const httplib::Request& req, httplib::Response& res) {
    std::string actor_fp, actor_role;
    if (!deps.require_user_auth_users_actor ||
        !deps.require_user_auth_users_actor(
            req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
        return;
    }

    (void)actor_role;
    res.set_header("Cache-Control", "no-store");

    auto audit_fail = [&](const std::string& workspace_id,
                          const std::string& reason,
                          int http,
                          const std::string& detail = "") {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
        f["reason"] = reason;
        f["http"] = std::to_string(http);
        if (!detail.empty()) f["detail"] = detail;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_decline_fail", "fail", f);
    };

    auto audit_ok = [&](const std::string& workspace_id) {
        if (!deps.audit_emit) return;
        std::map<std::string, std::string> f;
        f["actor_fp"] = actor_fp;
        f["workspace_id"] = workspace_id;
        f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
        auto it_cf = req.headers.find("CF-Connecting-IP");
        if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
        auto it_xff = req.headers.find("X-Forwarded-For");
        if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
        deps.audit_emit("workspace.invitation_decline_ok", "ok", f);
    };

    json j;
    try {
        j = req.body.empty() ? json::object() : json::parse(req.body);
    } catch (...) {
        audit_fail("", "bad_json", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "invalid json"}
        }.dump());
        return;
    }

    const std::string workspace_id = trim_copy_safe(j.value("workspace_id", ""));
    if (workspace_id.empty()) {
        audit_fail("", "missing_workspace_id", 400);
        deps.reply_json(res, 400, json{
            {"ok", false},
            {"error", "bad_request"},
            {"message", "missing workspace_id"}
        }.dump());
        return;
    }

    if (!deps.workspaces->load(deps.workspaces_path)) {
        audit_fail(workspace_id, "workspaces_reload_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "workspaces_reload_failed"},
            {"message", "failed to reload workspaces"}
        }.dump());
        return;
    }

    auto wopt = deps.workspaces->get(workspace_id);
    if (!wopt.has_value()) {
        audit_fail(workspace_id, "workspace_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace not found"}
        }.dump());
        return;
    }

    auto mopt = deps.workspaces->get_member(workspace_id, actor_fp);
    if (!mopt.has_value() || mopt->status != "invited") {
        audit_fail(workspace_id, "invitation_not_found", 404);
        deps.reply_json(res, 404, json{
            {"ok", false},
            {"error", "not_found"},
            {"message", "workspace invitation not found"}
        }.dump());
        return;
    }

    const std::string now_iso =
        iso_utc_from_epoch_sec(deps.now_epoch_sec ? deps.now_epoch_sec() : 0);

    if (!deps.workspaces->set_member_status(workspace_id, actor_fp, "disabled", now_iso, actor_fp)) {
        audit_fail(workspace_id, "set_member_status_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to decline invitation"}
        }.dump());
        return;
    }

    if (!deps.workspaces->save(deps.workspaces_path)) {
        audit_fail(workspace_id, "save_failed", 500);
        deps.reply_json(res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "failed to save workspaces"}
        }.dump());
        return;
    }

    audit_ok(workspace_id);

    deps.reply_json(res, 200, json{
        {"ok", true},
        {"workspace_id", workspace_id},
        {"status", "disabled"}
    }.dump());
});

    // GET /api/v4/workspaces/files/list?workspace_id=...&path=relative/dir
    // v1: physical filesystem only, no metadata-index merge yet
    srv.Get("/api/v4/workspaces/files/list",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& reason, int http, const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_list_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_dir,
                            std::size_t count) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_dir;
            f["count"] = std::to_string(static_cast<unsigned long long>(count));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_list_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail("workspace_not_found", 404, workspace_id);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail("workspace_disabled", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail("workspace_access_denied", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail("storage_unallocated", 403, workspace_id);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail("pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace list currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_dir;
        if (req.has_param("path")) rel_dir = req.get_param_value("path");

        std::string rel_dir_norm;
        std::filesystem::path abs_dir = workspace_dir_for_default_pool_only(deps.users_path, w);

        if (!rel_dir.empty()) {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_dir, &rel_dir_norm, &nerr)) {
                audit_fail("invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }

            std::string perr;
            const std::filesystem::path ws_root = workspace_dir_for_default_pool_only(deps.users_path, w);
            if (!pqnas::resolve_user_path_strict(ws_root, rel_dir_norm, &abs_dir, &perr)) {
                audit_fail("invalid_path", 400, perr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        struct ListedItem {
            std::string name;
            std::string type;
            std::uint64_t size_bytes = 0;
            long long mtime_unix = 0;
        };

        std::map<std::string, ListedItem> merged;

        bool dir_ok = false;
        {
            std::error_code ec;
            auto st = std::filesystem::symlink_status(abs_dir, ec);
            if (!ec &&
                std::filesystem::exists(st) &&
                !std::filesystem::is_symlink(st) &&
                std::filesystem::is_directory(st)) {
                dir_ok = true;

                for (std::filesystem::directory_iterator it(abs_dir, ec), end; it != end && !ec; it.increment(ec)) {
                const auto name = it->path().filename().string();
                if (name == "." || name == ".." || name.empty()) continue;
                if (name == ".pqnas") continue;

                std::error_code ec2;
                auto st2 = it->symlink_status(ec2);
                if (ec2) continue;

                if (std::filesystem::is_symlink(st2)) {
                    continue; // unsupported in workspace v1; hide from listing
                }

                std::string type = "other";
                if (std::filesystem::is_directory(st2)) {
                    type = "dir";
                } else if (std::filesystem::is_regular_file(st2)) {
                    type = "file";
                } else {
                    continue;
                }

                std::uint64_t size_bytes = 0;
                if (type == "file") {
                    ec2.clear();
                    auto sz = it->file_size(ec2);
                    if (!ec2) size_bytes = static_cast<std::uint64_t>(sz);
                }

                long long mtime_unix = 0;
                ec2.clear();
                auto ft = it->last_write_time(ec2);
                if (!ec2) {
                    using namespace std::chrono;
                    auto sctp = time_point_cast<system_clock::duration>(
                        ft - decltype(ft)::clock::now() + system_clock::now()
                    );
                    mtime_unix = static_cast<long long>(
                        duration_cast<seconds>(sctp.time_since_epoch()).count());
                }

                merged[name] = ListedItem{
                    name,
                    type,
                    size_bytes,
                    mtime_unix
                };
            }
            }
        }

        if (!dir_ok && !rel_dir_norm.empty()) {
            audit_fail("not_found", 404, rel_dir_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "directory not found"}
            }.dump());
            return;
        }

        json out;
        out["ok"] = true;
        out["workspace_id"] = workspace_id;
        out["path"] = rel_dir_norm.empty() ? rel_dir : rel_dir_norm;
        out["items"] = json::array();

        std::size_t count = 0;
        for (const auto& kv : merged) {
            out["items"].push_back(json{
                {"name", kv.second.name},
                {"type", kv.second.type},
                {"size_bytes", kv.second.size_bytes},
                {"mtime_unix", kv.second.mtime_unix}
            });
            ++count;
            if (count >= 5000) break;
        }

        audit_ok(workspace_id, rel_dir_norm.empty() ? rel_dir : rel_dir_norm, count);
        deps.reply_json(res, 200, out.dump());
    });
        // /api/v4/workspaces/files/stat?workspace_id=...&path=rel/path or "." (dir -> children + recursive bytes by default)
    // GET/POST /api/v4/workspaces/files/stat?workspace_id=...&path=rel/path or "." ...
    auto workspace_files_stat_handler = [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        const std::uint64_t RECURSIVE_HARD_CAP = 100000;
        const int RECURSIVE_TIME_CAP_MS = 300;

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& path_rel = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!path_rel.empty()) f["path"] = path_rel;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_stat_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            const std::string& type) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["type"] = type;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_stat_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // Keep consistent with current workspace file routes: default pool only for now.
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace stat currently supports default pool only"}
            }.dump());
            return;
        }

        std::string path_rel;
        if (req.has_param("path")) path_rel = req.get_param_value("path");

        if (path_rel == "." || path_rel == "./" || path_rel == "/") path_rel.clear();

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::string rel_norm;
        std::filesystem::path path_abs = ws_root;

        if (!path_rel.empty()) {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr, path_rel);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }

            std::string perr;
            if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
                audit_fail(workspace_id, "invalid_path", 400, perr, path_rel);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            audit_fail(workspace_id, "not_found", 404, "", path_rel.empty() ? "." : rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "path not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail(workspace_id, "symlink_not_supported", 400, "", path_rel.empty() ? "." : rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported"}
            }.dump());
            return;
        }

        auto make_path_norm = [&](const std::filesystem::path& p) -> std::string {
            std::error_code ec2;
            auto rel = std::filesystem::relative(p, ws_root, ec2);
            if (ec2) return "/";
            std::string s = rel.generic_string();
            if (s.empty() || s == ".") return "/";
            if (!s.empty() && s[0] != '/') s = "/" + s;
            return s;
        };

        auto mode_octal_from_perms = [&](std::filesystem::perms pr) -> std::string {
            auto has = [&](std::filesystem::perms bit) {
                return (pr & bit) != std::filesystem::perms::none;
            };

            int m = 0;
            if (has(std::filesystem::perms::owner_read))  m |= 0400;
            if (has(std::filesystem::perms::owner_write)) m |= 0200;
            if (has(std::filesystem::perms::owner_exec))  m |= 0100;
            if (has(std::filesystem::perms::group_read))  m |= 0040;
            if (has(std::filesystem::perms::group_write)) m |= 0020;
            if (has(std::filesystem::perms::group_exec))  m |= 0010;
            if (has(std::filesystem::perms::others_read))  m |= 0004;
            if (has(std::filesystem::perms::others_write)) m |= 0002;
            if (has(std::filesystem::perms::others_exec))  m |= 0001;

            std::string out = "0000";
            out[0] = '0';
            out[1] = static_cast<char>('0' + ((m >> 6) & 0x7));
            out[2] = static_cast<char>('0' + ((m >> 3) & 0x7));
            out[3] = static_cast<char>('0' + (m & 0x7));
            return out;
        };

        auto guess_mime = [&](const std::string& name) -> std::string {
            auto lower = [](std::string s) {
                for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                return s;
            };

            std::string n = lower(name);
            auto dot = n.rfind('.');
            std::string ext = (dot == std::string::npos) ? "" : n.substr(dot + 1);

            if (ext == "txt" || ext == "log" || ext == "md") return "text/plain";
            if (ext == "json") return "application/json";
            if (ext == "html" || ext == "htm") return "text/html";
            if (ext == "css") return "text/css";
            if (ext == "js") return "application/javascript";
            if (ext == "xml") return "application/xml";
            if (ext == "csv") return "text/csv";

            if (ext == "png") return "image/png";
            if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
            if (ext == "gif") return "image/gif";
            if (ext == "webp") return "image/webp";
            if (ext == "svg") return "image/svg+xml";

            if (ext == "pdf") return "application/pdf";
            if (ext == "zip") return "application/zip";

            return "application/octet-stream";
        };

        auto looks_like_text = [&](const std::filesystem::path& p) -> bool {
            std::ifstream f(p, std::ios::binary);
            if (!f.good()) return false;

            char buf[4096];
            f.read(buf, sizeof(buf));
            std::streamsize n = f.gcount();
            for (std::streamsize i = 0; i < n; ++i) {
                if (buf[i] == '\0') return false;
            }
            return true;
        };

        const bool is_dir = std::filesystem::is_directory(st);
        const bool is_file = std::filesystem::is_regular_file(st);

        std::string type = "other";
        if (is_dir) type = "dir";
        else if (is_file) type = "file";

        std::string path_norm = path_rel.empty() ? "/" : make_path_norm(path_abs);
        const std::string name = path_rel.empty() ? "" : path_abs.filename().string();

        std::uint64_t mtime_epoch = 0;
        {
            std::error_code ec3;
            auto ftime = std::filesystem::last_write_time(path_abs, ec3);
            if (!ec3) {
                using namespace std::chrono;
                auto sctp = time_point_cast<system_clock::duration>(
                    ftime - std::filesystem::file_time_type::clock::now() + system_clock::now()
                );
                auto sec = duration_cast<seconds>(sctp.time_since_epoch()).count();
                if (sec > 0) mtime_epoch = static_cast<std::uint64_t>(sec);
            }
        }

        std::string mode_octal = "0000";
        {
            std::error_code ec4;
            auto stp = std::filesystem::status(path_abs, ec4);
            if (!ec4) mode_octal = mode_octal_from_perms(stp.permissions());
        }

        json out;
        out["ok"] = true;
        out["workspace_id"] = workspace_id;
        out["path"] = path_rel.empty() ? "." : rel_norm;
        out["path_norm"] = path_norm;
        out["name"] = name;
        out["type"] = type;
        out["exists"] = true;
        if (mtime_epoch > 0) out["mtime_epoch"] = mtime_epoch;
        out["mode_octal"] = mode_octal;

        if (type == "file") {
            out["bytes"] = pqnas::file_size_u64_safe(path_abs);
            out["mime"] = guess_mime(name);
            out["is_text"] = looks_like_text(path_abs);

            audit_ok(workspace_id, path_rel.empty() ? "." : rel_norm, type);
            deps.reply_json(res, 200, out.dump());
            return;
        }

        if (type == "dir") {
            std::uint64_t c_files = 0, c_dirs = 0, c_other = 0;

            std::error_code ec5;
            for (auto it = std::filesystem::directory_iterator(
                     path_abs,
                     std::filesystem::directory_options::skip_permission_denied,
                     ec5);
                 !ec5 && it != std::filesystem::directory_iterator();
                 it.increment(ec5)) {

                std::error_code ec6;
                auto stc = it->symlink_status(ec6);
                if (ec6) { c_other++; continue; }

                if (std::filesystem::is_symlink(stc)) { c_other++; continue; }
                if (std::filesystem::is_directory(stc)) c_dirs++;
                else if (std::filesystem::is_regular_file(stc)) c_files++;
                else c_other++;
            }

            out["children"] = json{
                {"files", c_files},
                {"dirs", c_dirs},
                {"other", c_other}
            };

            std::uint64_t bytes_recursive = 0;
            std::uint64_t scanned = 0;
            bool complete = true;

            auto t0 = std::chrono::steady_clock::now();
            std::filesystem::directory_options opts =
                std::filesystem::directory_options::skip_permission_denied;

            ec5.clear();
            for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec5);
                 it != std::filesystem::recursive_directory_iterator();
                 it.increment(ec5)) {

                if (ec5) {
                    audit_fail(workspace_id, "walk_failed", 500, ec5.message(), path_rel.empty() ? "." : rel_norm);
                    deps.reply_json(res, 500, json{
                        {"ok", false},
                        {"error", "server_error"},
                        {"message", "directory walk failed"},
                        {"detail", ec5.message()}
                    }.dump());
                    return;
                }

                scanned++;

                if (scanned >= RECURSIVE_HARD_CAP) {
                    complete = false;
                    break;
                }

                auto now = std::chrono::steady_clock::now();
                auto ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count());
                if (ms >= RECURSIVE_TIME_CAP_MS) {
                    complete = false;
                    break;
                }

                std::error_code ec6;
                auto st2 = it->symlink_status(ec6);
                if (ec6) continue;

                if (std::filesystem::is_symlink(st2)) {
                    if (it->is_directory(ec6)) it.disable_recursion_pending();
                    continue;
                }

                if (std::filesystem::is_regular_file(st2)) {
                    bytes_recursive += pqnas::file_size_u64_safe(it->path());
                }
            }

            out["bytes_recursive"] = bytes_recursive;
            out["recursive_scanned_entries"] = scanned;
            out["recursive_complete"] = complete;
            out["scan_cap"] = RECURSIVE_HARD_CAP;
            out["time_cap_ms"] = RECURSIVE_TIME_CAP_MS;

            audit_ok(workspace_id, path_rel.empty() ? "." : rel_norm, type);
            deps.reply_json(res, 200, out.dump());
            return;
        }

        audit_ok(workspace_id, path_rel.empty() ? "." : rel_norm, type);
        deps.reply_json(res, 200, out.dump());
    };

    srv.Post("/api/v4/workspaces/files/stat", workspace_files_stat_handler);
    srv.Get ("/api/v4/workspaces/files/stat", workspace_files_stat_handler);
    // POST /api/v4/workspaces/files/hash?workspace_id=...&path=rel/path&algo=sha256
    srv.Post("/api/v4/workspaces/files/hash",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& path_rel = "",
                              const std::string& algo = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!path_rel.empty()) f["path"] = path_rel;
            if (!algo.empty())     f["algo"] = algo;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_hash_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& path_rel,
                            const std::string& algo,
                            std::uint64_t bytes,
                            const std::string& digest_hex) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = path_rel;
            f["algo"] = algo;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["digest"] = digest_hex;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_hash_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // Keep consistent with current workspace file routes.
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace hash currently supports default pool only"}
            }.dump());
            return;
        }

        std::string path_rel;
        if (req.has_param("path")) path_rel = req.get_param_value("path");
        if (path_rel.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        std::string algo = "sha256";
        if (req.has_param("algo")) algo = req.get_param_value("algo");

        if (algo != "sha256") {
            audit_fail(workspace_id, "unsupported_algo", 400, "", path_rel, algo);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "unsupported algo (use sha256)"}
            }.dump());
            return;
        }

        std::string rel_norm;
        std::string nerr;
        if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
            audit_fail(workspace_id, "invalid_path", 400, nerr, path_rel, algo);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path path_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr, path_rel, algo);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

         std::error_code ec;
         auto st = std::filesystem::symlink_status(path_abs, ec);
         if (ec || !std::filesystem::exists(st)) {
             audit_fail(workspace_id, "not_found", 404, "", rel_norm, algo);
             deps.reply_json(res, 404, json{
                 {"ok", false},
                 {"error", "not_found"},
                 {"message", "file not found"}
             }.dump());
             return;
         }

         if (std::filesystem::is_symlink(st)) {
             audit_fail(workspace_id, "symlink_not_supported", 400, "", rel_norm, algo);
             deps.reply_json(res, 400, json{
                 {"ok", false},
                 {"error", "bad_request"},
                 {"message", "symlinks not supported"}
             }.dump());
             return;
         }

         if (!std::filesystem::is_regular_file(st)) {
             audit_fail(workspace_id, "not_found", 404, "", rel_norm, algo);
             deps.reply_json(res, 404, json{
                 {"ok", false},
                 {"error", "not_found"},
                 {"message", "file not found"}
             }.dump());
             return;
         }
        const std::uint64_t bytes = pqnas::file_size_u64_safe(path_abs);

        std::string digest_hex, herr;
        if (!sha256_file_local(path_abs, &digest_hex, &herr)) {
            audit_fail(workspace_id, "hash_failed", 500, herr, rel_norm, algo);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "hash failed"},
                {"detail", herr}
            }.dump());
            return;
        }

        audit_ok(workspace_id, rel_norm, algo, bytes, digest_hex);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"algo", algo},
            {"bytes", bytes},
            {"digest_hex", digest_hex}
        }.dump());
    });

        // GET /api/v4/workspaces/files/read_text?workspace_id=...&path=rel/path
    srv.Get("/api/v4/workspaces/files/read_text",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& path_rel = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!path_rel.empty()) f["path"] = path_rel;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_read_text_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& path_rel,
                            std::uint64_t bytes,
                            std::uint64_t mtime_epoch,
                            const std::string& sha256_hex) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = path_rel;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["mtime_epoch"] = std::to_string(static_cast<unsigned long long>(mtime_epoch));
            f["sha256"] = sha256_hex;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_read_text_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";
        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace read_text currently supports default pool only"}
            }.dump());
            return;
        }

        std::string path_rel;
        if (req.has_param("path")) path_rel = req.get_param_value("path");
        if (path_rel.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }
        const std::string session_id =
            req.has_param("session_id") ? trim_copy_safe(req.get_param_value("session_id")) : "";

        std::string rel_norm;
        std::string nerr;
        if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
            audit_fail(workspace_id, "invalid_path", 400, nerr, path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path path_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr, path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            audit_fail(workspace_id, "not_found", 404, "", rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "file not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail(workspace_id, "symlink_not_supported", 400, "", rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported"}
            }.dump());
            return;
        }

        if (!std::filesystem::is_regular_file(st)) {
            audit_fail(workspace_id, "not_file", 400, "", rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "not a file"}
            }.dump());
            return;
        }

        const std::uint64_t bytes = pqnas::file_size_u64_safe(path_abs);
        if (bytes > k_text_edit_max_bytes_local) {
            audit_fail(workspace_id, "too_large", 413, std::to_string(static_cast<unsigned long long>(bytes)), rel_norm);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "file too large to edit in browser"},
                {"bytes", bytes},
                {"max_bytes", k_text_edit_max_bytes_local}
            }.dump());
            return;
        }

        std::string terr;
        if (!looks_like_text_no_nul_prefix_local(path_abs, &terr)) {
            audit_fail(workspace_id, "not_text", 400, terr, rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "not_text"},
                {"message", "file does not look like text"}
            }.dump());
            return;
        }

        std::string raw;
        std::string err;
        if (!read_file_bytes_all_local(path_abs, &raw, &err)) {
            audit_fail(workspace_id, "read_failed", 500, err, rel_norm);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "read failed"},
                {"detail", err}
            }.dump());
            return;
        }

        bool had_bom = false;
        std::string text = strip_utf8_bom_local(raw, &had_bom);
        if (!is_valid_utf8_local(text)) {
            audit_fail(workspace_id, "decode_failed", 400, "invalid utf-8", rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "decode_failed"},
                {"message", "file is not valid UTF-8 text"}
            }.dump());
            return;
        }

        std::string digest_hex, herr;
        if (!sha256_file_local(path_abs, &digest_hex, &herr)) {
            audit_fail(workspace_id, "hash_failed", 500, herr, rel_norm);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "hash failed"},
                {"detail", herr}
            }.dump());
            return;
        }

        const std::uint64_t mtime_epoch = file_mtime_epoch_safe_local(path_abs);
        const std::string name = path_abs.filename().string();

                json edit = json{
                    {"can_edit", (mopt->role == "owner" || mopt->role == "editor")},
                    {"read_only", !(mopt->role == "owner" || mopt->role == "editor")},
                    {"locked_by_other", false}
                };

                if (mopt->role == "owner" || mopt->role == "editor") {
                    std::string lerr;
                    const auto lock_abs = workspace_edit_lock_path_local(ws_root, rel_norm, &lerr);

                    if (!lock_abs.empty()) {
                        WorkspaceEditLeaseRec cur;
                        bool found = false;

                        if (load_workspace_edit_lease_local(lock_abs, &cur, &found, &lerr) && found) {
                            const std::uint64_t now_epoch =
                                deps.now_epoch_sec ? static_cast<std::uint64_t>(deps.now_epoch_sec()) : 0;

                            if (workspace_edit_lease_is_active_local(cur, now_epoch)) {
                                edit["lease"] = workspace_edit_lease_public_json_local(cur);

                                if (!workspace_edit_lease_owned_by_local(cur, actor_fp, session_id)) {
                                    edit["can_edit"] = false;
                                    edit["read_only"] = true;
                                    edit["locked_by_other"] = true;
                                }
                            }
                        }
                    }
                }

        audit_ok(workspace_id, rel_norm, bytes, mtime_epoch, digest_hex);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"name", name},
            {"mime", guess_text_mime_from_name_local(name)},
            {"encoding", "utf-8"},
            {"had_utf8_bom", had_bom},
            {"bytes", bytes},
            {"mtime_epoch", mtime_epoch},
            {"sha256", digest_hex},
            {"text", text},
            {"edit", edit}
        }.dump());
    });

        // POST /api/v4/workspaces/files/write_text
    srv.Post("/api/v4/workspaces/files/write_text",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& path_rel = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!path_rel.empty()) f["path"] = path_rel;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_write_text_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& path_rel,
                            std::uint64_t bytes,
                            std::uint64_t mtime_epoch,
                            const std::string& sha256_hex) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = path_rel;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["mtime_epoch"] = std::to_string(static_cast<unsigned long long>(mtime_epoch));
            f["sha256"] = sha256_hex;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_write_text_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            audit_fail("", "invalid_json", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(in.value("workspace_id", ""));
        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace write_text currently supports default pool only"}
            }.dump());
            return;
        }

        const std::string path_rel = in.value("path", "");
        const std::string text = in.value("text", "");
        const std::uint64_t expected_mtime_epoch =
            (in.contains("expected_mtime_epoch") && in["expected_mtime_epoch"].is_number_unsigned())
                ? in["expected_mtime_epoch"].get<std::uint64_t>()
                : 0;
        const std::string expected_sha256 = in.value("expected_sha256", "");
        const std::string session_id = trim_copy_safe(in.value("session_id", ""));

        if (path_rel.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }
         if (session_id.empty()) {
             audit_fail(workspace_id, "missing_session_id", 400, "", path_rel);
             deps.reply_json(res, 400, json{
                 {"ok", false},
                 {"error", "bad_request"},
                 {"message", "missing session_id"}
             }.dump());
             return;
         }
        if (!is_valid_utf8_local(text)) {
            audit_fail(workspace_id, "invalid_utf8", 400, "", path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "text must be valid UTF-8"}
            }.dump());
            return;
        }

        if (static_cast<std::uint64_t>(text.size()) > k_text_edit_max_bytes_local) {
            audit_fail(workspace_id, "too_large", 413, std::to_string(static_cast<unsigned long long>(text.size())), path_rel);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "file too large to edit in browser"},
                {"bytes", static_cast<std::uint64_t>(text.size())},
                {"max_bytes", k_text_edit_max_bytes_local}
            }.dump());
            return;
        }

        std::string rel_norm;
        std::string nerr;
        if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
            audit_fail(workspace_id, "invalid_path", 400, nerr, path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path path_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr, path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            audit_fail(workspace_id, "not_found", 404, "", rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "file not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail(workspace_id, "symlink_not_supported", 400, "", rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported"}
            }.dump());
            return;
        }

        if (!std::filesystem::is_regular_file(st)) {
            audit_fail(workspace_id, "not_file", 400, "", rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "not a file"}
            }.dump());
            return;
        }

        const std::uint64_t old_bytes = pqnas::file_size_u64_safe(path_abs);
        if (old_bytes > k_text_edit_max_bytes_local) {
            audit_fail(workspace_id, "too_large", 413, std::to_string(static_cast<unsigned long long>(old_bytes)), rel_norm);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "file too large to edit in browser"},
                {"bytes", old_bytes},
                {"max_bytes", k_text_edit_max_bytes_local}
            }.dump());
            return;
        }

        std::string terr;
        if (!looks_like_text_no_nul_prefix_local(path_abs, &terr)) {
            audit_fail(workspace_id, "not_text", 400, terr, rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "not_text"},
                {"message", "file does not look like text"}
            }.dump());
            return;
        }

        const std::uint64_t current_mtime_epoch = file_mtime_epoch_safe_local(path_abs);

        std::string current_sha256, herr;
        if (!sha256_file_local(path_abs, &current_sha256, &herr)) {
            audit_fail(workspace_id, "hash_failed", 500, herr, rel_norm);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "hash failed"},
                {"detail", herr}
            }.dump());
            return;
        }

        if (expected_mtime_epoch != 0 &&
            current_mtime_epoch != 0 &&
            expected_mtime_epoch != current_mtime_epoch) {
            audit_fail(workspace_id, "changed_on_server", 409, "mtime mismatch", rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "changed_on_server"},
                {"message", "file changed on server"},
                {"current_mtime_epoch", current_mtime_epoch},
                {"current_sha256", current_sha256}
            }.dump());
            return;
        }

        if (!expected_sha256.empty() && expected_sha256 != current_sha256) {
            audit_fail(workspace_id, "changed_on_server", 409, "sha256 mismatch", rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "changed_on_server"},
                {"message", "file changed on server"},
                {"current_mtime_epoch", current_mtime_epoch},
                {"current_sha256", current_sha256}
            }.dump());
            return;
        }
                 {
             std::string lerr;
             const auto lock_abs = workspace_edit_lock_path_local(ws_root, rel_norm, &lerr);
             if (lock_abs.empty()) {
                 audit_fail(workspace_id, "edit_lock_path_failed", 500, lerr, rel_norm);
                 deps.reply_json(res, 500, json{
                     {"ok", false},
                     {"error", "server_error"},
                     {"message", "failed to build edit lock path"},
                     {"detail", lerr}
                 }.dump());
                 return;
             }

             WorkspaceEditLeaseRec cur;
             bool found = false;
             if (!load_workspace_edit_lease_local(lock_abs, &cur, &found, &lerr)) {
                 audit_fail(workspace_id, "edit_lock_load_failed", 500, lerr, rel_norm);
                 deps.reply_json(res, 500, json{
                     {"ok", false},
                     {"error", "server_error"},
                     {"message", "failed to load edit lease"},
                     {"detail", lerr}
                 }.dump());
                 return;
             }

             const std::uint64_t now_epoch =
                 deps.now_epoch_sec ? static_cast<std::uint64_t>(deps.now_epoch_sec()) : 0;

             if (!found ||
                 !workspace_edit_lease_is_active_local(cur, now_epoch) ||
                 !workspace_edit_lease_owned_by_local(cur, actor_fp, session_id)) {
                 audit_fail(workspace_id, "edit_locked", 409, "", rel_norm);
                 deps.reply_json(res, 409, json{
                     {"ok", false},
                     {"error", "edit_locked"},
                     {"message", "file is currently being edited"},
                     {"lease", found ? workspace_edit_lease_public_json_local(cur) : json::object()}
                 }.dump());
                 return;
             }
         }
        // workspace quota safety
        const std::uint64_t used_bytes = dir_size_bytes_best_effort_local(ws_root);
        const std::uint64_t existing_bytes = pqnas::file_size_u64_safe(path_abs);

        std::uint64_t would_used_bytes = used_bytes;
        if (existing_bytes <= would_used_bytes) {
            would_used_bytes -= existing_bytes;
        }
        would_used_bytes += static_cast<std::uint64_t>(text.size());

        if (w.quota_bytes == 0) {
            if (!text.empty()) {
                audit_fail(workspace_id, "quota_exceeded", 413, "", rel_norm);
                deps.reply_json(res, 413, json{
                    {"ok", false},
                    {"error", "quota_exceeded"},
                    {"message", "Quota exceeded"},
                    {"workspace_id", workspace_id},
                    {"used_bytes", used_bytes},
                    {"quota_bytes", w.quota_bytes},
                    {"incoming_bytes", static_cast<std::uint64_t>(text.size())},
                    {"existing_bytes", existing_bytes},
                    {"would_used_bytes", would_used_bytes}
                }.dump());
                return;
            }
        } else if (would_used_bytes > w.quota_bytes) {
            audit_fail(workspace_id, "quota_exceeded", 413, "", rel_norm);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "Quota exceeded"},
                {"workspace_id", workspace_id},
                {"used_bytes", used_bytes},
                {"quota_bytes", w.quota_bytes},
                {"incoming_bytes", static_cast<std::uint64_t>(text.size())},
                {"existing_bytes", existing_bytes},
                {"would_used_bytes", would_used_bytes}
            }.dump());
            return;
        }

        if (!write_text_file_atomic_utf8_local(path_abs, text, &perr)) {
            audit_fail(workspace_id, "write_failed", 500, perr, rel_norm);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "write failed"},
                {"detail", perr}
            }.dump());
            return;
        }

        const std::uint64_t new_bytes = pqnas::file_size_u64_safe(path_abs);
        const std::uint64_t new_mtime_epoch = file_mtime_epoch_safe_local(path_abs);

        std::string new_sha256, herr2;
        if (!sha256_file_local(path_abs, &new_sha256, &herr2)) {
            audit_fail(workspace_id, "hash_after_write_failed", 500, herr2, rel_norm);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "hash failed after write"},
                {"detail", herr2}
            }.dump());
            return;
        }

        audit_ok(workspace_id, rel_norm, new_bytes, new_mtime_epoch, new_sha256);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"bytes", new_bytes},
            {"mtime_epoch", new_mtime_epoch},
            {"sha256", new_sha256}
        }.dump());
    });


    // POST /api/v4/workspaces/files/edit_lease/acquire
    srv.Post("/api/v4/workspaces/files/edit_lease/acquire",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(in.value("workspace_id", ""));
        const std::string path_rel = in.value("path", "");
        const std::string session_id = trim_copy_safe(in.value("session_id", ""));

        std::uint64_t lease_seconds = k_edit_lease_default_sec_local;
        if (in.contains("lease_seconds") && in["lease_seconds"].is_number_unsigned()) {
            lease_seconds = in["lease_seconds"].get<std::uint64_t>();
        }
        if (lease_seconds < k_edit_lease_min_sec_local) lease_seconds = k_edit_lease_min_sec_local;
        if (lease_seconds > k_edit_lease_max_sec_local) lease_seconds = k_edit_lease_max_sec_local;

        if (workspace_id.empty() || path_rel.empty() || session_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id, path or session_id"}
            }.dump());
            return;
        }

        WorkspaceMemberRec member;
        std::string rel_norm, rerr;
        std::filesystem::path ws_root, abs_path;
             if (!resolve_workspace_edit_target_local(deps, actor_fp, workspace_id, path_rel, true,
                                                      &member, &rel_norm, &ws_root, &abs_path, &rerr)) {
            const int http =
                (rerr == "workspace not found" || rerr == "file not found") ? 404 :
                (rerr == "workspace access denied" || rerr == "workspace write access denied" ||
                 rerr == "workspace disabled" || rerr == "workspace storage not allocated") ? 403 :
                (rerr == "pool not supported yet") ? 400 : 400;

            deps.reply_json(res, http, json{
                {"ok", false},
                {"error", (http == 404) ? "not_found" : ((http == 403) ? "forbidden" : "bad_request")},
                {"message", rerr}
            }.dump());
            return;
        }

        std::string lerr;
        const auto lock_abs = workspace_edit_lock_path_local(ws_root, rel_norm, &lerr);
        if (lock_abs.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to build edit lock path"},
                {"detail", lerr}
            }.dump());
            return;
        }

        const std::uint64_t now_epoch =
            deps.now_epoch_sec ? static_cast<std::uint64_t>(deps.now_epoch_sec()) : 0;

        WorkspaceEditLeaseRec cur;
        bool found = false;
        if (!load_workspace_edit_lease_local(lock_abs, &cur, &found, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        if (found &&
            workspace_edit_lease_is_active_local(cur, now_epoch) &&
            !workspace_edit_lease_owned_by_local(cur, actor_fp, session_id)) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "edit_locked"},
                {"message", "file is currently being edited"},
                {"lease", workspace_edit_lease_public_json_local(cur)},
                {"edit", {
                    {"can_edit", false},
                    {"read_only", true},
                    {"locked_by_other", true}
                }}
            }.dump());
            return;
        }

        WorkspaceEditLeaseRec next;
        next.workspace_id = workspace_id;
        next.path = rel_norm;
        next.holder_fp = actor_fp;
        next.session_id = session_id;
        next.mode = "edit";
        next.acquired_epoch = (found && workspace_edit_lease_owned_by_local(cur, actor_fp, session_id) && cur.acquired_epoch != 0)
            ? cur.acquired_epoch : now_epoch;
        next.last_seen_epoch = now_epoch;
        next.expires_epoch = now_epoch + lease_seconds;
        next.acquired_at = (found && workspace_edit_lease_owned_by_local(cur, actor_fp, session_id) && !cur.acquired_at.empty())
            ? cur.acquired_at : iso_utc_from_epoch_sec(static_cast<std::int64_t>(next.acquired_epoch));
        next.last_seen_at = iso_utc_from_epoch_sec(static_cast<std::int64_t>(next.last_seen_epoch));
        next.expires_at = iso_utc_from_epoch_sec(static_cast<std::int64_t>(next.expires_epoch));

        if (!save_workspace_edit_lease_local(lock_abs, next, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"lease", workspace_edit_lease_public_json_local(next)},
            {"edit", {
                {"can_edit", true},
                {"read_only", false},
                {"locked_by_other", false}
            }}
        }.dump());
    });

    // POST /api/v4/workspaces/files/edit_lease/refresh
    srv.Post("/api/v4/workspaces/files/edit_lease/refresh",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(in.value("workspace_id", ""));
        const std::string path_rel = in.value("path", "");
        const std::string session_id = trim_copy_safe(in.value("session_id", ""));

        std::uint64_t lease_seconds = k_edit_lease_default_sec_local;
        if (in.contains("lease_seconds") && in["lease_seconds"].is_number_unsigned()) {
            lease_seconds = in["lease_seconds"].get<std::uint64_t>();
        }
        if (lease_seconds < k_edit_lease_min_sec_local) lease_seconds = k_edit_lease_min_sec_local;
        if (lease_seconds > k_edit_lease_max_sec_local) lease_seconds = k_edit_lease_max_sec_local;

        if (workspace_id.empty() || path_rel.empty() || session_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id, path or session_id"}
            }.dump());
            return;
        }

        WorkspaceMemberRec member;
        std::string rel_norm, rerr;
        std::filesystem::path ws_root, abs_path;
             if (!resolve_workspace_edit_target_local(deps, actor_fp, workspace_id, path_rel, true,
                                                      &member, &rel_norm, &ws_root, &abs_path, &rerr)) {
            const int http =
                (rerr == "workspace not found" || rerr == "file not found") ? 404 :
                (rerr == "workspace access denied" || rerr == "workspace write access denied" ||
                 rerr == "workspace disabled" || rerr == "workspace storage not allocated") ? 403 :
                (rerr == "pool not supported yet") ? 400 : 400;

            deps.reply_json(res, http, json{
                {"ok", false},
                {"error", (http == 404) ? "not_found" : ((http == 403) ? "forbidden" : "bad_request")},
                {"message", rerr}
            }.dump());
            return;
        }

        std::string lerr;
        const auto lock_abs = workspace_edit_lock_path_local(ws_root, rel_norm, &lerr);
        if (lock_abs.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to build edit lock path"},
                {"detail", lerr}
            }.dump());
            return;
        }

        const std::uint64_t now_epoch =
            deps.now_epoch_sec ? static_cast<std::uint64_t>(deps.now_epoch_sec()) : 0;

        WorkspaceEditLeaseRec cur;
        bool found = false;
        if (!load_workspace_edit_lease_local(lock_abs, &cur, &found, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        if (!found) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "edit_lock_missing"},
                {"message", "edit lease not found"}
            }.dump());
            return;
        }

        if (!workspace_edit_lease_owned_by_local(cur, actor_fp, session_id)) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "edit_locked"},
                {"message", "file is currently being edited by another session"},
                {"lease", workspace_edit_lease_public_json_local(cur)}
            }.dump());
            return;
        }

        cur.last_seen_epoch = now_epoch;
        cur.expires_epoch = now_epoch + lease_seconds;
        cur.last_seen_at = iso_utc_from_epoch_sec(static_cast<std::int64_t>(cur.last_seen_epoch));
        cur.expires_at = iso_utc_from_epoch_sec(static_cast<std::int64_t>(cur.expires_epoch));

        if (!save_workspace_edit_lease_local(lock_abs, cur, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"lease", workspace_edit_lease_public_json_local(cur)}
        }.dump());
    });

    // POST /api/v4/workspaces/files/edit_lease/release
    srv.Post("/api/v4/workspaces/files/edit_lease/release",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        json in = json::parse(req.body, nullptr, false);
        if (in.is_discarded() || !in.is_object()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        const std::string workspace_id = trim_copy_safe(in.value("workspace_id", ""));
        const std::string path_rel = in.value("path", "");
        const std::string session_id = trim_copy_safe(in.value("session_id", ""));

        if (workspace_id.empty() || path_rel.empty() || session_id.empty()) {
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id, path or session_id"}
            }.dump());
            return;
        }

        WorkspaceMemberRec member;
        std::string rel_norm, rerr;
        std::filesystem::path ws_root, abs_path;
             if (!resolve_workspace_edit_target_local(deps, actor_fp, workspace_id, path_rel, true,
                                                      &member, &rel_norm, &ws_root, &abs_path, &rerr)) {
            const int http =
                (rerr == "workspace not found" || rerr == "file not found") ? 404 :
                (rerr == "workspace access denied" || rerr == "workspace write access denied" ||
                 rerr == "workspace disabled" || rerr == "workspace storage not allocated") ? 403 :
                (rerr == "pool not supported yet") ? 400 : 400;

            deps.reply_json(res, http, json{
                {"ok", false},
                {"error", (http == 404) ? "not_found" : ((http == 403) ? "forbidden" : "bad_request")},
                {"message", rerr}
            }.dump());
            return;
        }

        std::string lerr;
        const auto lock_abs = workspace_edit_lock_path_local(ws_root, rel_norm, &lerr);
        if (lock_abs.empty()) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to build edit lock path"},
                {"detail", lerr}
            }.dump());
            return;
        }

        WorkspaceEditLeaseRec cur;
        bool found = false;
        if (!load_workspace_edit_lease_local(lock_abs, &cur, &found, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to load edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        if (!found) {
            deps.reply_json(res, 200, json{
                {"ok", true},
                {"workspace_id", workspace_id},
                {"path", rel_norm},
                {"released", false}
            }.dump());
            return;
        }

        if (!workspace_edit_lease_owned_by_local(cur, actor_fp, session_id)) {
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "edit_locked"},
                {"message", "file is currently being edited by another session"},
                {"lease", workspace_edit_lease_public_json_local(cur)}
            }.dump());
            return;
        }

        if (!remove_workspace_edit_lease_local(lock_abs, &lerr)) {
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to remove edit lease"},
                {"detail", lerr}
            }.dump());
            return;
        }

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"released", true}
        }.dump());
    });

    // POST /api/v4/workspaces/files/stat_sel
    // Body: { "paths": ["rel/path", ".", ...] }
    // Returns aggregated selection stats (total bytes etc) + per-item minimal stats.
    srv.Post("/api/v4/workspaces/files/stat_sel",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        const std::uint64_t RECURSIVE_HARD_CAP = 100000;
        const int RECURSIVE_TIME_CAP_MS = 300;
        const int MAX_ITEMS = 200;

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_stat_sel_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            int count,
                            std::uint64_t bytes_total,
                            bool partial) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["count"] = std::to_string(count);
            f["bytes_total"] = std::to_string(static_cast<unsigned long long>(bytes_total));
            f["partial"] = partial ? "true" : "false";
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_stat_sel_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace stat_sel currently supports default pool only"}
            }.dump());
            return;
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            audit_fail(workspace_id, "bad_json", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        if (!body.is_object() || !body.contains("paths") || !body["paths"].is_array()) {
            audit_fail(workspace_id, "bad_request", 400, "body must be { paths: [...] }");
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "body must be { paths: [...] }"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        auto mode_octal_from_perms = [&](std::filesystem::perms pr) -> std::string {
            auto has = [&](std::filesystem::perms bit) {
                return (pr & bit) != std::filesystem::perms::none;
            };

            int m = 0;
            if (has(std::filesystem::perms::owner_read))  m |= 0400;
            if (has(std::filesystem::perms::owner_write)) m |= 0200;
            if (has(std::filesystem::perms::owner_exec))  m |= 0100;
            if (has(std::filesystem::perms::group_read))  m |= 0040;
            if (has(std::filesystem::perms::group_write)) m |= 0020;
            if (has(std::filesystem::perms::group_exec))  m |= 0010;
            if (has(std::filesystem::perms::others_read))  m |= 0004;
            if (has(std::filesystem::perms::others_write)) m |= 0002;
            if (has(std::filesystem::perms::others_exec))  m |= 0001;

            std::string out = "0000";
            out[0] = '0';
            out[1] = static_cast<char>('0' + ((m >> 6) & 0x7));
            out[2] = static_cast<char>('0' + ((m >> 3) & 0x7));
            out[3] = static_cast<char>('0' + (m & 0x7));
            return out;
        };

        auto make_path_norm = [&](const std::filesystem::path& p) -> std::string {
            std::error_code ec2;
            auto rel = std::filesystem::relative(p, ws_root, ec2);
            if (ec2) return "/";
            std::string s = rel.generic_string();
            if (s.empty() || s == ".") return "/";
            if (!s.empty() && s[0] != '/') s = "/" + s;
            return s;
        };

        auto dir_bytes_recursive = [&](const std::filesystem::path& base_abs,
                                       std::uint64_t* out_scanned,
                                       bool* out_complete) -> std::uint64_t {
            std::uint64_t bytes_recursive = 0;
            std::uint64_t scanned = 0;
            bool complete = true;

            auto t0 = std::chrono::steady_clock::now();
            std::filesystem::directory_options opts =
                std::filesystem::directory_options::skip_permission_denied;

            std::error_code ec;
            for (auto it = std::filesystem::recursive_directory_iterator(base_abs, opts, ec);
                 it != std::filesystem::recursive_directory_iterator();
                 it.increment(ec)) {

                if (ec) {
                    complete = false;
                    break;
                }

                scanned++;
                if (scanned >= RECURSIVE_HARD_CAP) {
                    complete = false;
                    break;
                }

                auto now = std::chrono::steady_clock::now();
                auto ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count());
                if (ms >= RECURSIVE_TIME_CAP_MS) {
                    complete = false;
                    break;
                }

                std::error_code ec6;
                auto st2 = it->symlink_status(ec6);
                if (ec6) continue;

                if (std::filesystem::is_symlink(st2)) {
                    if (it->is_directory(ec6)) it.disable_recursion_pending();
                    continue;
                }

                if (std::filesystem::is_regular_file(st2)) {
                    bytes_recursive += pqnas::file_size_u64_safe(it->path());
                }
            }

            if (out_scanned) *out_scanned = scanned;
            if (out_complete) *out_complete = complete;
            return bytes_recursive;
        };

        std::uint64_t total_bytes = 0;
        int n_files = 0, n_dirs = 0, n_other = 0;
        bool partial = false;

        json items = json::array();
        json errors = json::array();

        int idx = 0;
        for (const auto& v : body["paths"]) {
            if (idx >= MAX_ITEMS) {
                partial = true;
                break;
            }
            idx++;

            if (!v.is_string()) {
                partial = true;
                errors.push_back(json{
                    {"path", ""},
                    {"error", "bad_request"},
                    {"message", "path must be string"}
                });
                continue;
            }

            std::string path_rel = v.get<std::string>();
            if (path_rel == "." || path_rel == "./" || path_rel == "/") path_rel.clear();

            std::string rel_norm;
            std::filesystem::path path_abs = ws_root;

            if (!path_rel.empty()) {
                std::string nerr;
                if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
                    partial = true;
                    errors.push_back(json{
                        {"path", path_rel},
                        {"error", "bad_request"},
                        {"message", "invalid path"}
                    });
                    continue;
                }

                std::string perr;
                if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
                    partial = true;
                    errors.push_back(json{
                        {"path", path_rel},
                        {"error", "bad_request"},
                        {"message", "invalid path"}
                    });
                    continue;
                }
            }

            std::error_code ec;
            auto st = std::filesystem::symlink_status(path_abs, ec);
            if (ec || !std::filesystem::exists(st)) {
                partial = true;
                errors.push_back(json{
                    {"path", path_rel.empty() ? "." : rel_norm},
                    {"error", "not_found"}
                });
                continue;
            }

            if (std::filesystem::is_symlink(st)) {
                partial = true;
                errors.push_back(json{
                    {"path", path_rel.empty() ? "." : rel_norm},
                    {"error", "symlink_not_supported"}
                });
                continue;
            }

            const bool is_dir = std::filesystem::is_directory(st);
            const bool is_file = std::filesystem::is_regular_file(st);

            std::string type = "other";
            if (is_dir) type = "dir";
            else if (is_file) type = "file";

            json itj;
            itj["path"] = path_rel.empty() ? "." : rel_norm;
            itj["path_norm"] = path_rel.empty() ? "/" : make_path_norm(path_abs);
            itj["type"] = type;

            {
                std::error_code ec4;
                auto stp = std::filesystem::status(path_abs, ec4);
                if (!ec4) itj["mode_octal"] = mode_octal_from_perms(stp.permissions());
            }

            if (type == "file") {
                std::uint64_t b = pqnas::file_size_u64_safe(path_abs);
                itj["bytes"] = b;
                total_bytes += b;
                n_files++;
                items.push_back(itj);
                continue;
            }

            if (type == "dir") {
                std::uint64_t scanned = 0;
                bool complete = true;
                std::uint64_t b = dir_bytes_recursive(path_abs, &scanned, &complete);

                itj["bytes_recursive"] = b;
                itj["recursive_scanned_entries"] = scanned;
                itj["recursive_complete"] = complete;

                total_bytes += b;
                n_dirs++;
                if (!complete) partial = true;

                items.push_back(itj);
                continue;
            }

            n_other++;
            partial = true;
            items.push_back(itj);
        }

        json out;
        out["ok"] = true;
        out["workspace_id"] = workspace_id;
        out["count"] = static_cast<int>(items.size());
        out["files"] = n_files;
        out["dirs"] = n_dirs;
        out["other"] = n_other;
        out["bytes_total"] = total_bytes;
        out["partial"] = partial;
        out["limits"] = json{
            {"max_items", MAX_ITEMS},
            {"scan_cap", RECURSIVE_HARD_CAP},
            {"time_cap_ms", RECURSIVE_TIME_CAP_MS}
        };
        out["items"] = items;
        out["errors"] = errors;

        audit_ok(workspace_id, static_cast<int>(items.size()), total_bytes, partial);
        deps.reply_json(res, 200, out.dump());
    });
    // POST /api/v4/workspaces/files/mkdir?workspace_id=...&path=relative/dir
    srv.Post("/api/v4/workspaces/files/mkdir",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_mkdir_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_mkdir_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");

        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may create directories
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace mkdir currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_norm;
        std::string nerr;
        if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
            audit_fail(workspace_id, "invalid_path", 400, nerr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_dir;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_dir, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        std::filesystem::create_directories(abs_dir, ec);
        if (ec) {
            audit_fail(workspace_id, "mkdir_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to create directory"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        audit_ok(workspace_id, rel_norm);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm}
        }.dump());
    });
        // PUT /api/v4/workspaces/files/put?workspace_id=...&path=relative/path.bin[&overwrite=1]
    // Body: raw bytes streamed to temp file, then renamed atomically
    srv.Put("/api/v4/workspaces/files/put",
            [&](const httplib::Request& req,
                httplib::Response& res,
                const httplib::ContentReader& content_reader) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto header_u64 = [&](const char* name, std::uint64_t* out) -> bool {
            if (!out) return false;
            auto it = req.headers.find(name);
            if (it == req.headers.end()) return false;
            const std::string& s = it->second;
            try {
                std::size_t idx = 0;
                unsigned long long v = std::stoull(s, &idx, 10);
                if (idx != s.size()) return false;
                *out = static_cast<std::uint64_t>(v);
                return true;
            } catch (...) {
                return false;
            }
        };

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_put_fail", "fail", f);
        };

        auto audit_quota_deny = [&](const std::string& workspace_id,
                                    const std::string& rel_path,
                                    std::uint64_t used_bytes,
                                    std::uint64_t quota_bytes,
                                    std::uint64_t incoming_bytes,
                                    std::uint64_t existing_bytes,
                                    std::uint64_t would_used_bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["used_bytes"] = std::to_string(static_cast<unsigned long long>(used_bytes));
            f["quota_bytes"] = std::to_string(static_cast<unsigned long long>(quota_bytes));
            f["incoming_bytes"] = std::to_string(static_cast<unsigned long long>(incoming_bytes));
            f["existing_bytes"] = std::to_string(static_cast<unsigned long long>(existing_bytes));
            f["would_used_bytes"] = std::to_string(static_cast<unsigned long long>(would_used_bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace_quota_exceeded", "deny", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_put_ok", "ok", f);
        };

        auto file_time_to_epoch_sec = [](const std::filesystem::file_time_type& ft) -> std::int64_t {
            using namespace std::chrono;
            const auto sctp = time_point_cast<system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now() + system_clock::now()
            );
            return static_cast<std::int64_t>(
                duration_cast<seconds>(sctp.time_since_epoch()).count());
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may upload
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace put currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        bool overwrite = false;
        if (req.has_param("overwrite")) {
            const std::string ov = req.get_param_value("overwrite");
            overwrite = (ov == "1" || ov == "true" || ov == "yes");
        }

        std::uint64_t cl = 0;
        if (!header_u64("Content-Length", &cl)) {
            audit_fail(workspace_id, "missing_content_length", 411);
            deps.reply_json(res, 411, json{
                {"ok", false},
                {"error", "length_required"},
                {"message", "Content-Length required"}
            }.dump());
            return;
        }

        const std::uint64_t incoming_bytes = cl;
        const std::uint64_t transport_max =
            (deps.transport_max_upload_bytes ? deps.transport_max_upload_bytes
                                             : deps.payload_max_upload_bytes);

        if (incoming_bytes > transport_max) {
            audit_fail(workspace_id, "transport_limit_exceeded", 413,
                       "Content-Length=" + std::to_string(static_cast<unsigned long long>(incoming_bytes)) +
                       " max=" + std::to_string(static_cast<unsigned long long>(transport_max)));
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "transport_limit_exceeded"},
                {"message", "Upload exceeds maximum allowed size"},
                {"content_length", incoming_bytes},
                {"max_bytes", transport_max},
                {"payload_max_upload_bytes", deps.payload_max_upload_bytes}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path out_abs;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &out_abs, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        {
            std::string found_ancestor;
            if (any_file_ancestor_exists_physical(ws_root, rel_norm, &found_ancestor)) {
                audit_fail(workspace_id, "ancestor_is_file", 409, found_ancestor);
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "a parent path is an existing file"},
                    {"ancestor", found_ancestor}
                }.dump());
                return;
            }
        }

        // quota check
        const std::uint64_t used_bytes = dir_size_bytes_best_effort_local(ws_root);
        const std::uint64_t existing_bytes = pqnas::file_size_u64_safe(out_abs);

        std::uint64_t would_used_bytes = used_bytes;
        if (existing_bytes <= would_used_bytes) {
            would_used_bytes -= existing_bytes;
        }
        would_used_bytes += incoming_bytes;

        if (w.quota_bytes == 0) {
            if (incoming_bytes > 0) {
                audit_quota_deny(workspace_id, rel_norm, used_bytes, w.quota_bytes,
                                 incoming_bytes, existing_bytes, would_used_bytes);
                deps.reply_json(res, 413, json{
                    {"ok", false},
                    {"error", "quota_exceeded"},
                    {"message", "Quota exceeded"},
                    {"workspace_id", workspace_id},
                    {"used_bytes", used_bytes},
                    {"quota_bytes", w.quota_bytes},
                    {"incoming_bytes", incoming_bytes},
                    {"existing_bytes", existing_bytes},
                    {"would_used_bytes", would_used_bytes}
                }.dump());
                return;
            }
        } else if (would_used_bytes > w.quota_bytes) {
            audit_quota_deny(workspace_id, rel_norm, used_bytes, w.quota_bytes,
                             incoming_bytes, existing_bytes, would_used_bytes);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "quota_exceeded"},
                {"message", "Quota exceeded"},
                {"workspace_id", workspace_id},
                {"used_bytes", used_bytes},
                {"quota_bytes", w.quota_bytes},
                {"incoming_bytes", incoming_bytes},
                {"existing_bytes", existing_bytes},
                {"would_used_bytes", would_used_bytes}
            }.dump());
            return;
        }

        bool physical_exists = false;
        std::uint64_t physical_existing_size = 0;
        std::int64_t physical_existing_mtime = 0;

        {
            std::error_code ec;
            auto st_existing = std::filesystem::symlink_status(out_abs, ec);

            // Important:
            // A brand new upload target may live under parent directories that do not
            // exist yet. That is not a fatal error here, because we create parent
            // directories later with create_directories(out_abs.parent_path()).
            if (ec) {
                if (ec == std::make_error_code(std::errc::no_such_file_or_directory)) {
                    ec.clear();
                    physical_exists = false;
                } else {
                    audit_fail(workspace_id, "target_exists_check_failed", 500, ec.message());
                    deps.reply_json(res, 500, json{
                        {"ok", false},
                        {"error", "server_error"},
                        {"message", "target existence check failed"},
                        {"detail", ec.message()}
                    }.dump());
                    return;
                }
            } else {
                physical_exists = std::filesystem::exists(st_existing);
            }

            if (physical_exists) {
                if (std::filesystem::is_symlink(st_existing)) {
                    audit_fail(workspace_id, "target_is_symlink", 409, out_abs.string());
                    deps.reply_json(res, 409, json{
                        {"ok", false},
                        {"error", "path_conflict"},
                        {"message", "target path exists and is a symlink"},
                        {"path", rel_norm}
                    }.dump());
                    return;
                }

                if (!std::filesystem::is_regular_file(st_existing)) {
                    audit_fail(workspace_id, "target_not_regular_file", 409, out_abs.string());
                    deps.reply_json(res, 409, json{
                        {"ok", false},
                        {"error", "path_conflict"},
                        {"message", "target path exists and is not a regular file"},
                        {"path", rel_norm}
                    }.dump());
                    return;
                }

                physical_existing_size = pqnas::file_size_u64_safe(out_abs);

                std::error_code ec_mtime;
                auto ft = std::filesystem::last_write_time(out_abs, ec_mtime);
                if (!ec_mtime) {
                    physical_existing_mtime = file_time_to_epoch_sec(ft);
                }
            }
        }

        if (!overwrite && physical_exists) {
            json existing = json::object();
            existing["size_bytes"] = physical_existing_size;
            existing["mtime_epoch"] = physical_existing_mtime;
            existing["physical_path"] = out_abs.string();

            audit_fail(workspace_id, "file_exists", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "file_exists"},
                {"message", "file already exists"},
                {"path", rel_norm},
                {"existing", existing}
            }.dump());
            return;
        }

        {
            std::error_code ec;
            std::filesystem::create_directories(out_abs.parent_path(), ec);
            if (ec) {
                audit_fail(workspace_id, "mkdir_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to create directories"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
        }

        const std::filesystem::path tmp =
            out_abs.parent_path() /
            (out_abs.filename().string() + ".upload." + random_urlsafe_token(8) + ".tmp");

        std::uint64_t bytes_written = 0;
        bool stream_ok = true;
        std::string stream_err;

        try {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f.good()) {
                throw std::runtime_error("open tmp failed");
            }

            content_reader([&](const char* data, size_t len) {
                if (!stream_ok) return false;
                if (len == 0) return true;

                const std::uint64_t chunk = static_cast<std::uint64_t>(len);
                const std::uint64_t next = bytes_written + chunk;

                if (next < bytes_written) {
                    stream_ok = false;
                    stream_err = "byte_count_overflow";
                    return false;
                }

                if (next > incoming_bytes) {
                    stream_ok = false;
                    stream_err = "content_length_exceeded";
                    return false;
                }

                if (next > transport_max) {
                    stream_ok = false;
                    stream_err = "transport_limit_exceeded";
                    return false;
                }

                f.write(data, static_cast<std::streamsize>(len));
                if (!f.good()) {
                    stream_ok = false;
                    stream_err = "write_tmp_failed";
                    return false;
                }

                bytes_written = next;
                return true;
            });

            f.flush();
            if (!f.good()) {
                throw std::runtime_error("write tmp failed");
            }
            f.close();

            if (!stream_ok) {
                std::error_code ec;
                std::filesystem::remove(tmp, ec);

                const int http = (stream_err == "transport_limit_exceeded") ? 413 : 400;
                audit_fail(workspace_id, stream_err, http);

                deps.reply_json(res, http, json{
                    {"ok", false},
                    {"error", (stream_err == "transport_limit_exceeded") ? "transport_limit_exceeded" : "bad_request"},
                    {"message", stream_err},
                    {"content_length", incoming_bytes},
                    {"bytes_written", bytes_written}
                }.dump());
                return;
            }

            if (bytes_written != incoming_bytes) {
                std::error_code ec;
                std::filesystem::remove(tmp, ec);

                audit_fail(workspace_id, "content_length_mismatch", 400,
                           "Content-Length=" + std::to_string(static_cast<unsigned long long>(incoming_bytes)) +
                           " written=" + std::to_string(static_cast<unsigned long long>(bytes_written)));

                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "Content-Length mismatch"},
                    {"content_length", incoming_bytes},
                    {"bytes_written", bytes_written}
                }.dump());
                return;
            }

            std::error_code rename_ec;
            std::filesystem::rename(tmp, out_abs, rename_ec);
            if (rename_ec) {
                std::error_code rm_ec;
                std::filesystem::remove(tmp, rm_ec);
                throw std::runtime_error(std::string("rename failed: ") + rename_ec.message());
            }

            audit_ok(workspace_id, rel_norm, bytes_written);

            deps.reply_json(res, 200, json{
                {"ok", true},
                {"workspace_id", workspace_id},
                {"path", rel_norm},
                {"bytes", bytes_written},
                {"overwrite", overwrite}
            }.dump());
            return;

        } catch (const std::exception& e) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);

            audit_fail(workspace_id, "write_failed", 500, e.what());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "upload failed"},
                {"detail", e.what()}
            }.dump());
            return;
        }
    });
    // GET /api/v4/workspaces/files/get?workspace_id=...&path=relative/file.bin
    // v1: physical filesystem only, reads file into memory before reply
    srv.Get("/api/v4/workspaces/files/get",
            [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_get_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_get_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace get currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_path;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!std::filesystem::exists(st)) {
            audit_fail(workspace_id, "not_found", 404, rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "file not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail(workspace_id, "symlink_not_supported", 400, rel_norm);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported"}
            }.dump());
            return;
        }

        if (!std::filesystem::is_regular_file(st)) {
            audit_fail(workspace_id, "not_regular_file", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "target path is not a regular file"},
                {"path", rel_norm}
            }.dump());
            return;
        }

        std::ifstream f(abs_path, std::ios::binary);
        if (!f.good()) {
            audit_fail(workspace_id, "open_failed", 500, abs_path.string());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to open file"}
            }.dump());
            return;
        }

        std::string body((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        if (!f.good() && !f.eof()) {
            audit_fail(workspace_id, "read_failed", 500, abs_path.string());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to read file"}
            }.dump());
            return;
        }

        const auto filename = abs_path.filename().string();
        res.set_header("Content-Disposition",
                       "inline; filename=\"" + filename + "\"");
        res.set_content(body, "application/octet-stream");

        audit_ok(workspace_id, rel_norm, static_cast<std::uint64_t>(body.size()));
    });

        // GET/POST /api/v4/workspaces/files/zip?workspace_id=...&path=relative/path&max_bytes=52428800
    // v1: default pool only, in-memory zip response, read-only member access
    auto workspace_files_zip_handler = [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& path_rel = "",
                              std::uint64_t max_bytes = 0) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!path_rel.empty()) f["path"] = pqnas::shorten(path_rel, 200);
            if (max_bytes) f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
            if (!detail.empty()) f["detail"] = pqnas::shorten(detail, 180);
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = pqnas::shorten(it_xff->second, 120);
            deps.audit_emit("workspace.files_zip_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& path_rel,
                            const std::string& type,
                            std::uint64_t max_bytes,
                            std::uint64_t input_bytes,
                            std::uint64_t zip_bytes,
                            std::uint64_t files,
                            std::uint64_t dirs) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = pqnas::shorten(path_rel, 200);
            f["type"] = type;
            f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
            f["input_bytes"] = std::to_string((unsigned long long)input_bytes);
            f["zip_bytes"] = std::to_string((unsigned long long)zip_bytes);
            f["files"] = std::to_string((unsigned long long)files);
            f["dirs"] = std::to_string((unsigned long long)dirs);
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = pqnas::shorten(it_xff->second, 120);
            deps.audit_emit("workspace.files_zip_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace zip currently supports default pool only"}
            }.dump());
            return;
        }

        std::string path_rel;
        if (req.has_param("path")) path_rel = req.get_param_value("path");

        if (path_rel == "." || path_rel == "./" || path_rel == "/") path_rel.clear();

        if (!path_rel.empty() && path_rel[0] == '-') {
            audit_fail(workspace_id, "invalid_path", 400, "leading '-' refused", path_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        std::uint64_t max_bytes = 50ull * 1024 * 1024;
        if (req.has_param("max_bytes")) {
            try {
                long long v = std::stoll(req.get_param_value("max_bytes"));
                if (v > 0) max_bytes = static_cast<std::uint64_t>(v);
            } catch (...) {}
        }
        const std::uint64_t MINB = 1ull * 1024 * 1024;
        const std::uint64_t MAXB = 250ull * 1024 * 1024;
        if (max_bytes < MINB) max_bytes = MINB;
        if (max_bytes > MAXB) max_bytes = MAXB;

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::string rel_norm;
        std::filesystem::path path_abs = ws_root;

        if (!path_rel.empty()) {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(path_rel, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr, path_rel, max_bytes);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }

            std::string perr;
            if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &path_abs, &perr)) {
                audit_fail(workspace_id, "invalid_path", 400, perr, path_rel, max_bytes);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        std::error_code ec;
        auto st = std::filesystem::symlink_status(path_abs, ec);
        if (ec || !std::filesystem::exists(st)) {
            audit_fail(workspace_id, "not_found", 404, "", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "path not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(st)) {
            audit_fail(workspace_id, "symlink_not_supported", 400, "", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported for zip download"}
            }.dump());
            return;
        }

        const bool is_file = std::filesystem::is_regular_file(st);
        const bool is_dir = std::filesystem::is_directory(st);
        const std::string type = is_dir ? "dir" : (is_file ? "file" : "other");

        std::uint64_t files = 0, dirs = 0, input_bytes = 0;

        if (is_file) {
            files = 1;
            input_bytes = pqnas::file_size_u64_safe(path_abs);
        } else if (is_dir) {
            dirs = 1;

            std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;
            ec.clear();
            for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
                 it != std::filesystem::recursive_directory_iterator();
                 it.increment(ec)) {

                if (ec) {
                    audit_fail(workspace_id, "walk_failed", 500, ec.message(), rel_norm.empty() ? "." : rel_norm, max_bytes);
                    deps.reply_json(res, 500, json{
                        {"ok", false},
                        {"error", "server_error"},
                        {"message", "directory walk failed"},
                        {"detail", pqnas::shorten(ec.message(), 180)}
                    }.dump());
                    return;
                }

                std::error_code ec2;
                auto st2 = it->symlink_status(ec2);
                if (ec2) continue;

                if (std::filesystem::is_symlink(st2)) {
                    audit_fail(workspace_id, "symlink_not_supported", 400, "symlink inside tree", rel_norm.empty() ? "." : rel_norm, max_bytes);
                    deps.reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "symlinks inside directory are not supported for zip download"}
                    }.dump());
                    return;
                }

                if (std::filesystem::is_directory(st2)) {
                    dirs += 1;
                    continue;
                }

                if (std::filesystem::is_regular_file(st2)) {
                    files += 1;
                    input_bytes += pqnas::file_size_u64_safe(it->path());
                    if (input_bytes > max_bytes) break;
                    continue;
                }

                files += 1;
            }
        } else {
            audit_fail(workspace_id, "unsupported_type", 400, "", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "unsupported path type for zip download"}
            }.dump());
            return;
        }

        if (input_bytes > max_bytes) {
            audit_fail(workspace_id, "too_large", 413, "input exceeds max_bytes", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "selected content exceeds max_bytes"}
            }.dump());
            return;
        }

        int pipefd[2];
        if (::pipe(pipefd) != 0) {
            audit_fail(workspace_id, "pipe_failed", 500, "pipe()", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        pid_t pid = ::fork();
        if (pid < 0) {
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            audit_fail(workspace_id, "fork_failed", 500, "fork()", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        if (pid == 0) {
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::close(pipefd[0]);
            ::close(pipefd[1]);

            if (::chdir(ws_root.c_str()) != 0) _exit(127);

            const std::string zip_target = rel_norm.empty() ? "." : rel_norm;

            const char* argv[] = {
                "zip",
                "-r",
                "-q",
                "-",
                zip_target.c_str(),
                nullptr
            };
            ::execvp("zip", (char* const*)argv);
            _exit(127);
        }

        ::close(pipefd[1]);

        std::string zip_data;
        zip_data.reserve((size_t)std::min<std::uint64_t>(max_bytes, 4ull * 1024 * 1024));

        const std::uint64_t zip_limit = max_bytes + 8ull * 1024 * 1024;
        std::array<char, 64 * 1024> buf{};

        while (true) {
            ssize_t n = ::read(pipefd[0], buf.data(), (ssize_t)buf.size());
            if (n == 0) break;
            if (n < 0) {
                ::close(pipefd[0]);
                ::kill(pid, SIGKILL);
                audit_fail(workspace_id, "read_failed", 500, "read()", rel_norm.empty() ? "." : rel_norm, max_bytes);
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "zip failed"}
                }.dump());
                return;
            }

            if (zip_data.size() + (size_t)n > (size_t)zip_limit) {
                ::close(pipefd[0]);
                ::kill(pid, SIGKILL);
                audit_fail(workspace_id, "zip_too_large", 413, "zip output exceeds limit", rel_norm.empty() ? "." : rel_norm, max_bytes);
                deps.reply_json(res, 413, json{
                    {"ok", false},
                    {"error", "too_large"},
                    {"message", "zip output too large"}
                }.dump());
                return;
            }

            zip_data.append(buf.data(), (size_t)n);
        }

        ::close(pipefd[0]);

        int child_status = 0;
        ::waitpid(pid, &child_status, 0);
        if (!(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0)) {
            audit_fail(workspace_id, "zip_failed", 500, "zip exit nonzero", rel_norm.empty() ? "." : rel_norm, max_bytes);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        std::string base = rel_norm.empty()
            ? (w.name.empty() ? workspace_id : w.name)
            : std::filesystem::path(rel_norm).filename().string();
        if (base.empty()) base = "workspace";
        std::string fname = base + ".zip";

        audit_ok(
            workspace_id,
            rel_norm.empty() ? "." : rel_norm,
            type,
            max_bytes,
            input_bytes,
            (std::uint64_t)zip_data.size(),
            files,
            dirs);

        res.status = 200;
        res.set_header("Cache-Control", "no-store");
        res.set_header("Content-Type", "application/zip");
        res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
        res.body = std::move(zip_data);
    };

    srv.Get("/api/v4/workspaces/files/zip", workspace_files_zip_handler);
    srv.Post("/api/v4/workspaces/files/zip", workspace_files_zip_handler);

        // POST /api/v4/workspaces/files/zip_sel?workspace_id=...
    // Body JSON: { "paths": ["rel/a.txt", "rel/dir"], "max_bytes": 52428800, "base": "rel/base" }
    srv.Post("/api/v4/workspaces/files/zip_sel",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              std::uint64_t max_bytes = 0,
                              std::uint64_t paths_n = 0) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (max_bytes) f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
            if (paths_n) f["paths_n"] = std::to_string((unsigned long long)paths_n);
            if (!detail.empty()) f["detail"] = pqnas::shorten(detail, 180);
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = pqnas::shorten(it_xff->second, 120);
            deps.audit_emit("workspace.files_zip_sel_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            std::uint64_t max_bytes,
                            std::uint64_t input_bytes,
                            std::uint64_t zip_bytes,
                            std::uint64_t files,
                            std::uint64_t dirs,
                            std::uint64_t paths_n,
                            const std::string& base_rel) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["max_bytes"] = std::to_string((unsigned long long)max_bytes);
            f["input_bytes"] = std::to_string((unsigned long long)input_bytes);
            f["zip_bytes"] = std::to_string((unsigned long long)zip_bytes);
            f["files"] = std::to_string((unsigned long long)files);
            f["dirs"] = std::to_string((unsigned long long)dirs);
            f["paths_n"] = std::to_string((unsigned long long)paths_n);
            if (!base_rel.empty()) f["base"] = pqnas::shorten(base_rel, 200);
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = pqnas::shorten(it_xff->second, 120);
            deps.audit_emit("workspace.files_zip_sel_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace zip_sel currently supports default pool only"}
            }.dump());
            return;
        }

        json body;
        try {
            body = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (const std::exception& e) {
            audit_fail(workspace_id, "json_parse", 400, e.what());
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid json"}
            }.dump());
            return;
        }

        if (!body.is_object() || !body.contains("paths") || !body["paths"].is_array()) {
            audit_fail(workspace_id, "missing_paths", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing paths[]"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::string base_rel;
        if (body.contains("base") && body["base"].is_string()) {
            base_rel = body["base"].get<std::string>();
            if (base_rel == "." || base_rel == "./" || base_rel == "/") base_rel.clear();

            for (char& c : base_rel) if (c == '\\') c = '/';
            while (!base_rel.empty() && base_rel[0] == '/') base_rel.erase(base_rel.begin());

            {
                std::string tmp;
                tmp.reserve(base_rel.size());
                bool prev_slash = false;
                for (char c : base_rel) {
                    if (c == '/') {
                        if (prev_slash) continue;
                        prev_slash = true;
                        tmp.push_back(c);
                    } else {
                        prev_slash = false;
                        tmp.push_back(c);
                    }
                }
                base_rel.swap(tmp);
            }

            while (!base_rel.empty() && base_rel.back() == '/') base_rel.pop_back();

            bool bad = false;
            if (!base_rel.empty() && base_rel[0] == '-') bad = true;
            if (base_rel.find('\n') != std::string::npos || base_rel.find('\r') != std::string::npos) bad = true;

            if (!bad && !base_rel.empty()) {
                size_t start = 0;
                while (start < base_rel.size()) {
                    size_t end = base_rel.find('/', start);
                    if (end == std::string::npos) end = base_rel.size();
                    std::string seg = base_rel.substr(start, end - start);
                    if (seg == "." || seg == ".." || seg.empty()) { bad = true; break; }
                    start = end + 1;
                }
            }

            if (bad) base_rel.clear();
        }

        std::uint64_t max_bytes = 50ull * 1024 * 1024;
        if (body.contains("max_bytes")) {
            try {
                long long v = 0;
                if (body["max_bytes"].is_number_integer()) v = body["max_bytes"].get<long long>();
                else if (body["max_bytes"].is_string()) v = std::stoll(body["max_bytes"].get<std::string>());
                if (v > 0) max_bytes = (std::uint64_t)v;
            } catch (...) {}
        }

        const std::uint64_t MINB = 1ull * 1024 * 1024;
        const std::uint64_t MAXB = 250ull * 1024 * 1024;
        if (max_bytes < MINB) max_bytes = MINB;
        if (max_bytes > MAXB) max_bytes = MAXB;

        std::vector<std::string> paths_in;
        paths_in.reserve(body["paths"].size());

        for (const auto& it : body["paths"]) {
            if (!it.is_string()) continue;

            std::string p = it.get<std::string>();
            if (p == "." || p == "./" || p == "/") p.clear();

            for (char& c : p) if (c == '\\') c = '/';
            while (!p.empty() && p[0] == '/') p.erase(p.begin());

            {
                std::string tmp;
                tmp.reserve(p.size());
                bool prev_slash = false;
                for (char c : p) {
                    if (c == '/') {
                        if (prev_slash) continue;
                        prev_slash = true;
                        tmp.push_back(c);
                    } else {
                        prev_slash = false;
                        tmp.push_back(c);
                    }
                }
                p.swap(tmp);
            }

            while (p.size() > 1 && p.back() == '/') p.pop_back();

            if (!p.empty() && p[0] == '-') continue;

            bool bad = false;
            if (p.find('\n') != std::string::npos || p.find('\r') != std::string::npos) bad = true;

            if (!bad && !p.empty()) {
                size_t start = 0;
                while (start < p.size()) {
                    size_t end = p.find('/', start);
                    if (end == std::string::npos) end = p.size();
                    std::string seg = p.substr(start, end - start);
                    if (seg == "." || seg == ".." || seg.empty()) { bad = true; break; }
                    start = end + 1;
                }
            }

            if (bad) continue;

            paths_in.push_back(std::move(p));
        }

        const std::size_t MAX_PATHS = 500;
        if (paths_in.empty() && body["paths"].size() > 0) {
            paths_in.push_back("");
        }

        if (paths_in.empty()) {
            audit_fail(workspace_id, "no_valid_paths", 400, "", max_bytes, 0);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "no valid paths"}
            }.dump());
            return;
        }

        if (paths_in.size() > MAX_PATHS) {
            audit_fail(workspace_id, "too_many_paths", 413, "paths[] too large", max_bytes, (std::uint64_t)paths_in.size());
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "too many selected paths"}
            }.dump());
            return;
        }

        std::sort(paths_in.begin(), paths_in.end());
        paths_in.erase(std::unique(paths_in.begin(), paths_in.end()), paths_in.end());

        std::vector<std::string> paths_rel;
        paths_rel.reserve(paths_in.size());

        auto is_child_of = [&](const std::string& child, const std::string& parent) -> bool {
            if (parent.empty()) return false;
            if (child.size() <= parent.size()) return false;
            if (child.compare(0, parent.size(), parent) != 0) return false;
            return child[parent.size()] == '/';
        };

        for (const auto& p : paths_in) {
            if (paths_rel.empty()) {
                paths_rel.push_back(p);
                continue;
            }

            bool covered = false;
            for (const auto& sel : paths_rel) {
                if (sel.empty()) {
                    covered = true;
                    break;
                }
                if (!p.empty() && is_child_of(p, sel)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) paths_rel.push_back(p);
        }

        std::filesystem::path base_abs = ws_root;
        if (!base_rel.empty()) {
            std::string berr;
            if (!pqnas::resolve_user_path_strict(ws_root, base_rel, &base_abs, &berr)) {
                audit_fail(workspace_id, "invalid_base", 400, berr, max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid base"}
                }.dump());
                return;
            }

            std::error_code bec;
            auto bst = std::filesystem::symlink_status(base_abs, bec);
            if (bec || !std::filesystem::exists(bst) || !std::filesystem::is_directory(bst) || std::filesystem::is_symlink(bst)) {
                audit_fail(workspace_id, "invalid_base", 400, "base must be an existing directory", max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid base"}
                }.dump());
                return;
            }
        }

        if (!base_rel.empty()) {
            for (const auto& p : paths_rel) {
                if (p.empty()) {
                    audit_fail(workspace_id, "path_outside_base", 400, ".", max_bytes, (std::uint64_t)paths_rel.size());
                    deps.reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "selected path outside base"}
                    }.dump());
                    return;
                }

                if (p == base_rel) continue;
                if (!is_child_of(p, base_rel)) {
                    audit_fail(workspace_id, "path_outside_base", 400, pqnas::shorten(p, 180), max_bytes, (std::uint64_t)paths_rel.size());
                    deps.reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "selected path outside base"}
                    }.dump());
                    return;
                }
            }
        }

        std::uint64_t files = 0, dirs = 0, input_bytes = 0;

        for (const auto& path_rel : paths_rel) {
            std::filesystem::path path_abs = ws_root;

            if (!path_rel.empty()) {
                std::string err;
                if (!pqnas::resolve_user_path_strict(ws_root, path_rel, &path_abs, &err)) {
                    audit_fail(workspace_id, "invalid_path", 400, err, max_bytes, (std::uint64_t)paths_rel.size());
                    deps.reply_json(res, 400, json{
                        {"ok", false},
                        {"error", "bad_request"},
                        {"message", "invalid path"}
                    }.dump());
                    return;
                }
            }

            std::error_code ec;
            auto st = std::filesystem::symlink_status(path_abs, ec);
            if (ec || !std::filesystem::exists(st)) {
                audit_fail(workspace_id, "not_found", 404, path_rel.empty() ? "." : path_rel, max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 404, json{
                    {"ok", false},
                    {"error", "not_found"},
                    {"message", "path not found"}
                }.dump());
                return;
            }

            if (std::filesystem::is_symlink(st)) {
                audit_fail(workspace_id, "symlink_not_supported", 400, "symlink selected", max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "symlinks not supported for zip download"}
                }.dump());
                return;
            }

            const bool is_file = std::filesystem::is_regular_file(st);
            const bool is_dir = std::filesystem::is_directory(st);

            if (is_file) {
                files += 1;
                input_bytes += pqnas::file_size_u64_safe(path_abs);
                if (input_bytes > max_bytes) break;
                continue;
            }

            if (is_dir) {
                dirs += 1;

                std::filesystem::directory_options opts = std::filesystem::directory_options::skip_permission_denied;
                ec.clear();
                for (auto it = std::filesystem::recursive_directory_iterator(path_abs, opts, ec);
                     it != std::filesystem::recursive_directory_iterator();
                     it.increment(ec)) {

                    if (ec) {
                        audit_fail(workspace_id, "walk_failed", 500, ec.message(), max_bytes, (std::uint64_t)paths_rel.size());
                        deps.reply_json(res, 500, json{
                            {"ok", false},
                            {"error", "server_error"},
                            {"message", "directory walk failed"},
                            {"detail", pqnas::shorten(ec.message(), 180)}
                        }.dump());
                        return;
                    }

                    std::error_code ec2;
                    auto st2 = it->symlink_status(ec2);
                    if (ec2) continue;

                    if (std::filesystem::is_symlink(st2)) {
                        audit_fail(workspace_id, "symlink_not_supported", 400, "symlink inside tree", max_bytes, (std::uint64_t)paths_rel.size());
                        deps.reply_json(res, 400, json{
                            {"ok", false},
                            {"error", "bad_request"},
                            {"message", "symlinks inside directory are not supported for zip download"}
                        }.dump());
                        return;
                    }

                    if (std::filesystem::is_directory(st2)) {
                        dirs += 1;
                        continue;
                    }

                    if (std::filesystem::is_regular_file(st2)) {
                        files += 1;
                        input_bytes += pqnas::file_size_u64_safe(it->path());
                        if (input_bytes > max_bytes) break;
                        continue;
                    }

                    files += 1;
                }

                if (input_bytes > max_bytes) break;
                continue;
            }

            audit_fail(workspace_id, "unsupported_type", 400, path_rel, max_bytes, (std::uint64_t)paths_rel.size());
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "unsupported path type for zip download"}
            }.dump());
            return;
        }

        if (input_bytes > max_bytes) {
            audit_fail(workspace_id, "too_large", 413, "input exceeds max_bytes", max_bytes, (std::uint64_t)paths_rel.size());
            deps.reply_json(res, 413, json{
                {"ok", false},
                {"error", "too_large"},
                {"message", "selected content exceeds max_bytes"}
            }.dump());
            return;
        }

        int out_pipe[2] = {-1, -1};
        int in_pipe[2] = {-1, -1};
        if (::pipe(out_pipe) != 0 || ::pipe(in_pipe) != 0) {
            if (out_pipe[0] >= 0) { ::close(out_pipe[0]); ::close(out_pipe[1]); }
            if (in_pipe[0] >= 0) { ::close(in_pipe[0]); ::close(in_pipe[1]); }
            audit_fail(workspace_id, "pipe_failed", 500, "pipe()", max_bytes, (std::uint64_t)paths_rel.size());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        pid_t pid = ::fork();
        if (pid < 0) {
            ::close(out_pipe[0]); ::close(out_pipe[1]);
            ::close(in_pipe[0]); ::close(in_pipe[1]);
            audit_fail(workspace_id, "fork_failed", 500, "fork()", max_bytes, (std::uint64_t)paths_rel.size());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        if (pid == 0) {
            ::dup2(in_pipe[0], STDIN_FILENO);
            ::dup2(out_pipe[1], STDOUT_FILENO);

            ::close(out_pipe[0]);
            ::close(out_pipe[1]);
            ::close(in_pipe[0]);
            ::close(in_pipe[1]);

            if (!base_rel.empty()) {
                std::filesystem::path cd = ws_root / base_rel;
                if (::chdir(cd.c_str()) != 0) _exit(127);
            } else {
                if (::chdir(ws_root.c_str()) != 0) _exit(127);
            }

            const char* argv[] = {
                "zip",
                "-r",
                "-q",
                "-",
                "-@",
                nullptr
            };
            ::execvp("zip", (char* const*)argv);
            _exit(127);
        }

        ::close(out_pipe[1]);
        ::close(in_pipe[0]);

        {
            auto starts_with_dir = [](const std::string& p, const std::string& base) -> bool {
                if (base.empty()) return false;
                if (p.size() <= base.size()) return false;
                if (p.compare(0, base.size(), base) != 0) return false;
                return p[base.size()] == '/';
            };

            bool write_ok = true;
            for (const auto& p0 : paths_rel) {
                std::string p = p0;

                if (!base_rel.empty()) {
                    if (p0 == base_rel) {
                        p = ".";
                    } else if (starts_with_dir(p0, base_rel)) {
                        p = p0.substr(base_rel.size() + 1);
                    } else {
                        write_ok = false;
                    }
                } else if (p.empty()) {
                    p = ".";
                }

                if (!write_ok) break;
                if (p.empty()) p = ".";

                std::string line = p;
                line.push_back('\n');

                const char* data = line.data();
                size_t left = line.size();
                while (left > 0) {
                    ssize_t n = ::write(in_pipe[1], data, (ssize_t)left);
                    if (n <= 0) { write_ok = false; break; }
                    data += n;
                    left -= (size_t)n;
                }
                if (!write_ok) break;
            }

            ::close(in_pipe[1]);

            if (!write_ok) {
                ::close(out_pipe[0]);
                ::kill(pid, SIGKILL);
                audit_fail(workspace_id, "write_failed", 500, "write(stdin)", max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "zip failed"}
                }.dump());
                return;
            }
        }

        std::string zip_data;
        zip_data.reserve((size_t)std::min<std::uint64_t>(max_bytes, 4ull * 1024 * 1024));

        const std::uint64_t zip_limit = max_bytes + 8ull * 1024 * 1024;
        std::array<char, 64 * 1024> buf{};

        while (true) {
            ssize_t n = ::read(out_pipe[0], buf.data(), (ssize_t)buf.size());
            if (n == 0) break;
            if (n < 0) {
                ::close(out_pipe[0]);
                ::kill(pid, SIGKILL);
                audit_fail(workspace_id, "read_failed", 500, "read(zip)", max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "zip failed"}
                }.dump());
                return;
            }

            if (zip_data.size() + (size_t)n > (size_t)zip_limit) {
                ::close(out_pipe[0]);
                ::kill(pid, SIGKILL);
                audit_fail(workspace_id, "zip_too_large", 413, "zip output exceeds limit", max_bytes, (std::uint64_t)paths_rel.size());
                deps.reply_json(res, 413, json{
                    {"ok", false},
                    {"error", "too_large"},
                    {"message", "zip output too large"}
                }.dump());
                return;
            }

            zip_data.append(buf.data(), (size_t)n);
        }

        ::close(out_pipe[0]);

        int child_status = 0;
        ::waitpid(pid, &child_status, 0);
        if (!(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0)) {
            audit_fail(workspace_id, "zip_failed", 500, "zip exit nonzero", max_bytes, (std::uint64_t)paths_rel.size());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "zip failed"}
            }.dump());
            return;
        }

        const std::string fname = "selection.zip";

        audit_ok(
            workspace_id,
            max_bytes,
            input_bytes,
            (std::uint64_t)zip_data.size(),
            files,
            dirs,
            (std::uint64_t)paths_rel.size(),
            base_rel);

        res.status = 200;
        res.set_header("Cache-Control", "no-store");
        res.set_header("Content-Type", "application/zip");
        res.set_header("Content-Disposition", ("attachment; filename=\"" + fname + "\"").c_str());
        res.body = std::move(zip_data);
    });

        // POST /api/v4/workspaces/files/delete?workspace_id=...&path=relative/path
    // v1: physical filesystem only, allows file delete and recursive directory delete
    srv.Post("/api/v4/workspaces/files/delete",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!detail.empty()) f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_delete_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& rel_path,
                            std::uint64_t removed_count) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["path"] = rel_path;
            f["removed_count"] = std::to_string(static_cast<unsigned long long>(removed_count));
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_delete_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string rel_path;
        if (req.has_param("path")) rel_path = req.get_param_value("path");
        if (rel_path.empty()) {
            audit_fail(workspace_id, "missing_path", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing path"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may delete
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace delete currently supports default pool only"}
            }.dump());
            return;
        }

        std::string rel_norm;
        {
            std::string nerr;
            if (!pqnas::normalize_user_rel_path_strict(rel_path, &rel_norm, &nerr)) {
                audit_fail(workspace_id, "invalid_path", 400, nerr);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "invalid path"}
                }.dump());
                return;
            }
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path abs_path;
        std::string perr;
        if (!pqnas::resolve_user_path_strict(ws_root, rel_norm, &abs_path, &perr)) {
            audit_fail(workspace_id, "invalid_path", 400, perr);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid path"}
            }.dump());
            return;
        }

        // refuse deleting workspace root
        if (abs_path.lexically_normal() == ws_root.lexically_normal()) {
            audit_fail(workspace_id, "refuse_delete_root", 409, rel_norm);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "path_conflict"},
                {"message", "refusing to delete workspace root"}
            }.dump());
            return;
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (!exists) {
            audit_fail(workspace_id, "not_found", 404, rel_norm);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "path not found"}
            }.dump());
            return;
        }

        std::uint64_t removed_count = 0;

        const bool is_dir = std::filesystem::is_directory(abs_path, ec);
        if (ec) {
            audit_fail(workspace_id, "stat_failed", 500, ec.message());
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "target stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        if (is_dir) {
            const auto removed = std::filesystem::remove_all(abs_path, ec);
            if (ec) {
                audit_fail(workspace_id, "remove_all_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to delete directory"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
            removed_count = static_cast<std::uint64_t>(removed);
        } else {
            const bool removed = std::filesystem::remove(abs_path, ec);
            if (ec) {
                audit_fail(workspace_id, "remove_failed", 500, ec.message());
                deps.reply_json(res, 500, json{
                    {"ok", false},
                    {"error", "server_error"},
                    {"message", "failed to delete file"},
                    {"detail", ec.message()}
                }.dump());
                return;
            }
            if (!removed) {
                audit_fail(workspace_id, "not_found", 404, rel_norm);
                deps.reply_json(res, 404, json{
                    {"ok", false},
                    {"error", "not_found"},
                    {"message", "path not found"}
                }.dump());
                return;
            }
            removed_count = 1;
        }

        audit_ok(workspace_id, rel_norm, removed_count);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"path", rel_norm},
            {"removed_count", removed_count}
        }.dump());
    });
        // POST /api/v4/workspaces/files/move?workspace_id=...&from=old/path&to=new/path
    // v1: physical filesystem only, same workspace only
    srv.Post("/api/v4/workspaces/files/move",
             [&](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp, actor_role;
        if (!deps.require_user_auth_users_actor ||
            !deps.require_user_auth_users_actor(
                req, res, deps.cookie_key, deps.users, &actor_fp, &actor_role)) {
            return;
        }

        (void)actor_role;
        res.set_header("Cache-Control", "no-store");

        auto audit_fail = [&](const std::string& workspace_id,
                              const std::string& reason,
                              int http,
                              const std::string& detail = "",
                              const std::string& from_rel = "",
                              const std::string& to_rel = "") {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            if (!workspace_id.empty()) f["workspace_id"] = workspace_id;
            f["reason"] = reason;
            f["http"] = std::to_string(http);
            if (!from_rel.empty()) f["from"] = from_rel;
            if (!to_rel.empty())   f["to"]   = to_rel;
            if (!detail.empty())   f["detail"] = detail;
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_move_fail", "fail", f);
        };

        auto audit_ok = [&](const std::string& workspace_id,
                            const std::string& from_rel,
                            const std::string& to_rel,
                            const std::string& type,
                            std::uint64_t bytes) {
            if (!deps.audit_emit) return;
            std::map<std::string, std::string> f;
            f["actor_fp"] = actor_fp;
            f["workspace_id"] = workspace_id;
            f["from"] = from_rel;
            f["to"] = to_rel;
            f["type"] = type;
            if (type == "file") {
                f["bytes"] = std::to_string(static_cast<unsigned long long>(bytes));
            }
            f["ip"] = req.remote_addr.empty() ? "?" : req.remote_addr;
            auto it_cf = req.headers.find("CF-Connecting-IP");
            if (it_cf != req.headers.end()) f["cf_ip"] = it_cf->second;
            auto it_xff = req.headers.find("X-Forwarded-For");
            if (it_xff != req.headers.end()) f["xff"] = it_xff->second;
            deps.audit_emit("workspace.files_move_ok", "ok", f);
        };

        if (!deps.workspaces->load(deps.workspaces_path)) {
            audit_fail("", "workspaces_reload_failed", 500);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "workspaces_reload_failed"},
                {"message", "failed to reload workspaces"}
            }.dump());
            return;
        }

        const std::string workspace_id =
            req.has_param("workspace_id") ? trim_copy_safe(req.get_param_value("workspace_id")) : "";

        if (workspace_id.empty()) {
            audit_fail("", "missing_workspace_id", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing workspace_id"}
            }.dump());
            return;
        }

        std::string from_rel, to_rel;
        if (req.has_param("from")) from_rel = req.get_param_value("from");
        if (req.has_param("to"))   to_rel   = req.get_param_value("to");

        if (from_rel.empty() || to_rel.empty()) {
            audit_fail(workspace_id, "missing_from_or_to", 400);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "missing from or to"}
            }.dump());
            return;
        }

        auto wopt = deps.workspaces->get(workspace_id);
        if (!wopt.has_value()) {
            audit_fail(workspace_id, "workspace_not_found", 404, "", from_rel, to_rel);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "workspace not found"}
            }.dump());
            return;
        }

        const WorkspaceRec& w = *wopt;

        if (w.status != "enabled") {
            audit_fail(workspace_id, "workspace_disabled", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace disabled"}
            }.dump());
            return;
        }

        auto mopt = enabled_member_for_actor(w, actor_fp);
        if (!mopt.has_value()) {
            audit_fail(workspace_id, "workspace_access_denied", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace access denied"}
            }.dump());
            return;
        }

        // v1 policy: only owner/editor may move
        if (!(mopt->role == "owner" || mopt->role == "editor")) {
            audit_fail(workspace_id, "workspace_write_denied", 403, mopt->role, from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "workspace write access denied"}
            }.dump());
            return;
        }

        if (w.storage_state != "allocated") {
            audit_fail(workspace_id, "storage_unallocated", 403, "", from_rel, to_rel);
            deps.reply_json(res, 403, json{
                {"ok", false},
                {"error", "storage_unallocated"},
                {"message", "Workspace storage not allocated"},
                {"workspace_id", workspace_id},
                {"quota_bytes", w.quota_bytes}
            }.dump());
            return;
        }

        // v1 minimal: default pool only
        if (!w.storage_pool_id.empty()) {
            audit_fail(workspace_id, "pool_not_supported_yet", 400, w.storage_pool_id, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "pool_not_supported_yet"},
                {"message", "workspace move currently supports default pool only"}
            }.dump());
            return;
        }

        std::string from_rel_norm, to_rel_norm;
        std::string nerr1, nerr2;

        if (!pqnas::normalize_user_rel_path_strict(from_rel, &from_rel_norm, &nerr1)) {
            audit_fail(workspace_id, "invalid_from_path", 400, nerr1, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid from path"}
            }.dump());
            return;
        }

        if (!pqnas::normalize_user_rel_path_strict(to_rel, &to_rel_norm, &nerr2)) {
            audit_fail(workspace_id, "invalid_to_path", 400, nerr2, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid to path"}
            }.dump());
            return;
        }

        if (from_rel_norm == to_rel_norm) {
            audit_fail(workspace_id, "same_path", 400, "", from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "from and to are the same"}
            }.dump());
            return;
        }

        const std::filesystem::path ws_root =
            workspace_dir_for_default_pool_only(deps.users_path, w);

        std::filesystem::path from_abs, to_abs;
        std::string perr1, perr2;

        if (!pqnas::resolve_user_path_strict(ws_root, from_rel_norm, &from_abs, &perr1)) {
            audit_fail(workspace_id, "invalid_from_path", 400, perr1, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid from path"}
            }.dump());
            return;
        }

        if (!pqnas::resolve_user_path_strict(ws_root, to_rel_norm, &to_abs, &perr2)) {
            audit_fail(workspace_id, "invalid_to_path", 400, perr2, from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid to path"}
            }.dump());
            return;
        }

        {
            std::string found_ancestor;
            if (any_file_ancestor_exists_physical(ws_root, to_rel_norm, &found_ancestor)) {
                audit_fail(workspace_id, "dest_ancestor_is_file", 409, found_ancestor, from_rel, to_rel);
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "destination parent path is an existing file"},
                    {"ancestor", found_ancestor}
                }.dump());
                return;
            }
        }

        std::error_code ec;

        auto from_st = std::filesystem::symlink_status(from_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "source_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "source stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        const bool from_exists = std::filesystem::exists(from_st);
        if (!from_exists) {
            audit_fail(workspace_id, "not_found", 404, "", from_rel, to_rel);
            deps.reply_json(res, 404, json{
                {"ok", false},
                {"error", "not_found"},
                {"message", "source not found"}
            }.dump());
            return;
        }

        if (std::filesystem::is_symlink(from_st)) {
            audit_fail(workspace_id, "source_is_symlink", 400, "", from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "symlinks not supported"}
            }.dump());
            return;
        }

        auto to_st = std::filesystem::symlink_status(to_abs, ec);
        if (ec) {
            audit_fail(workspace_id, "dest_stat_failed", 500, ec.message(), from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "destination stat failed"},
                {"detail", ec.message()}
            }.dump());
            return;
        }

        const bool to_exists = std::filesystem::exists(to_st);
        if (to_exists) {
            if (std::filesystem::is_symlink(to_st)) {
                audit_fail(workspace_id, "dest_is_symlink", 409, "", from_rel, to_rel);
                deps.reply_json(res, 409, json{
                    {"ok", false},
                    {"error", "path_conflict"},
                    {"message", "destination already exists and is a symlink"}
                }.dump());
                return;
            }

            audit_fail(workspace_id, "dest_exists", 409, "", from_rel, to_rel);
            deps.reply_json(res, 409, json{
                {"ok", false},
                {"error", "dest_exists"},
                {"message", "destination already exists"}
            }.dump());
            return;
        }

        const bool src_is_dir = std::filesystem::is_directory(from_st);
        const bool src_is_file = std::filesystem::is_regular_file(from_st);

        if (!src_is_dir && !src_is_file) {
            audit_fail(workspace_id, "unsupported_type", 400, "", from_rel, to_rel);
            deps.reply_json(res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "unsupported source type"}
            }.dump());
            return;
        }

        // Prevent moving directory into itself/subtree
        if (src_is_dir) {
            if (to_rel_norm == from_rel_norm ||
                to_rel_norm.rfind(from_rel_norm + "/", 0) == 0) {
                audit_fail(workspace_id, "dir_into_self", 400, "", from_rel, to_rel);
                deps.reply_json(res, 400, json{
                    {"ok", false},
                    {"error", "bad_request"},
                    {"message", "cannot move a directory into itself"}
                }.dump());
                return;
            }
        }

        auto move_one_path = [&](const std::filesystem::path& src_path,
                                 const std::filesystem::path& dst_path,
                                 bool is_dir,
                                 std::string* move_err) -> bool {
            if (move_err) move_err->clear();

            std::error_code mec;
            std::filesystem::create_directories(dst_path.parent_path(), mec);
            if (mec) {
                if (move_err) *move_err = "mkdir failed: " + mec.message();
                return false;
            }

            mec.clear();
            std::filesystem::rename(src_path, dst_path, mec);
            if (!mec) return true;

            const bool is_exdev =
                (mec == std::make_error_code(std::errc::cross_device_link));

            if (!is_exdev) {
                if (move_err) *move_err = "rename failed: " + mec.message();
                return false;
            }

            std::error_code ec_copy;
            if (is_dir) {
                std::filesystem::copy(src_path, dst_path,
                                      std::filesystem::copy_options::recursive,
                                      ec_copy);
            } else {
                std::filesystem::copy_file(src_path, dst_path,
                                           std::filesystem::copy_options::none,
                                           ec_copy);
            }
            if (ec_copy) {
                if (move_err) *move_err = "copy fallback failed: " + ec_copy.message();
                return false;
            }

            std::error_code ec_rm;
            if (is_dir) std::filesystem::remove_all(src_path, ec_rm);
            else        std::filesystem::remove(src_path, ec_rm);

            if (ec_rm) {
                if (move_err) *move_err = "cleanup failed: " + ec_rm.message();
                return false;
            }

            return true;
        };

        const std::uint64_t bytes =
            src_is_file ? pqnas::file_size_u64_safe(from_abs) : 0;

        std::string move_err;
        if (!move_one_path(from_abs, to_abs, src_is_dir, &move_err)) {
            audit_fail(workspace_id, "move_failed", 500, move_err, from_rel, to_rel);
            deps.reply_json(res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "move failed"},
                {"detail", move_err}
            }.dump());
            return;
        }

        audit_ok(workspace_id, from_rel_norm, to_rel_norm, src_is_dir ? "dir" : "file", bytes);

        deps.reply_json(res, 200, json{
            {"ok", true},
            {"workspace_id", workspace_id},
            {"from", from_rel_norm},
            {"to", to_rel_norm},
            {"type", src_is_dir ? "dir" : "file"},
            {"bytes", bytes}
        }.dump());
    });
    // ---- Files API (user storage) ----

    // GET  /api/v4/workspaces/files/get
    // POST /api/v4/workspaces/files/delete
    
}

}