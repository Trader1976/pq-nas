#include "users_registry.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <cstdint>

using json = nlohmann::json;

namespace pqnas {

static std::string norm_role(std::string r) {
  if (r == "admin") return "admin";
  return "user";
}

static std::string norm_status(std::string s) {
  if (s == "enabled" || s == "disabled" || s == "revoked") return s;
  return "disabled";
}

static std::string norm_storage_state(std::string s) {
  if (s == "allocated") return "allocated";
  return "unallocated";
}

static std::uint64_t safe_u64_from_json(const json& obj, const char* key, std::uint64_t def) {
  if (!obj.is_object() || !obj.contains(key)) return def;
  const auto& v = obj.at(key);
  // nlohmann can store numbers as integer/unsigned; be defensive.
  try {
    if (v.is_number_unsigned()) return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
      auto x = v.get<std::int64_t>();
      return (x < 0) ? def : static_cast<std::uint64_t>(x);
    }
    if (v.is_number_float()) {
      double x = v.get<double>();
      if (x < 0) return def;
      if (x > static_cast<double>(std::numeric_limits<std::uint64_t>::max())) return def;
      return static_cast<std::uint64_t>(x);
    }
  } catch (...) {
  }
  return def;
}

bool UsersRegistry::load(const std::string& path) {
  std::lock_guard<std::mutex> lk(mu_);
  by_fp_.clear();

  std::ifstream f(path);
  if (!f.good()) return false;

  json j;
  f >> j;
  if (!j.is_object() || !j.contains("users") || !j["users"].is_array()) return false;

  for (auto& it : j["users"]) {
    if (!it.is_object()) continue;

    UserRec u;
    u.fingerprint = it.value("fingerprint", "");
    if (u.fingerprint.empty()) continue;

    // Existing
    u.name      = it.value("name", "");
    u.role      = norm_role(it.value("role", "user"));
    u.status    = norm_status(it.value("status", "disabled"));
    u.added_at  = it.value("added_at", "");
    u.last_seen = it.value("last_seen", "");
    u.notes     = it.value("notes", "");

    // New: profile
    u.group   = it.value("group", "");
    u.email   = it.value("email", "");
    u.address = it.value("address", "");

    // New: storage metadata (defaults for backward compatibility)
    u.storage_state = norm_storage_state(it.value("storage_state", "unallocated"));
    u.quota_bytes   = safe_u64_from_json(it, "quota_bytes", 0);
    u.root_rel      = it.value("root_rel", "");
    u.storage_set_at = it.value("storage_set_at", "");
    u.storage_set_by = it.value("storage_set_by", "");

    by_fp_[u.fingerprint] = u;
  }

  return true;
}

bool UsersRegistry::save(const std::string& path) const {
  std::lock_guard<std::mutex> lk(mu_);

  std::vector<std::string> keys;
  keys.reserve(by_fp_.size());
  for (const auto& kv : by_fp_) keys.push_back(kv.first);
  std::sort(keys.begin(), keys.end());

  json j;
  j["users"] = json::array();
  for (const auto& k : keys) {
    const auto& u = by_fp_.at(k);

    j["users"].push_back(json{
      // Existing
      {"fingerprint", u.fingerprint},
      {"name", u.name},
      {"role", u.role},
      {"status", u.status},
      {"added_at", u.added_at},
      {"last_seen", u.last_seen},
      {"notes", u.notes},

      // New: profile
      {"group", u.group},
      {"email", u.email},
      {"address", u.address},

      // New: storage metadata
      {"storage_state", norm_storage_state(u.storage_state)},
      {"quota_bytes", u.quota_bytes},
      {"root_rel", u.root_rel},
      {"storage_set_at", u.storage_set_at},
      {"storage_set_by", u.storage_set_by}
    });
  }

  // Atomic-ish write: write temp then rename
  std::filesystem::path p(path);
  std::filesystem::create_directories(p.parent_path());
  auto tmp = p;
  tmp += ".tmp";

  {
    std::ofstream out(tmp.string(), std::ios::trunc);
    if (!out.good()) return false;
    out << j.dump(2) << "\n";
    out.flush();
  }

  std::error_code ec;
  std::filesystem::rename(tmp, p, ec);
  if (ec) {
    // fallback: try remove + rename
    std::filesystem::remove(p, ec);
    ec.clear();
    std::filesystem::rename(tmp, p, ec);
    if (ec) return false;
  }

  return true;
}

bool UsersRegistry::exists(const std::string& fp_hex) const {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_.find(fp_hex) != by_fp_.end();
}

std::optional<UserRec> UsersRegistry::get(const std::string& fp_hex) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return std::nullopt;
  return it->second;
}

bool UsersRegistry::is_enabled_user(const std::string& fp_hex) const {
  auto u = get(fp_hex);
  return u.has_value() && u->status == "enabled";
}

bool UsersRegistry::is_admin_enabled(const std::string& fp_hex) const {
  auto u = get(fp_hex);
  return u.has_value() && u->status == "enabled" && u->role == "admin";
}

std::string UsersRegistry::role_of(const std::string& fp_hex) const {
  auto u = get(fp_hex);
  return u.has_value() ? u->role : "";
}

bool UsersRegistry::ensure_present_disabled_user(const std::string& fp_hex, const std::string& now_iso) {
  std::lock_guard<std::mutex> lk(mu_);
  if (by_fp_.find(fp_hex) != by_fp_.end()) return false;

  UserRec u;
  u.fingerprint = fp_hex;

  // Existing defaults
  u.name = "";
  u.role = "user";
  u.status = "disabled";      // created but not enabled
  u.added_at = now_iso;
  u.last_seen = "";
  u.notes = "";

  // New defaults
  u.group = "";
  u.email = "";
  u.address = "";

  u.storage_state = "unallocated";
  u.quota_bytes = 0;
  u.root_rel = "";
  u.storage_set_at = "";
  u.storage_set_by = "";

  by_fp_[fp_hex] = u;
  return true; // created
}

bool UsersRegistry::upsert(const UserRec& in) {
  std::lock_guard<std::mutex> lk(mu_);
  if (in.fingerprint.empty()) return false;

  UserRec u = in;

  // Normalize
  u.role = norm_role(u.role);
  u.status = norm_status(u.status);
  u.storage_state = norm_storage_state(u.storage_state);

  by_fp_[u.fingerprint] = u;
  return true;
}

bool UsersRegistry::set_status(const std::string& fp_hex, const std::string& status) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.status = norm_status(status);
  return true;
}

bool UsersRegistry::set_role(const std::string& fp_hex, const std::string& role) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.role = norm_role(role);
  return true;
}

bool UsersRegistry::set_name_notes(const std::string& fp_hex, const std::string& name, const std::string& notes) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.name = name;
  it->second.notes = notes;
  return true;
}

bool UsersRegistry::touch_last_seen(const std::string& fp_hex, const std::string& now_iso) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.last_seen = now_iso;
  return true;
}

bool UsersRegistry::erase(const std::string& fp_hex) {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_.erase(fp_hex) > 0;
}

std::unordered_map<std::string, UserRec> UsersRegistry::snapshot() const {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_;
}

} // namespace pqnas
