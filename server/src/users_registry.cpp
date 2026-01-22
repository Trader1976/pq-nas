#include "users_registry.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>

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

    u.name      = it.value("name", "");
    u.role      = norm_role(it.value("role", "user"));
    u.status    = norm_status(it.value("status", "disabled"));
    u.added_at  = it.value("added_at", "");
    u.last_seen = it.value("last_seen", "");
    u.notes     = it.value("notes", "");

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
      {"fingerprint", u.fingerprint},
      {"name", u.name},
      {"role", u.role},
      {"status", u.status},
      {"added_at", u.added_at},
      {"last_seen", u.last_seen},
      {"notes", u.notes}
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
  u.name = "";
  u.role = "user";
  u.status = "disabled";      // C+D: created but not enabled
  u.added_at = now_iso;
  u.last_seen = "";
  u.notes = "";
  by_fp_[fp_hex] = u;
  return true; // created
}

bool UsersRegistry::upsert(const UserRec& in) {
  std::lock_guard<std::mutex> lk(mu_);
  if (in.fingerprint.empty()) return false;
  UserRec u = in;
  u.role = norm_role(u.role);
  u.status = norm_status(u.status);
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
