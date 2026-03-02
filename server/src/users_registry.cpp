#include "users_registry.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <unistd.h>

using json = nlohmann::json;

namespace pqnas {

/*
================================================================================
Users Registry — Architectural Overview
================================================================================

Purpose
-------
UsersRegistry is PQ-NAS's in-process authoritative source of user metadata,
backed by a JSON file on disk.

It stores and serves:
  - Identity: fingerprint (primary key)
  - Authorization: role (admin/user) and status (enabled/disabled/revoked)
  - Profile metadata: name, group, email, address, avatar_url, notes
  - Storage metadata: storage_state, quota_bytes, root_rel, and audit fields
  - Activity: added_at and last_seen (ISO8601 strings in PQ-NAS conventions)

This module is designed to be:
  - Simple: JSON file with a stable schema.
  - Backward-compatible: missing fields default to safe values.
  - Thread-safe: internal state is guarded by a mutex.

Data model
----------
Primary key:
  - fingerprint (fp_hex string)

Core fields:
  - role: "admin" | "user"
  - status: "enabled" | "disabled" | "revoked"
  - storage_state: "allocated" | "unallocated"

Storage metadata (important for quotas + File Manager):
  - quota_bytes: uint64 (0 is treated as "deny positive uploads" by quota code)
  - root_rel: per-user relative root directory for data
  - storage_set_at / storage_set_by: audit trace for allocations

Threading model
---------------
  - by_fp_ is protected by mu_
  - All public methods either take the lock directly or call a method that does.
  - snapshot() provides a full copy for callers that need stable iteration
    without holding the lock.

Persistence model
-----------------
  - load(path): reads the JSON file and replaces in-memory state.
  - save(path): writes a complete snapshot to a temp file in the same directory,
    then renames tmp -> target for atomic replace.

Durability notes:
  - save() uses flush(), but does not fsync() file or parent directory.
    If you need power-loss durability, consider fsync(tmp_fd) + fsync(dir_fd).

Security / correctness notes
----------------------------
  - Normalization functions (norm_role/norm_status/norm_storage_state) provide
    a schema firewall: only known values are accepted; unknown values map to
    conservative defaults (e.g., disabled/unallocated).
  - safe_u64_from_json is defensive against signed/float encodings.

Potential issues to be aware of
-------------------------------
  - load() currently returns false if file is missing/unreadable.
    Some registry designs treat missing as "empty registry" and return true.
    Ensure higher-level code handles this according to your intended UX.
  - save(): "address" is currently written twice in the JSON initializer.
    This is likely a copy/paste mistake; it can confuse readers and may mask bugs.
================================================================================
*/


//------------------------------------------------------------------------------
// Normalization helpers (schema firewall)
//------------------------------------------------------------------------------

/*
norm_role()
  - Enforces a two-role model: "admin" or "user".
  - Unknown input collapses to "user" (least privilege).
*/
static std::string norm_role(std::string r) {
  if (r == "admin") return "admin";
  return "user";
}

/*
norm_status()
  - Enforces allowed account statuses.
  - Unknown input collapses to "disabled" (fail-closed).
  - This helps prevent unexpected JSON edits from granting access.
*/
static std::string norm_status(std::string s) {
  if (s == "enabled" || s == "disabled" || s == "revoked") return s;
  return "disabled";
}

/*
norm_storage_state()
  - Enforces allowed storage states.
  - Unknown input collapses to "unallocated" (fail-closed).
*/
static std::string norm_storage_state(std::string s) {
  if (s == "allocated") return "allocated";
  return "unallocated";
}


//------------------------------------------------------------------------------
// JSON decoding helper (defensive numeric parsing)
//------------------------------------------------------------------------------

/*
safe_u64_from_json(obj, key, def)
  - Reads an integer-like field from JSON and returns it as uint64_t.
  - Accepts:
      * unsigned integers
      * signed integers (>=0)
      * floats (>=0 and within range)
  - Anything invalid returns def.
  - This preserves backward compatibility and tolerates accidental type drift.
*/
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


//------------------------------------------------------------------------------
// Persistence: load()
//------------------------------------------------------------------------------

/*
UsersRegistry::load(path)
  - Replaces current in-memory registry with contents of the JSON file.
  - This is a full snapshot load (not incremental).

Error handling strategy:
  - Returns false if:
      * file cannot be opened
      * JSON is malformed / schema mismatch
  - Skips malformed user entries, but keeps loading others.

Backward compatibility:
  - New fields are read with defaults so older files remain valid.
  - Normalization is applied so unexpected values do not escalate privilege.

NOTE:
  - This function currently returns false if the file is missing.
    If you want "missing file = empty registry" semantics (like ShareRegistry),
    adjust this behavior and ensure callers match the intended UX.
*/
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
    u.avatar_url = it.value("avatar_url", "");

    // New: storage metadata (defaults for backward compatibility)
    u.storage_state  = norm_storage_state(it.value("storage_state", "unallocated"));
    u.quota_bytes    = safe_u64_from_json(it, "quota_bytes", 0);
    u.root_rel       = it.value("root_rel", "");
    u.storage_set_at = it.value("storage_set_at", "");
    u.storage_set_by = it.value("storage_set_by", "");

    by_fp_[u.fingerprint] = u;
  }

  return true;
}


//------------------------------------------------------------------------------
// Persistence: save() with atomic replace
//------------------------------------------------------------------------------

/*
UsersRegistry::save(path)
  - Writes a normalized snapshot of all users to disk.
  - Sorting keys produces stable output for diffing and reproducibility.
  - Uses atomic replace:
      write tmp in same directory -> rename tmp -> target

Caveats:
  - The JSON initializer currently includes {"address", u.address} twice.
    That is likely unintentional. Nlohmann JSON will keep the last duplicate key,
    but it’s confusing and should be removed.
*/
bool UsersRegistry::save(const std::string& path) const {
  std::lock_guard<std::mutex> lk(mu_);

  // Stable ordering makes the registry file deterministic and diff-friendly.
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
      {"avatar_url", u.avatar_url},

      // New: storage metadata
      {"storage_state", norm_storage_state(u.storage_state)},
      {"quota_bytes", u.quota_bytes},
      {"root_rel", u.root_rel},
      {"storage_set_at", u.storage_set_at},
      {"storage_set_by", u.storage_set_by}
    });
  }

  std::filesystem::path p(path);
  std::error_code ec;

  // Ensure parent dir exists
  std::filesystem::create_directories(p.parent_path(), ec);
  if (ec) return false;

  // Unique temp file in the same directory (atomic rename guarantee)
  std::filesystem::path tmp = p;
  tmp += ".tmp.";
  tmp += std::to_string(::getpid());
  tmp += ".";
  tmp += std::to_string(static_cast<long long>(std::time(nullptr)));

  // Write temp
  {
    std::ofstream out(tmp.string(), std::ios::trunc);
    if (!out.good()) return false;
    out << j.dump(2) << "\n";
    out.flush();
    if (!out.good()) {
      std::filesystem::remove(tmp, ec);
      return false;
    }
  }

  // Atomic replace: rename tmp -> target
  ec.clear();
  std::filesystem::rename(tmp, p, ec);
  if (ec) {
    // Cleanup tmp on failure
    std::filesystem::remove(tmp, ec);
    return false;
  }

  return true;
}


//------------------------------------------------------------------------------
// Read helpers (thread-safe queries)
//------------------------------------------------------------------------------

/*
exists()
  - O(1) lookup by fingerprint.
*/
bool UsersRegistry::exists(const std::string& fp_hex) const {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_.find(fp_hex) != by_fp_.end();
}

/*
get()
  - Returns a copy of the user record if present.
  - Copy is intentional: caller gets a stable snapshot without holding the lock.
*/
std::optional<UserRec> UsersRegistry::get(const std::string& fp_hex) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return std::nullopt;
  return it->second;
}

/*
Convenience authorization checks
  - These are intentionally strict: enabled must be set.
*/
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


//------------------------------------------------------------------------------
// Mutation helpers
//------------------------------------------------------------------------------

/*
ensure_present_disabled_user(fp, now_iso)
  - Used by "Approvals" onboarding flows:
      * when a fingerprint is first seen, create a disabled user record
      * admin later approves (enables) it
  - Returns true if created, false if already present.
*/
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
  u.avatar_url = "";

  // Storage defaults: user cannot use File Manager until allocated.
  u.storage_state = "unallocated";
  u.quota_bytes = 0;
  u.root_rel = "";
  u.storage_set_at = "";
  u.storage_set_by = "";

  by_fp_[fp_hex] = u;
  return true; // created
}

/*
upsert()
  - Inserts or replaces a user record.
  - Applies normalization to prevent invalid values from entering the registry.
  - Caller must provide fingerprint.
*/
bool UsersRegistry::upsert(const UserRec& in) {
  std::lock_guard<std::mutex> lk(mu_);
  if (in.fingerprint.empty()) return false;

  UserRec u = in;

  // Normalize (schema firewall)
  u.role = norm_role(u.role);
  u.status = norm_status(u.status);
  u.storage_state = norm_storage_state(u.storage_state);

  by_fp_[u.fingerprint] = u;
  return true;
}

/*
set_status(), set_role()
  - Small mutation helpers used by admin operations.
  - Values are normalized to avoid invalid states.
*/
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

/*
set_name_notes()
  - Updates UI-facing metadata fields.
  - Does not validate content here; caller should enforce length/charset policies
    if needed.
*/
bool UsersRegistry::set_name_notes(const std::string& fp_hex, const std::string& name, const std::string& notes) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.name = name;
  it->second.notes = notes;
  return true;
}

/*
touch_last_seen()
  - Updates last_seen timestamp for activity tracking / UI.
  - Caller should pass an ISO8601 string consistent with the rest of PQ-NAS.
*/
bool UsersRegistry::touch_last_seen(const std::string& fp_hex, const std::string& now_iso) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_fp_.find(fp_hex);
  if (it == by_fp_.end()) return false;
  it->second.last_seen = now_iso;
  return true;
}

/*
erase()
  - Removes a user record entirely.
  - Higher layers should ensure policy: do not allow deleting the last admin, etc.
*/
bool UsersRegistry::erase(const std::string& fp_hex) {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_.erase(fp_hex) > 0;
}

/*
snapshot()
  - Returns a full copy of the internal map.
  - Useful for pages that need to list/iterate users without holding mu_.
*/
std::unordered_map<std::string, UserRec> UsersRegistry::snapshot() const {
  std::lock_guard<std::mutex> lk(mu_);
  return by_fp_;
}

} // namespace pqnas