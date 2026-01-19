#include "audit_log.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
#include <deque>


#include <openssl/sha.h>

namespace pqnas {

static std::string to_hex(const unsigned char* p, size_t n) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.resize(n * 2);
  for (size_t i = 0; i < n; i++) {
    out[i*2+0] = kHex[(p[i] >> 4) & 0xF];
    out[i*2+1] = kHex[(p[i] >> 0) & 0xF];
  }
  return out;
}

AuditLog::AuditLog(std::string jsonl_path, std::string state_path)
  : jsonl_path_(std::move(jsonl_path)), state_path_(std::move(state_path)) {}

std::string AuditLog::now_iso_utc() {
  using namespace std::chrono;
  auto now = system_clock::now();
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

  std::time_t tt = system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
      << "." << std::setw(3) << std::setfill('0') << ms.count()
      << "Z";
  return oss.str();
}

std::string AuditLog::sha256_hex(const std::string& s) {
  unsigned char h[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), h);
  return to_hex(h, sizeof(h));
}

std::string AuditLog::load_prev_hash_() {
  std::ifstream f(state_path_);
  if (!f.good()) return std::string(64, '0');
  std::string line;
  std::getline(f, line);
  if (line.size() != 64) return std::string(64, '0');
  return line;
}

void AuditLog::store_prev_hash_(const std::string& h) {
  std::ofstream f(state_path_, std::ios::trunc);
  f << h << "\n";
}

std::string AuditLog::json_escape_(const std::string& s) {
  std::ostringstream o;
  for (char c : s) {
    switch (c) {
      case '\"': o << "\\\""; break;
      case '\\': o << "\\\\"; break;
      case '\b': o << "\\b"; break;
      case '\f': o << "\\f"; break;
      case '\n': o << "\\n"; break;
      case '\r': o << "\\r"; break;
      case '\t': o << "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << (int)(unsigned char)c << std::dec;
        } else {
          o << c;
        }
    }
  }
  return o.str();
}

// Build JSON without line_hash first; compute content_hash = sha256(prev_hash + json_without_line_hash)
// then add line_hash field.
std::string AuditLog::build_json_(const AuditEvent& e,
                                 const std::string& prev_hash,
                                 std::string* out_content_hash_hex) {
  std::ostringstream js;
  js << "{"
     << "\"ts\":\"" << json_escape_(e.ts_utc) << "\""
     << ",\"event\":\"" << json_escape_(e.event) << "\""
     << ",\"outcome\":\"" << json_escape_(e.outcome) << "\""
     << ",\"prev_hash\":\"" << prev_hash << "\"";

  if (!e.f.empty()) {
    js << ",\"f\":{";
    bool first = true;
    for (const auto& kv : e.f) {
      if (!first) js << ",";
      first = false;
      js << "\"" << json_escape_(kv.first) << "\":"
         << "\"" << json_escape_(kv.second) << "\"";
    }
    js << "}";
  }

  js << "}";

  const std::string json_without_line_hash = js.str();
  const std::string content = prev_hash + json_without_line_hash;
  *out_content_hash_hex = sha256_hex(content);

  std::ostringstream js2;
  // insert line_hash at end (simple approach: rebuild with line_hash)
  // (No need to keep exact field ordering stable beyond internal consistency.)
  js2 << "{"
      << "\"ts\":\"" << json_escape_(e.ts_utc) << "\""
      << ",\"event\":\"" << json_escape_(e.event) << "\""
      << ",\"outcome\":\"" << json_escape_(e.outcome) << "\""
      << ",\"prev_hash\":\"" << prev_hash << "\""
      << ",\"line_hash\":\"" << *out_content_hash_hex << "\"";

  if (!e.f.empty()) {
    js2 << ",\"f\":{";
    bool first = true;
    for (const auto& kv : e.f) {
      if (!first) js2 << ",";
      first = false;
      js2 << "\"" << json_escape_(kv.first) << "\":"
          << "\"" << json_escape_(kv.second) << "\"";
    }
    js2 << "}";
  }

  js2 << "}";
  return js2.str();
}

void AuditLog::append(const AuditEvent& e_in) {
  std::lock_guard<std::mutex> lk(mu_);

  AuditEvent e = e_in;
  if (e.ts_utc.empty()) e.ts_utc = now_iso_utc();

  const std::string prev = load_prev_hash_();

  std::string content_hash;
  const std::string line = build_json_(e, prev, &content_hash);

  // Append JSONL line
  std::ofstream out(jsonl_path_, std::ios::app);
  out << line << "\n";
  out.flush();

  // Update state
  store_prev_hash_(content_hash);
}

} // namespace pqnas
