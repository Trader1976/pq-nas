#pragma once
#include <string>
#include <map>
#include <mutex>

namespace pqnas {

    struct AuditEvent {
        std::string ts_utc;                  // ISO-8601 UTC with milliseconds + "Z"
        std::string event;                   // e.g. "v4.session_issued"
        std::string outcome;                 // "ok" | "fail" | "deny"
        std::map<std::string, std::string> f; // extra fields (string-only for simplicity)
    };

    // Hash-chained JSONL logger:
    // Each line includes: prev_hash + line_hash (sha256 over: prev_hash + json_line_without_line_hash)
    class AuditLog {
    public:
        AuditLog(std::string jsonl_path, std::string state_path);

        // Thread-safe append
        void append(const AuditEvent& e);

        // convenience
        static std::string now_iso_utc();

        // Sanitizers / helpers
        static std::string sha256_hex(const std::string& s);

    private:
        std::string jsonl_path_;
        std::string state_path_;
        std::mutex mu_;

        std::string load_prev_hash_();        // 64 hex or "0"*64
        void store_prev_hash_(const std::string& h);

        static std::string json_escape_(const std::string& s);
        static std::string build_json_(const AuditEvent& e,
                                       const std::string& prev_hash,
                                       std::string* out_content_hash_hex);
    };

} // namespace pqnas
