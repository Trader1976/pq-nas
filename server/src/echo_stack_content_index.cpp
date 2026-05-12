#include "echo_stack_content_index.h"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace pqnas {
namespace {

static std::string col_text(sqlite3_stmt* st, int idx) {
    const unsigned char* p = sqlite3_column_text(st, idx);
    return p ? reinterpret_cast<const char*>(p) : std::string();
}

static void bind_text(sqlite3_stmt* st, int idx, const std::string& s) {
    sqlite3_bind_text(st, idx, s.c_str(), -1, SQLITE_TRANSIENT);
}

static std::string lower_ascii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static std::string trim_copy(const std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;

    std::size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;

    return s.substr(a, b - a);
}

static std::string collapse_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());

    bool ws = false;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!ws) out.push_back(' ');
            ws = true;
        } else {
            out.push_back(c);
            ws = false;
        }
    }

    return trim_copy(out);
}

static std::vector<std::string> tokenize_query(const std::string& q) {
    std::vector<std::string> terms;
    std::string cur;

    for (char c : q) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc)) {
            cur.push_back(static_cast<char>(std::tolower(uc)));
        } else {
            if (!cur.empty()) {
                terms.push_back(cur);
                cur.clear();
            }
        }
    }

    if (!cur.empty()) terms.push_back(cur);

    std::vector<std::string> out;
    for (const auto& t : terms) {
        if (t.empty()) continue;

        bool exists = false;
        for (const auto& x : out) {
            if (x == t) {
                exists = true;
                break;
            }
        }

        if (!exists) out.push_back(t);
        if (out.size() >= 12) break;
    }

    return out;
}

static bool contains_term(const std::string& haystack_lower, const std::string& needle_lower) {
    return !needle_lower.empty() &&
           haystack_lower.find(needle_lower) != std::string::npos;
}

static double score_field(const std::string& field_lower,
                          const std::string& phrase_lower,
                          const std::vector<std::string>& terms,
                          double phrase_points,
                          double term_points) {
    double score = 0.0;

    if (!phrase_lower.empty() && contains_term(field_lower, phrase_lower)) {
        score += phrase_points;
    }

    for (const auto& t : terms) {
        if (contains_term(field_lower, t)) score += term_points;
    }

    return score;
}

static std::string make_snippet(const std::string& body,
                                const std::string& query,
                                const std::vector<std::string>& terms) {
    if (body.empty()) return "";

    const std::string low = lower_ascii(body);
    const std::string phrase = lower_ascii(trim_copy(query));

    std::size_t pos = std::string::npos;

    if (!phrase.empty()) {
        pos = low.find(phrase);
    }

    if (pos == std::string::npos) {
        for (const auto& t : terms) {
            pos = low.find(t);
            if (pos != std::string::npos) break;
        }
    }

    if (pos == std::string::npos) {
        const std::size_t n = std::min<std::size_t>(body.size(), 220);
        return collapse_ws(body.substr(0, n)) + (body.size() > n ? "…" : "");
    }

    const std::size_t radius = 130;
    const std::size_t start = pos > radius ? pos - radius : 0;
    const std::size_t end = std::min<std::size_t>(body.size(), pos + radius);
    std::string snip = collapse_ws(body.substr(start, end - start));

    if (start > 0) snip = "…" + snip;
    if (end < body.size()) snip += "…";

    return snip;
}

} // namespace

EchoStackContentIndex::EchoStackContentIndex(const std::filesystem::path& db_path)
    : db_path_(db_path) {}

EchoStackContentIndex::~EchoStackContentIndex() {
    std::lock_guard<std::mutex> lk(mu_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool EchoStackContentIndex::open(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (db_) return true;

    std::error_code ec;
    std::filesystem::create_directories(db_path_.parent_path(), ec);
    if (ec) {
        if (err) *err = "failed to create content index directory: " + ec.message();
        return false;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path_.string().c_str(), &db) != SQLITE_OK) {
        if (err) *err = db ? sqlite3_errmsg(db) : "sqlite open failed";
        if (db) sqlite3_close(db);
        return false;
    }

    db_ = db;

    char* emsg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &emsg);
    if (emsg) sqlite3_free(emsg);

    emsg = nullptr;
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, &emsg);
    if (emsg) sqlite3_free(emsg);

    return true;
}

bool EchoStackContentIndex::init_schema(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = R"SQL(
CREATE TABLE IF NOT EXISTS echo_stack_content (
    owner_fp      TEXT NOT NULL,
    item_id       TEXT NOT NULL,
    url           TEXT NOT NULL DEFAULT '',
    final_url     TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    tags_text     TEXT NOT NULL DEFAULT '',
    collection    TEXT NOT NULL DEFAULT '',
    source_file   TEXT NOT NULL DEFAULT '',
    body_text     TEXT NOT NULL DEFAULT '',
    indexed_epoch INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(owner_fp, item_id)
);

CREATE INDEX IF NOT EXISTS idx_echo_stack_content_owner_indexed
ON echo_stack_content(owner_fp, indexed_epoch DESC);
)SQL";

    char* emsg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &emsg) != SQLITE_OK) {
        if (err) *err = emsg ? emsg : "content schema init failed";
        if (emsg) sqlite3_free(emsg);
        return false;
    }

    if (emsg) sqlite3_free(emsg);
    return true;
}

bool EchoStackContentIndex::upsert(const EchoStackItemRec& item,
                                   const std::string& body_text,
                                   const std::string& source_file,
                                   std::int64_t indexed_epoch,
                                   std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = R"SQL(
INSERT INTO echo_stack_content (
    owner_fp, item_id, url, final_url, title, description,
    tags_text, collection, source_file, body_text, indexed_epoch
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
)
ON CONFLICT(owner_fp, item_id) DO UPDATE SET
    url=excluded.url,
    final_url=excluded.final_url,
    title=excluded.title,
    description=excluded.description,
    tags_text=excluded.tags_text,
    collection=excluded.collection,
    source_file=excluded.source_file,
    body_text=excluded.body_text,
    indexed_epoch=excluded.indexed_epoch
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, item.owner_fp);
    bind_text(st, 2, item.id);
    bind_text(st, 3, item.url);
    bind_text(st, 4, item.final_url);
    bind_text(st, 5, item.title);
    bind_text(st, 6, item.description);
    bind_text(st, 7, item.tags_text);
    bind_text(st, 8, item.collection);
    bind_text(st, 9, source_file);
    bind_text(st, 10, body_text);
    sqlite3_bind_int64(st, 11, static_cast<sqlite3_int64>(indexed_epoch));

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

bool EchoStackContentIndex::remove_owner_item(const std::string& owner_fp,
                                              const std::string& item_id,
                                              std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = "DELETE FROM echo_stack_content WHERE owner_fp=?1 AND item_id=?2";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, owner_fp);
    bind_text(st, 2, item_id);

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

bool EchoStackContentIndex::clear_owner(const std::string& owner_fp, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!db_) {
        if (err) *err = "db not open";
        return false;
    }

    const char* sql = "DELETE FROM echo_stack_content WHERE owner_fp=?1";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return false;
    }

    bind_text(st, 1, owner_fp);

    const int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (err) *err = sqlite3_errmsg(db_);
        sqlite3_finalize(st);
        return false;
    }

    sqlite3_finalize(st);
    return true;
}

std::vector<EchoStackContentSearchHit> EchoStackContentIndex::search_owner(
    const std::string& owner_fp,
    const std::string& query,
    std::size_t limit,
    std::string* err
) {
    std::lock_guard<std::mutex> lk(mu_);

    std::vector<EchoStackContentSearchHit> out;

    if (!db_) {
        if (err) *err = "db not open";
        return out;
    }

    const std::string q = trim_copy(query);
    const std::vector<std::string> terms = tokenize_query(q);
    if (q.empty() || terms.empty()) return out;

    if (limit < 1) limit = 1;
    if (limit > 100) limit = 100;

    const char* sql = R"SQL(
SELECT item_id, url, final_url, title, description, tags_text,
       collection, source_file, body_text, indexed_epoch
FROM echo_stack_content
WHERE owner_fp=?1
ORDER BY indexed_epoch DESC
LIMIT 1500
)SQL";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
        if (err) *err = sqlite3_errmsg(db_);
        return out;
    }

    bind_text(st, 1, owner_fp);

    const std::string phrase_lower = lower_ascii(q);

    while (true) {
        const int rc = sqlite3_step(st);

        if (rc == SQLITE_ROW) {
            EchoStackContentSearchHit h;
            h.item_id = col_text(st, 0);
            h.url = col_text(st, 1);
            h.final_url = col_text(st, 2);
            h.title = col_text(st, 3);
            h.description = col_text(st, 4);
            h.tags_text = col_text(st, 5);
            h.collection = col_text(st, 6);
            h.source_file = col_text(st, 7);
            const std::string body = col_text(st, 8);
            h.indexed_epoch = static_cast<std::int64_t>(sqlite3_column_int64(st, 9));

            const std::string title_l = lower_ascii(h.title);
            const std::string url_l = lower_ascii(h.url + " " + h.final_url);
            const std::string desc_l = lower_ascii(h.description);
            const std::string tags_l = lower_ascii(h.tags_text + " " + h.collection);
            const std::string body_l = lower_ascii(body);

            double score = 0.0;
            score += score_field(title_l, phrase_lower, terms, 120.0, 35.0);
            score += score_field(url_l, phrase_lower, terms, 35.0, 12.0);
            score += score_field(desc_l, phrase_lower, terms, 40.0, 14.0);
            score += score_field(tags_l, phrase_lower, terms, 45.0, 16.0);
            score += score_field(body_l, phrase_lower, terms, 70.0, 6.0);

            if (score > 0.0) {
                h.score = score;
                h.snippet = make_snippet(body, q, terms);
                out.push_back(std::move(h));
            }

            continue;
        }

        if (rc == SQLITE_DONE) break;

        if (err) *err = sqlite3_errmsg(db_);
        break;
    }

    sqlite3_finalize(st);

    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.indexed_epoch > b.indexed_epoch;
    });

    if (out.size() > limit) out.resize(limit);
    return out;
}

} // namespace pqnas
