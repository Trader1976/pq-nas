#include "echo_stack_search_routes.h"

#include "echo_stack_content_index.h"
#include "echo_stack_text_extract.h"

#include <nlohmann/json.hpp>

#include <ctime>
#include <filesystem>
#include <map>
#include <string>

using json = nlohmann::json;

namespace pqnas {
namespace {

static void reply_json_local(const EchoStackRoutesDeps& deps,
                             httplib::Response& res,
                             int status,
                             const json& body) {
    if (deps.reply_json) {
        deps.reply_json(res, status, body.dump());
        return;
    }

    res.status = status;
    res.set_content(body.dump(), "application/json");
}

static json parse_body_json_local(const httplib::Request& req) {
    try {
        return json::parse(req.body);
    } catch (...) {
        return json();
    }
}

static bool require_actor_local(const EchoStackRoutesDeps& deps,
                                const httplib::Request& req,
                                httplib::Response& res,
                                std::string* fp,
                                std::string* role) {
    if (!deps.require_user_auth_users_actor ||
        !deps.users ||
        !deps.cookie_key ||
        !deps.echo_index) {
        reply_json_local(deps, res, 500, {
            {"ok", false},
            {"error", "server_error"},
            {"message", "Echo Stack Deep Search dependencies not configured"}
        });
        return false;
    }

    return deps.require_user_auth_users_actor(
        req, res, deps.cookie_key, deps.users, fp, role
    );
}

static std::size_t parse_limit_local(const httplib::Request& req,
                                     std::size_t defv,
                                     std::size_t maxv) {
    std::size_t v = defv;

    if (req.has_param("limit")) {
        try {
            const long long n = std::stoll(req.get_param_value("limit"));
            if (n > 0) v = static_cast<std::size_t>(n);
        } catch (...) {
        }
    }

    if (v < 1) v = 1;
    if (v > maxv) v = maxv;
    return v;
}

static std::filesystem::path user_root_for_fp_local(const EchoStackRoutesDeps& deps,
                                                   const std::string& fp) {
    if (!deps.user_dir_for_fp || !deps.users) return {};
    return deps.user_dir_for_fp(*deps.users, fp);
}

static std::filesystem::path content_db_path_local(const std::filesystem::path& user_root) {
    return user_root / ".pqnas_echostack" / "content_index.sqlite";
}

static bool archive_dir_for_item_local(const std::filesystem::path& user_root,
                                       const EchoStackItemRec& item,
                                       std::filesystem::path* out,
                                       std::string* err) {
    if (out) *out = std::filesystem::path();

    if (item.archive_rel_dir.empty()) {
        if (err) *err = "item_has_no_archive";
        return false;
    }

    std::filesystem::path rel(item.archive_rel_dir);
    if (rel.is_absolute()) {
        if (err) *err = "bad_archive_path";
        return false;
    }

    const auto root = user_root.lexically_normal();
    const auto p = (root / rel).lexically_normal();

    const std::string root_s = root.string();
    const std::string p_s = p.string();

    if (p_s != root_s &&
        !(p_s.size() > root_s.size() &&
          p_s.compare(0, root_s.size(), root_s) == 0 &&
          (root_s.empty() || root_s.back() == '/' || p_s[root_s.size()] == '/'))) {
        if (err) *err = "archive_path_escape";
        return false;
    }

    if (out) *out = p;
    return true;
}

static std::int64_t now_epoch_local(const EchoStackRoutesDeps& deps) {
    if (deps.now_epoch) return deps.now_epoch();
    return static_cast<std::int64_t>(std::time(nullptr));
}

static bool open_content_index_local(const EchoStackRoutesDeps& deps,
                                     const std::filesystem::path& user_root,
                                     EchoStackContentIndex* index,
                                     std::string* err) {
    if (!index) {
        if (err) *err = "bad_index";
        return false;
    }

    if (!index->open(err)) return false;
    if (!index->init_schema(err)) return false;

    (void)deps;
    (void)user_root;
    return true;
}

static bool reindex_item_local(const EchoStackRoutesDeps& deps,
                               const std::string& owner_fp,
                               const std::string& item_id,
                               std::string* indexed_source,
                               std::string* err) {
    if (indexed_source) indexed_source->clear();

    const auto user_root = user_root_for_fp_local(deps, owner_fp);
    if (user_root.empty()) {
        if (err) *err = "bad_user_root";
        return false;
    }

    std::string get_err;
    auto item_opt = deps.echo_index->get_owner_item(owner_fp, item_id, &get_err);
    if (!item_opt.has_value()) {
        if (err) *err = get_err.empty() ? "not_found" : get_err;
        return false;
    }

    EchoStackItemRec item = *item_opt;

    if (item.archive_status != "archived") {
        if (err) *err = "not_archived";
        return false;
    }

    std::filesystem::path archive_dir;
    if (!archive_dir_for_item_local(user_root, item, &archive_dir, err)) {
        return false;
    }

    auto extracted = extract_echo_stack_archive_text(archive_dir);
    if (!extracted.ok) {
        if (err) *err = extracted.error.empty() ? "extract_failed" : extracted.error;
        return false;
    }

    if (item.title.empty() && !extracted.title.empty()) {
        item.title = extracted.title;
    }

    EchoStackContentIndex content_index(content_db_path_local(user_root));
    if (!open_content_index_local(deps, user_root, &content_index, err)) {
        return false;
    }

    if (!content_index.upsert(
            item,
            extracted.text,
            extracted.source_file,
            now_epoch_local(deps),
            err
        )) {
        return false;
    }

    if (indexed_source) *indexed_source = extracted.source_file;
    return true;
}

} // namespace


bool echo_stack_index_archived_item_for_search(const EchoStackRoutesDeps& deps,
                                               const std::string& owner_fp,
                                               const std::string& item_id,
                                               std::string* indexed_source,
                                               std::string* err) {
    return reindex_item_local(deps, owner_fp, item_id, indexed_source, err);
}

void register_echo_stack_search_routes(httplib::Server& srv,
                                       const EchoStackRoutesDeps& deps) {
    srv.Get("/api/v4/echostack/search/fulltext",
            [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp;
        std::string role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const std::string q = req.has_param("q") ? req.get_param_value("q") : "";
        const std::size_t limit = parse_limit_local(req, 25, 100);

        const auto user_root = user_root_for_fp_local(deps, fp);
        if (user_root.empty()) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "server_error"},
                {"message", "Could not resolve user storage root"}
            });
            return;
        }

        EchoStackContentIndex content_index(content_db_path_local(user_root));

        std::string err;
        if (!open_content_index_local(deps, user_root, &content_index, &err)) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "index_open_failed"},
                {"message", err}
            });
            return;
        }

        auto hits = content_index.search_owner(fp, q, limit, &err);
        if (!err.empty()) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "search_failed"},
                {"message", err}
            });
            return;
        }

        json arr = json::array();

        for (const auto& h : hits) {
            std::string item_err;
            auto live_item = deps.echo_index->get_owner_item(fp, h.item_id, &item_err);
            if (!live_item.has_value()) {
                continue;
            }

            arr.push_back({
                {"id", h.item_id},
                {"url", live_item->url.empty() ? h.url : live_item->url},
                {"final_url", live_item->final_url.empty() ? h.final_url : live_item->final_url},
                {"title", live_item->title.empty() ? h.title : live_item->title},
                {"description", live_item->description.empty() ? h.description : live_item->description},
                {"tags_text", live_item->tags_text.empty() ? h.tags_text : live_item->tags_text},
                {"collection", live_item->collection.empty() ? h.collection : live_item->collection},
                {"source_file", h.source_file},
                {"snippet", h.snippet},
                {"score", h.score},
                {"indexed_epoch", h.indexed_epoch},
                {"archive_status", live_item->archive_status}
            });
        }

        reply_json_local(deps, res, 200, {
            {"ok", true},
            {"query", q},
            {"results", arr}
        });
    });

    srv.Post("/api/v4/echostack/search/reindex-item",
             [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp;
        std::string role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const json body = parse_body_json_local(req);
        const std::string id =
            body.contains("id") && body["id"].is_string()
                ? body["id"].get<std::string>()
                : "";

        if (id.empty()) {
            reply_json_local(deps, res, 400, {
                {"ok", false},
                {"error", "bad_request"},
                {"message", "Missing item id"}
            });
            return;
        }

        std::string source;
        std::string err;

        if (!reindex_item_local(deps, fp, id, &source, &err)) {
            reply_json_local(deps, res, 400, {
                {"ok", false},
                {"error", "reindex_failed"},
                {"message", err.empty() ? "Could not reindex item" : err}
            });
            return;
        }

        reply_json_local(deps, res, 200, {
            {"ok", true},
            {"id", id},
            {"source_file", source}
        });
    });

    srv.Post("/api/v4/echostack/search/reindex-all",
             [deps](const httplib::Request& req, httplib::Response& res) {
        std::string fp;
        std::string role;
        if (!require_actor_local(deps, req, res, &fp, &role)) return;

        const auto user_root = user_root_for_fp_local(deps, fp);
        if (user_root.empty()) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "server_error"},
                {"message", "Could not resolve user storage root"}
            });
            return;
        }

        EchoStackContentIndex content_index(content_db_path_local(user_root));

        std::string err;
        if (!open_content_index_local(deps, user_root, &content_index, &err)) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "index_open_failed"},
                {"message", err}
            });
            return;
        }

        if (!content_index.clear_owner(fp, &err)) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "clear_failed"},
                {"message", err}
            });
            return;
        }

        std::string list_err;
        auto items = deps.echo_index->list_owner(fp, "", 500, &list_err);

        if (!list_err.empty()) {
            reply_json_local(deps, res, 500, {
                {"ok", false},
                {"error", "list_failed"},
                {"message", list_err}
            });
            return;
        }

        int indexed = 0;
        int skipped = 0;
        int failed = 0;

        for (const auto& item : items) {
            if (item.archive_status != "archived" || item.archive_rel_dir.empty()) {
                ++skipped;
                continue;
            }

            std::string source;
            std::string one_err;
            if (reindex_item_local(deps, fp, item.id, &source, &one_err)) {
                ++indexed;
            } else {
                ++failed;
            }
        }

        reply_json_local(deps, res, 200, {
            {"ok", true},
            {"indexed", indexed},
            {"skipped", skipped},
            {"failed", failed},
            {"scanned", static_cast<int>(items.size())}
        });
    });
}

} // namespace pqnas
