#include "routes_people.h"

#include "people_contacts.h"

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas {
namespace {

using json = nlohmann::json;

void reply_json_local(const PeopleRoutesDeps& deps,
                      httplib::Response& res,
                      int code,
                      const json& body) {
    if (deps.reply_json) {
        deps.reply_json(res, code, body.dump());
        return;
    }

    res.status = code;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

bool deps_ok_local(const PeopleRoutesDeps& deps) {
    return deps.users &&
           deps.cookie_key &&
           deps.require_user_auth_users_actor &&
           deps.reply_json &&
           !deps.people_db_path.empty();
}

bool require_actor_local(const PeopleRoutesDeps& deps,
                         const httplib::Request& req,
                         httplib::Response& res,
                         std::string* actor_fp,
                         std::string* actor_role) {
    if (!deps_ok_local(deps)) {
        reply_json_local(deps, res, 500, json{
            {"ok", false},
            {"error", "server_error"},
            {"message", "people route dependencies missing"}
        });
        return false;
    }

    return deps.require_user_auth_users_actor(
        req,
        res,
        deps.cookie_key,
        deps.users,
        actor_fp,
        actor_role);
}

json contact_to_json_local(const PeopleContactRecord& c) {
    return json{
        {"id", c.id},
        {"subject_user_id", c.subject_user_id},
        {"subject_fingerprint", c.subject_fingerprint},
        {"subject_fingerprint_short", people_fingerprint_short(c.subject_fingerprint)},
        {"subject_kind", c.subject_kind},
        {"display_name", c.display_name},
        {"nickname", c.nickname},
        {"notes", c.notes},
        {"created_at_epoch", c.created_at_epoch},
        {"updated_at_epoch", c.updated_at_epoch}
    };
}

std::string json_string_local(const json& j, const char* key) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

} // namespace

void register_people_routes(httplib::Server& srv, const PeopleRoutesDeps& deps) {
    srv.Get("/api/v4/people/list", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;
        if (!require_actor_local(deps, req, res, &actor_fp, &actor_role)) return;

        actor_fp = people_canonical_fingerprint(actor_fp);
        if (!people_valid_fingerprint(actor_fp)) {
            reply_json_local(deps, res, 403, json{
                {"ok", false},
                {"error", "forbidden"},
                {"message", "invalid authenticated fingerprint"}
            });
            return;
        }

        PeopleContactsStore store(deps.people_db_path);
        std::vector<PeopleContactRecord> contacts;
        std::string err;
        if (!store.list_for_owner(actor_fp, &contacts, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to list people"}
            });
            return;
        }

        json arr = json::array();
        for (const auto& c : contacts) arr.push_back(contact_to_json_local(c));

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"contacts", arr},
            {"count", arr.size()}
        });
    });

    srv.Get("/api/v4/people/resolve", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;
        if (!require_actor_local(deps, req, res, &actor_fp, &actor_role)) return;

        actor_fp = people_canonical_fingerprint(actor_fp);
        const std::string subject_fp = people_canonical_fingerprint(
            req.has_param("fingerprint") ? req.get_param_value("fingerprint") : "");

        if (!people_valid_fingerprint(actor_fp) || !people_valid_fingerprint(subject_fp)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid fingerprint"}
            });
            return;
        }

        PeopleContactsStore store(deps.people_db_path);
        std::optional<PeopleContactRecord> found;
        std::string err;
        if (!store.find_for_owner(actor_fp, subject_fp, &found, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to resolve person"}
            });
            return;
        }

        if (found.has_value()) {
            reply_json_local(deps, res, 200, json{
                {"ok", true},
                {"resolved", true},
                {"source", "people"},
                {"person", contact_to_json_local(*found)}
            });
            return;
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"resolved", false},
            {"source", "fingerprint"},
            {"person", {
                {"subject_fingerprint", subject_fp},
                {"subject_fingerprint_short", people_fingerprint_short(subject_fp)},
                {"subject_kind", "fingerprint"},
                {"display_name", people_fingerprint_short(subject_fp)}
            }}
        });
    });

    srv.Post("/api/v4/people/upsert", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;
        if (!require_actor_local(deps, req, res, &actor_fp, &actor_role)) return;

        actor_fp = people_canonical_fingerprint(actor_fp);

        json body;
        try {
            body = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (...) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            });
            return;
        }

        PeopleContactRecord input;
        input.subject_user_id = json_string_local(body, "subject_user_id");
        input.subject_fingerprint = json_string_local(body, "subject_fingerprint");
        if (input.subject_fingerprint.empty()) {
            input.subject_fingerprint = json_string_local(body, "fingerprint");
        }
        input.subject_kind = json_string_local(body, "subject_kind");
        input.display_name = json_string_local(body, "display_name");
        input.nickname = json_string_local(body, "nickname");
        input.notes = json_string_local(body, "notes");

        input.subject_fingerprint = people_canonical_fingerprint(input.subject_fingerprint);

        if (!people_valid_fingerprint(actor_fp) || !people_valid_fingerprint(input.subject_fingerprint)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid fingerprint"}
            });
            return;
        }

        PeopleContactsStore store(deps.people_db_path);
        PeopleContactRecord saved;
        std::string err;
        if (!store.upsert_for_owner(actor_fp, input, &saved, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to save person"}
            });
            return;
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"contact", contact_to_json_local(saved)}
        });
    });

    srv.Post("/api/v4/people/delete", [deps](const httplib::Request& req, httplib::Response& res) {
        std::string actor_fp;
        std::string actor_role;
        if (!require_actor_local(deps, req, res, &actor_fp, &actor_role)) return;

        actor_fp = people_canonical_fingerprint(actor_fp);

        json body;
        try {
            body = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (...) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_json"},
                {"message", "invalid JSON body"}
            });
            return;
        }

        std::string subject_fp = json_string_local(body, "subject_fingerprint");
        if (subject_fp.empty()) subject_fp = json_string_local(body, "fingerprint");
        subject_fp = people_canonical_fingerprint(subject_fp);

        if (!people_valid_fingerprint(actor_fp) || !people_valid_fingerprint(subject_fp)) {
            reply_json_local(deps, res, 400, json{
                {"ok", false},
                {"error", "bad_request"},
                {"message", "invalid fingerprint"}
            });
            return;
        }

        PeopleContactsStore store(deps.people_db_path);
        bool deleted = false;
        std::string err;
        if (!store.delete_for_owner(actor_fp, subject_fp, &deleted, &err)) {
            reply_json_local(deps, res, 500, json{
                {"ok", false},
                {"error", "server_error"},
                {"message", "failed to delete person"}
            });
            return;
        }

        reply_json_local(deps, res, 200, json{
            {"ok", true},
            {"deleted", deleted}
        });
    });
}

} // namespace pqnas
