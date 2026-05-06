#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pqnas::activity {

struct ActivityActor {
    std::string user_id;
    std::string display_name;
    std::string device_name;
    std::string fingerprint_short;
    std::string kind = "user"; // user, device, guest, system
};

struct ActivityEvent {
    std::string owner_user_id;

    ActivityActor actor;

    std::string event_type;

    std::string scope_type = "user"; // user, workspace, dropzone, share, security
    std::string scope_id;

    std::string target_kind; // file, folder, device, share, dropzone, archive
    std::string target_name;
    std::string target_path;

    std::string message;
    nlohmann::json details = nlohmann::json::object();
};

struct ActivityRow {
    long long id = 0;
    long long created_at_epoch = 0;

    std::string owner_user_id;

    ActivityActor actor;

    std::string event_type;
    std::string scope_type;
    std::string scope_id;

    std::string target_kind;
    std::string target_name;
    std::string target_path;

    std::string message;
    nlohmann::json details = nlohmann::json::object();
};

std::filesystem::path activity_dir_for_user_root(const std::filesystem::path& user_root);
std::filesystem::path activity_db_path_for_user_root(const std::filesystem::path& user_root);

std::string actor_label(const ActivityActor& actor);
std::string build_default_message(const ActivityEvent& ev);

bool record_user_activity(
    const std::filesystem::path& user_root,
    const ActivityEvent& ev,
    std::string* error_out = nullptr
);

std::vector<ActivityRow> list_user_activity(
    const std::filesystem::path& user_root,
    int limit,
    std::string* error_out = nullptr
);

nlohmann::json activity_row_to_json(const ActivityRow& row);

} // namespace pqnas::activity
