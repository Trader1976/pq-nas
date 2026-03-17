#include "file_favorites.h"

#include "pqnas_util.h"

#include <algorithm>
#include <fstream>
#include <system_error>

using nlohmann::json;

namespace pqnas {

namespace {

std::string fav_key(const std::string& type, const std::string& rel_path_norm) {
    return (type == "dir" ? "dir:" : "file:") + rel_path_norm;
}

json make_empty_doc() {
    return json{
        {"version", 1},
        {"updated_at", pqnas::now_iso_utc()},
        {"favorites", json::object()}
    };
}

bool ensure_doc_shape(json* doc) {
    if (!doc || !doc->is_object()) return false;
    if (!doc->contains("version")) (*doc)["version"] = 1;
    if (!doc->contains("updated_at")) (*doc)["updated_at"] = pqnas::now_iso_utc();
    if (!doc->contains("favorites") || !(*doc)["favorites"].is_object()) {
        (*doc)["favorites"] = json::object();
    }
    return true;
}

bool read_json_file(const std::filesystem::path& p, json* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    std::ifstream f(p);
    if (!f.is_open()) {
        if (err) *err = "open failed";
        return false;
    }

    try {
        f >> *out;
        return true;
    } catch (const std::exception& e) {
        if (err) *err = e.what();
        return false;
    }
}
    bool write_text_file_atomic_local(const std::filesystem::path& path,
                                      const std::string& content,
                                      std::string* err) {
    if (err) err->clear();

    const std::filesystem::path tmp = path.string() + ".tmp";

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            if (err) *err = "open tmp failed";
            return false;
        }

        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!f.good()) {
            if (err) *err = "write tmp failed";
            f.close();
            std::error_code ec_rm;
            std::filesystem::remove(tmp, ec_rm);
            return false;
        }

        f.close();
        if (!f.good()) {
            if (err) *err = "close tmp failed";
            std::error_code ec_rm;
            std::filesystem::remove(tmp, ec_rm);
            return false;
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::error_code ec_rm;
        std::filesystem::remove(tmp, ec_rm);
        if (err) *err = ec.message();
        return false;
    }

    return true;
}
} // namespace

std::filesystem::path favorites_meta_dir_for_user(const std::filesystem::path& user_dir) {
    return user_dir / ".pqnas";
}

std::filesystem::path favorites_json_path_for_user(const std::filesystem::path& user_dir) {
    return favorites_meta_dir_for_user(user_dir) / "favorites.json";
}

bool favorites_load(const std::filesystem::path& user_dir,
                    json* out,
                    std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "null out";
        return false;
    }

    const auto path = favorites_json_path_for_user(user_dir);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        *out = make_empty_doc();
        return true;
    }

    json doc;
    if (!read_json_file(path, &doc, err)) return false;
    if (!ensure_doc_shape(&doc)) {
        if (err) *err = "invalid favorites doc";
        return false;
    }

    *out = std::move(doc);
    return true;
}

bool favorites_save_atomic(const std::filesystem::path& user_dir,
                           const json& doc,
                           std::string* err) {
    if (err) err->clear();

    std::error_code ec;
    const auto dir = favorites_meta_dir_for_user(user_dir);
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        if (err) *err = ec.message();
        return false;
    }

    json tmp = doc;
    if (!ensure_doc_shape(&tmp)) {
        if (err) *err = "invalid favorites doc";
        return false;
    }
    tmp["updated_at"] = pqnas::now_iso_utc();

    const auto final_path = favorites_json_path_for_user(user_dir);

    if (!write_text_file_atomic_local(final_path, tmp.dump(2) + "\n", err)) {
        return false;
    }
    return true;
}

bool favorites_list_items(const std::filesystem::path& user_dir,
                          std::vector<FavoriteItem>* out_items,
                          std::string* err) {
    if (err) err->clear();
    if (!out_items) {
        if (err) *err = "null out_items";
        return false;
    }

    json doc;
    if (!favorites_load(user_dir, &doc, err)) return false;

    out_items->clear();
    const auto& favs = doc["favorites"];
    for (auto it = favs.begin(); it != favs.end(); ++it) {
        if (!it.value().is_object()) continue;
        FavoriteItem fi;
        fi.path = it.value().value("path", "");
        fi.type = it.value().value("type", "");
        fi.added_at = it.value().value("added_at", "");
        if (fi.path.empty()) continue;
        if (fi.type != "file" && fi.type != "dir") continue;
        out_items->push_back(std::move(fi));
    }

    std::sort(out_items->begin(), out_items->end(),
              [](const FavoriteItem& a, const FavoriteItem& b) {
                  if (a.type != b.type) return a.type < b.type;
                  return a.path < b.path;
              });

    return true;
}

bool favorites_add(const std::filesystem::path& user_dir,
                   const std::string& rel_path_norm,
                   const std::string& type,
                   std::string* err) {
    if (err) err->clear();
    if (type != "file" && type != "dir") {
        if (err) *err = "invalid type";
        return false;
    }

    json doc;
    if (!favorites_load(user_dir, &doc, err)) return false;

    const std::string key = fav_key(type, rel_path_norm);
    doc["favorites"][key] = json{
        {"path", rel_path_norm},
        {"type", type},
        {"added_at", pqnas::now_iso_utc()}
    };

    return favorites_save_atomic(user_dir, doc, err);
}

bool favorites_remove(const std::filesystem::path& user_dir,
                      const std::string& rel_path_norm,
                      const std::string& type,
                      std::string* err) {
    if (err) err->clear();
    if (type != "file" && type != "dir") {
        if (err) *err = "invalid type";
        return false;
    }

    json doc;
    if (!favorites_load(user_dir, &doc, err)) return false;

    const std::string key = fav_key(type, rel_path_norm);
    doc["favorites"].erase(key);

    return favorites_save_atomic(user_dir, doc, err);
}

bool favorites_move_path(const std::filesystem::path& user_dir,
                         const std::string& from_rel_norm,
                         const std::string& to_rel_norm,
                         const std::string& type,
                         std::string* err) {
    if (err) err->clear();
    if (type != "file" && type != "dir") {
        if (err) *err = "invalid type";
        return false;
    }

    json doc;
    if (!favorites_load(user_dir, &doc, err)) return false;

    auto& favs = doc["favorites"];
    bool changed = false;

    if (type == "file") {
        const std::string oldk = fav_key("file", from_rel_norm);
        if (favs.contains(oldk) && favs[oldk].is_object()) {
            json rec = favs[oldk];
            favs.erase(oldk);
            rec["path"] = to_rel_norm;
            rec["type"] = "file";
            favs[fav_key("file", to_rel_norm)] = rec;
            changed = true;
        }
    } else {
        const std::string dir_oldk = fav_key("dir", from_rel_norm);
        if (favs.contains(dir_oldk) && favs[dir_oldk].is_object()) {
            json rec = favs[dir_oldk];
            favs.erase(dir_oldk);
            rec["path"] = to_rel_norm;
            rec["type"] = "dir";
            favs[fav_key("dir", to_rel_norm)] = rec;
            changed = true;
        }

        const std::string file_prefix = "file:" + from_rel_norm + "/";
        const std::string dir_prefix  = "dir:"  + from_rel_norm + "/";

        std::vector<std::pair<std::string, json>> replacements;
        std::vector<std::string> to_erase;

        for (auto it = favs.begin(); it != favs.end(); ++it) {
            const std::string k = it.key();
            if (k.rfind(file_prefix, 0) == 0 || k.rfind(dir_prefix, 0) == 0) {
                if (!it.value().is_object()) continue;
                const std::string old_path = it.value().value("path", "");
                if (old_path.empty()) continue;

                std::string suffix;
                if (old_path.size() > from_rel_norm.size()) suffix = old_path.substr(from_rel_norm.size());
                std::string new_path = to_rel_norm + suffix;

                json rec = it.value();
                rec["path"] = new_path;
                const std::string new_type = rec.value("type", "");
                replacements.push_back({ fav_key(new_type, new_path), rec });
                to_erase.push_back(k);
                changed = true;
            }
        }

        for (const auto& k : to_erase) favs.erase(k);
        for (auto& kv : replacements) favs[kv.first] = kv.second;
    }

    if (!changed) return true;
    return favorites_save_atomic(user_dir, doc, err);
}

bool favorites_remove_under_prefix(const std::filesystem::path& user_dir,
                                   const std::string& rel_path_norm,
                                   const std::string& type,
                                   std::string* err) {
    if (err) err->clear();
    if (type != "file" && type != "dir") {
        if (err) *err = "invalid type";
        return false;
    }

    json doc;
    if (!favorites_load(user_dir, &doc, err)) return false;

    auto& favs = doc["favorites"];


    favs.erase(fav_key(type, rel_path_norm));

    if (type == "dir")
    {
        const std::string file_prefix = "file:" + rel_path_norm + "/";
        const std::string dir_prefix  = "dir:"  + rel_path_norm + "/";
        for (auto it = favs.begin(); it != favs.end(); ) {
            const std::string k = it.key();
            if (k.rfind(file_prefix, 0) == 0 || k.rfind(dir_prefix, 0) == 0) {
                it = favs.erase(it);
            } else {
                ++it;
            }
        }
    }
    return favorites_save_atomic(user_dir, doc, err);
}

} // namespace pqnas