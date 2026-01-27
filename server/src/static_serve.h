#pragma once
#include "httplib.h"
#include <string>

bool serve_static_file(const httplib::Request& req,
                       httplib::Response& res,
                       const std::string& abs_path,
                       const std::string& content_type,
                       bool no_store);
