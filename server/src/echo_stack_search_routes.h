#pragma once

#include "echo_stack_routes.h"

namespace pqnas {


bool echo_stack_index_archived_item_for_search(const EchoStackRoutesDeps& deps,
                                               const std::string& owner_fp,
                                               const std::string& item_id,
                                               std::string* indexed_source,
                                               std::string* err);

void register_echo_stack_search_routes(httplib::Server& srv,
                                       const EchoStackRoutesDeps& deps);

} // namespace pqnas
