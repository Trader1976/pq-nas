#pragma once

#include <string>

namespace dnanexus::pq {

    // Diagnostic/provider-introspection helpers.
    //
    // These are intentionally separated from the public production ML-KEM API
    // surface. They remain useful for tests, startup checks, and diagnostics.

    bool mlkem768_available();
    std::string mlkem768_backend_name();
    bool mlkem768_selftest(std::string* err);

} // namespace dnanexus::pq