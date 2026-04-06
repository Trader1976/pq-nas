#include "internal/dna_mlkem768_backend_diag.h"
#include "internal/dna_mlkem768_provider.h"
#include "internal/dna_mlkem768_provider_select.h"

#include <iostream>
#include <string>

using namespace dnanexus::pq;

namespace {

bool expect_true(const char* label, bool cond) {
    if (!cond) {
        std::cerr << "[dna-pqcore] " << label << " failed\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    if (!expect_true("no selector override by default",
                     !internal::mlkem768_has_selected_provider_override())) {
        return 1;
    }

    if (!expect_true("provider available", mlkem768_available())) {
        return 1;
    }

    if (!expect_true("internal active provider is native",
                     internal::mlkem768_active_provider_id() ==
                         internal::MlKem768ProviderId::native)) {
        return 1;
    }

    if (!expect_true("selected provider is native",
                     internal::mlkem768_selected_provider_id() ==
                         internal::MlKem768ProviderId::native)) {
        return 1;
    }

    const std::string internal_name = internal::mlkem768_provider_name();
    const std::string stub_name = internal::mlkem768_stub_provider_name();
    const std::string dna_name = internal::mlkem768_dna_provider_name();
    const std::string selected_name = internal::mlkem768_selected_provider_name();
    const std::string public_name = mlkem768_backend_name();

    if (!expect_true("internal provider name is mlkem-native-c",
                     internal_name == "mlkem-native-c")) {
        return 1;
    }

    if (!expect_true("stub provider name is stub-unavailable",
                     stub_name == "stub-unavailable")) {
        return 1;
    }

    if (!expect_true("dna provider name is dna-internal-wip",
                     dna_name == "dna-internal-wip")) {
        return 1;
    }

    if (!expect_true("selected provider name is mlkem-native-c",
                     selected_name == "mlkem-native-c")) {
        return 1;
    }

    if (!expect_true("public backend name matches selected provider name",
                     public_name == selected_name)) {
        return 1;
    }

    if (!expect_true("selected provider available",
                     internal::mlkem768_selected_provider_available())) {
        return 1;
    }

    if (!expect_true("stub provider unavailable",
                     !internal::mlkem768_stub_provider_available())) {
        return 1;
    }

    if (!expect_true("dna provider available",
                     internal::mlkem768_dna_provider_available())) {
        return 1;
    }

    if (!expect_true("native and stub names differ", internal_name != stub_name)) {
        return 1;
    }

    if (!expect_true("native and dna names differ", internal_name != dna_name)) {
        return 1;
    }

    if (!expect_true("stub and dna names differ", stub_name != dna_name)) {
        return 1;
    }

    std::cout << "[dna-pqcore] provider identity ok"
              << " id=native"
              << " name=" << public_name
              << "\n";

    return 0;
}