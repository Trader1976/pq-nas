#include "internal/dna_mlkem768_provider_select.h"
#include "internal/dna_mlkem768_provider.h"

#include <cstdlib>
#include <cstring>

namespace dnanexus::pq::internal {
namespace {

bool g_has_selected_provider_override = false;
MlKem768ProviderId g_selected_provider_override = MlKem768ProviderId::native;

bool mlkem768_selected_provider_from_env(MlKem768ProviderId* out) {
    if (!out) return false;

    const char* v = std::getenv("DNA_MLKEM_SELECTED_PROVIDER");
    if (!v || !*v) return false;

    if (std::strcmp(v, "native") == 0) {
        *out = MlKem768ProviderId::native;
        return true;
    }

    if (std::strcmp(v, "dna") == 0) {
        *out = MlKem768ProviderId::dna;
        return true;
    }

    // Ignore unsupported/unknown values, including "stub".
    return false;
}

} // namespace

MlKem768ProviderId mlkem768_selected_provider_id() {
    MlKem768ProviderId env_id = MlKem768ProviderId::native;
    if (mlkem768_selected_provider_from_env(&env_id)) {
        return env_id;
    }

    if (g_has_selected_provider_override) {
        return g_selected_provider_override;
    }

    return mlkem768_active_provider_id();
}

bool mlkem768_set_selected_provider_override(MlKem768ProviderId id) {
    switch (id) {
        case MlKem768ProviderId::native:
        case MlKem768ProviderId::dna:
            g_selected_provider_override = id;
            g_has_selected_provider_override = true;
            return true;
        case MlKem768ProviderId::stub:
            return false;
    }
    return false;
}

void mlkem768_clear_selected_provider_override() {
    g_selected_provider_override = MlKem768ProviderId::native;
    g_has_selected_provider_override = false;
}

bool mlkem768_has_selected_provider_override() {
    return g_has_selected_provider_override;
}

bool mlkem768_provider_available_by_id(MlKem768ProviderId id) {
    switch (id) {
        case MlKem768ProviderId::native:
            return mlkem768_provider_available();
        case MlKem768ProviderId::stub:
            return mlkem768_stub_provider_available();
        case MlKem768ProviderId::dna:
            return mlkem768_dna_provider_available();
    }
    return false;
}

std::string mlkem768_provider_name_by_id(MlKem768ProviderId id) {
    switch (id) {
        case MlKem768ProviderId::native:
            return mlkem768_provider_name();
        case MlKem768ProviderId::stub:
            return mlkem768_stub_provider_name();
        case MlKem768ProviderId::dna:
            return mlkem768_dna_provider_name();
    }
    return "unknown";
}

MlKem768Status mlkem768_provider_keygen_by_id(MlKem768ProviderId id,
                                              MlKem768Keypair* out) {
    switch (id) {
        case MlKem768ProviderId::native:
            return mlkem768_provider_keygen(out);
        case MlKem768ProviderId::stub:
            return mlkem768_stub_provider_keygen(out);
        case MlKem768ProviderId::dna:
            return mlkem768_dna_provider_keygen(out);
    }
    return MlKem768Status::provider_failed;
}

MlKem768Status mlkem768_provider_encapsulate_by_id(
    MlKem768ProviderId id,
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out) {
    switch (id) {
        case MlKem768ProviderId::native:
            return mlkem768_provider_encapsulate(public_key, out);
        case MlKem768ProviderId::stub:
            return mlkem768_stub_provider_encapsulate(public_key, out);
        case MlKem768ProviderId::dna:
            return mlkem768_dna_provider_encapsulate(public_key, out);
    }
    return MlKem768Status::provider_failed;
}

MlKem768Status mlkem768_provider_decapsulate_by_id(
    MlKem768ProviderId id,
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>* out_shared_secret) {
    switch (id) {
        case MlKem768ProviderId::native:
            return mlkem768_provider_decapsulate(secret_key, ciphertext, out_shared_secret);
        case MlKem768ProviderId::stub:
            return mlkem768_stub_provider_decapsulate(secret_key, ciphertext, out_shared_secret);
        case MlKem768ProviderId::dna:
            return mlkem768_dna_provider_decapsulate(secret_key, ciphertext, out_shared_secret);
    }
    return MlKem768Status::provider_failed;
}

bool mlkem768_selected_provider_available() {
    return mlkem768_provider_available_by_id(mlkem768_selected_provider_id());
}

std::string mlkem768_selected_provider_name() {
    return mlkem768_provider_name_by_id(mlkem768_selected_provider_id());
}

MlKem768Status mlkem768_selected_provider_keygen(MlKem768Keypair* out) {
    return mlkem768_provider_keygen_by_id(mlkem768_selected_provider_id(), out);
}

MlKem768Status mlkem768_selected_provider_encapsulate(
    const std::vector<std::uint8_t>& public_key,
    MlKem768EncapResult* out) {
    return mlkem768_provider_encapsulate_by_id(
        mlkem768_selected_provider_id(), public_key, out);
}

MlKem768Status mlkem768_selected_provider_decapsulate(
    const std::vector<std::uint8_t>& secret_key,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>* out_shared_secret) {
    return mlkem768_provider_decapsulate_by_id(
        mlkem768_selected_provider_id(), secret_key, ciphertext, out_shared_secret);
}

} // namespace dnanexus::pq::internal