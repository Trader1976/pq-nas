#include "internal/dna_mlkem768_provider.h"

namespace dnanexus::pq::internal {

    bool mlkem768_dna_provider_available() {
        return false;
    }

    std::string mlkem768_dna_provider_name() {
        return "dna-internal-wip";
    }

    MlKem768Status mlkem768_dna_provider_keygen(MlKem768Keypair* out) {
        mlkem768_wipe_keypair(out);
        return out ? MlKem768Status::provider_failed : MlKem768Status::output_null;
    }

    MlKem768Status mlkem768_dna_provider_encapsulate(
        const std::vector<std::uint8_t>&,
        MlKem768EncapResult* out) {
        mlkem768_wipe_encap_result(out);
        return out ? MlKem768Status::provider_failed : MlKem768Status::output_null;
    }

    MlKem768Status mlkem768_dna_provider_decapsulate(
        const std::vector<std::uint8_t>&,
        const std::vector<std::uint8_t>&,
        std::vector<std::uint8_t>* out_shared_secret) {
        mlkem768_wipe_shared_secret(out_shared_secret);
        return out_shared_secret ? MlKem768Status::provider_failed
                                 : MlKem768Status::output_null;
    }

} // namespace dnanexus::pq::internal