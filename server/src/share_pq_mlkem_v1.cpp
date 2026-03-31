#include "share_pq_mlkem_v1.h"

#include <algorithm>

namespace pqnas {
    namespace {

        static void wipe_bytes(std::vector<std::uint8_t>* v) {
            if (!v) return;
            std::fill(v->begin(), v->end(), 0);
            v->clear();
            v->shrink_to_fit();
        }

    } // namespace

    bool mlkem768_available_v1() {
        return false;
    }

    std::string mlkem768_backend_name_v1() {
        return "unavailable";
    }

    bool mlkem768_keygen_v1(MlKem768KeypairV1* out, std::string* err) {
        if (out) {
            wipe_bytes(&out->public_key);
            wipe_bytes(&out->secret_key);
        }
        if (err) *err = "mlkem768_backend_unavailable";
        return false;
    }

    bool mlkem768_encapsulate_v1(const std::vector<std::uint8_t>& public_key,
                                 MlKem768EncapResultV1* out,
                                 std::string* err) {
        (void)public_key;
        if (out) {
            wipe_bytes(&out->ciphertext);
            wipe_bytes(&out->shared_secret);
        }
        if (err) *err = "mlkem768_backend_unavailable";
        return false;
    }

    bool mlkem768_decapsulate_v1(const std::vector<std::uint8_t>& secret_key,
                                 const std::vector<std::uint8_t>& ciphertext,
                                 std::vector<std::uint8_t>* out_shared_secret,
                                 std::string* err) {
        (void)secret_key;
        (void)ciphertext;
        if (out_shared_secret) wipe_bytes(out_shared_secret);
        if (err) *err = "mlkem768_backend_unavailable";
        return false;
    }

} // namespace pqnas