#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pqnas {

    struct MlKem768KeypairV1 {
        std::vector<std::uint8_t> public_key;
        std::vector<std::uint8_t> secret_key;
    };

    struct MlKem768EncapResultV1 {
        std::vector<std::uint8_t> ciphertext;
        std::vector<std::uint8_t> shared_secret;
    };

    bool mlkem768_available_v1();
    std::string mlkem768_backend_name_v1();

    bool mlkem768_keygen_v1(MlKem768KeypairV1* out, std::string* err);

    bool mlkem768_encapsulate_v1(const std::vector<std::uint8_t>& public_key,
                                 MlKem768EncapResultV1* out,
                                 std::string* err);

    bool mlkem768_decapsulate_v1(const std::vector<std::uint8_t>& secret_key,
                                 const std::vector<std::uint8_t>& ciphertext,
                                 std::vector<std::uint8_t>* out_shared_secret,
                                 std::string* err);

} // namespace pqnas