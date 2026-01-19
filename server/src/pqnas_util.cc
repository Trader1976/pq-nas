#include "pqnas_util.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <stdexcept>
#include <vector>
#include <sodium.h>

namespace pqnas {

long now_epoch() {
    return (long)std::time(nullptr);
}

std::string lower_ascii(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

std::vector<unsigned char> b64decode_loose(const std::string& in) {
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') s.push_back(c);
    }

    std::vector<unsigned char> out(s.size() + 8);
    size_t out_len = 0;

    auto try_variant = [&](int variant) -> bool {
        out_len = 0;
        return sodium_base642bin(out.data(), out.size(),
                                 s.c_str(), s.size(),
                                 nullptr, &out_len, nullptr,
                                 variant) == 0;
    };

    if (try_variant(sodium_base64_VARIANT_ORIGINAL) ||
        try_variant(sodium_base64_VARIANT_URLSAFE) ||
        try_variant(sodium_base64_VARIANT_URLSAFE_NO_PADDING)) {
        out.resize(out_len);
        return out;
    }

    throw std::runtime_error("invalid base64");
}

} // namespace pqnas
