#pragma once
#include <string>
#include <vector>

namespace pqnas {

long now_epoch();
std::string lower_ascii(std::string s);

// Base64 decode (accepts original + urlsafe + urlsafe-no-padding; ignores whitespace).
// Throws std::runtime_error on invalid base64.
std::vector<unsigned char> b64decode_loose(const std::string& in);

} // namespace pqnasespace pqnas