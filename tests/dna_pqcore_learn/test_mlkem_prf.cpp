#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "dna_mlkem_prf.h"

using namespace pqnas::dna_pqcore_learn;

namespace {

bool fail(const char* msg) {
    std::cerr << "[dna-pqcore-learn] prf test failed: " << msg << "\n";
    return false;
}

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

} // namespace

int main() {
    static_assert(kMlkemSymBytes == 32, "test assumes 32-byte ML-KEM seed");
    static_assert(kMlkemPrfEta2Bytes == 128, "test assumes eta2 PRF length");
    static_assert(kMlkemPrfEta3Bytes == 192, "test assumes eta3 PRF length");

    std::array<std::uint8_t, kMlkemSymBytes> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
    }

    std::array<std::uint8_t, kMlkemPrfEta2Bytes> out_eta2_a{};
    std::array<std::uint8_t, kMlkemPrfEta2Bytes> out_eta2_b{};
    std::array<std::uint8_t, kMlkemPrfEta2Bytes> out_eta2_nonce9{};
    std::array<std::uint8_t, kMlkemPrfEta3Bytes> out_eta3{};

    std::string err;

    if (!mlkem_prf_eta2(out_eta2_a.data(), seed.data(), 7, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta2 nonce=7 failed");
    }

    if (!mlkem_prf_eta2(out_eta2_b.data(), seed.data(), 7, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta2 repeat nonce=7 failed");
    }

    if (!mlkem_prf_eta2(out_eta2_nonce9.data(), seed.data(), 9, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta2 nonce=9 failed");
    }

    if (!mlkem_prf_eta3(out_eta3.data(), seed.data(), 7, &err)) {
        std::cerr << err << "\n";
        return fail("mlkem_prf_eta3 nonce=7 failed");
    }

    // Determinism.
    for (std::size_t i = 0; i < out_eta2_a.size(); ++i) {
        if (out_eta2_a[i] != out_eta2_b[i]) {
            return fail("eta2 determinism mismatch");
        }
    }

    // Different nonce should change output.
    bool any_diff = false;
    for (std::size_t i = 0; i < out_eta2_a.size(); ++i) {
        if (out_eta2_a[i] != out_eta2_nonce9[i]) {
            any_diff = true;
            break;
        }
    }
    if (!any_diff) return fail("nonce did not affect eta2 output");

    // SHAKE prefix property:
    // eta=3 output should start with the eta=2 output when seed||nonce is same.
    for (std::size_t i = 0; i < out_eta2_a.size(); ++i) {
        if (out_eta3[i] != out_eta2_a[i]) {
            return fail("eta3 prefix mismatch");
        }
    }

    // Fixed vectors for seed = 00 01 02 ... 1f and nonce = 07 / 09.
    const std::string expected_eta2_nonce7 =
        "ef0db3228629d8c1fd9ff01307267104f06b42249d61c11743378f41743612aa"
        "b524292b182c797dff1dc34c80cca108c3239dc537da4bd5c3b3ffe0291d62ec"
        "94095b0f4777573bad953fed0a44b35af880a34cc3d8f07d30ec62855efdad04"
        "45fa57066185379d2906601280af0a6ef28b25476640025664a786b600c28fae";

    const std::string expected_eta3_nonce7 =
        "ef0db3228629d8c1fd9ff01307267104f06b42249d61c11743378f41743612aa"
        "b524292b182c797dff1dc34c80cca108c3239dc537da4bd5c3b3ffe0291d62ec"
        "94095b0f4777573bad953fed0a44b35af880a34cc3d8f07d30ec62855efdad04"
        "45fa57066185379d2906601280af0a6ef28b25476640025664a786b600c28fae"
        "fbad68b8afcfec08f39d855f6f085d434e1fe291060f34da053e337b964bb533"
        "a8002ce0eb78aa908c138d098162311048fe4539571cc0725105cfa73e6ecb06";

    const std::string expected_eta2_nonce9 =
        "208e27af2033dba3da3c8e11bc831754e9c8c42cbf1d82415206ba4fd1602b83"
        "f009664333680b2f8dfa2d507536cd81868d921c6b846158e422804d2ca21819"
        "ddc15c6dd8dbd71701055cf79eefb464efe6fde272a71c41e742611000c41f84"
        "f48c0ebbfeffcf40c5c69a30651f91b089ff48e5bd2e1d2bcdd9ac1bda463262";

    if (to_hex(out_eta2_a.data(), out_eta2_a.size()) != expected_eta2_nonce7) {
        return fail("eta2 fixed vector nonce=7 mismatch");
    }

    if (to_hex(out_eta3.data(), out_eta3.size()) != expected_eta3_nonce7) {
        return fail("eta3 fixed vector nonce=7 mismatch");
    }

    if (to_hex(out_eta2_nonce9.data(), out_eta2_nonce9.size()) != expected_eta2_nonce9) {
        return fail("eta2 fixed vector nonce=9 mismatch");
    }

    std::cout
        << "[dna-pqcore-learn] prf ok"
        << " seed_bytes=" << kMlkemSymBytes
        << " eta2_bytes=" << kMlkemPrfEta2Bytes
        << " eta3_bytes=" << kMlkemPrfEta3Bytes
        << "\n";

    return 0;
}