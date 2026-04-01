#include "dna_mlkem_polyvec_bytes.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    PolyVec v;
    polyvec_zero(&v);

    // Fill with deterministic canonical values across all k polynomials.
    for (std::size_t p = 0; p < kK; ++p) {
        for (std::size_t i = 0; i < kN; ++i) {
            v.polys[p].coeffs[i] = coeff_normalize(
                static_cast<std::int32_t>(p * 1000 + i * 13 + 19));
        }
    }

    if (!polyvec_is_canonical(v)) return 1;

    std::vector<std::uint8_t> enc;
    std::string err;
    if (!polyvec_to_bytes(v, &enc, &err)) {
        std::cerr << "polyvec_to_bytes failed: " << err << std::endl;
        return 1;
    }

    if (enc.size() != kPolyVecBytes) {
        std::cerr << "encoded polyvec size mismatch" << std::endl;
        return 1;
    }

    PolyVec dec;
    if (!polyvec_from_bytes(enc, &dec, &err)) {
        std::cerr << "polyvec_from_bytes failed: " << err << std::endl;
        return 1;
    }

    if (!polyvec_equal(v, dec)) {
        std::cerr << "polyvec roundtrip mismatch" << std::endl;
        return 1;
    }

    // Wrong length must fail.
    {
        std::vector<std::uint8_t> short_in(kPolyVecBytes - 1, 0);
        PolyVec tmp;
        if (polyvec_from_bytes(short_in, &tmp, &err)) {
            std::cerr << "expected polyvec length rejection" << std::endl;
            return 1;
        }
        if (err != "bad_polyvec_bytes_len") {
            std::cerr << "unexpected short polyvec error: " << err << std::endl;
            return 1;
        }
    }

    // Corrupt one coefficient in the first encoded polynomial so decode rejects it.
    {
        std::vector<std::uint8_t> bad = enc;

        // First polynomial begins at offset 0.
        // First coefficient is encoded by bad[0] and low nibble of bad[1].
        // Force it to 4095 (> q-1), which must fail canonical-range validation.
        bad[0] = 0xff;
        bad[1] = static_cast<std::uint8_t>((bad[1] & 0xf0) | 0x0f);

        PolyVec tmp;
        if (polyvec_from_bytes(bad, &tmp, &err)) {
            std::cerr << "expected canonical-range rejection" << std::endl;
            return 1;
        }
        if (err != "decoded_coeff_not_canonical") {
            std::cerr << "unexpected decode error: " << err << std::endl;
            return 1;
        }
    }

    // Non-canonical polyvec must not serialize.
    {
        PolyVec bad_v = v;
        bad_v.polys[1].coeffs[9] = static_cast<std::int16_t>(kQ);
        if (polyvec_to_bytes(bad_v, &enc, &err)) {
            std::cerr << "expected non-canonical polyvec serialize rejection" << std::endl;
            return 1;
        }
        if (err != "polyvec_not_canonical") {
            std::cerr << "unexpected non-canonical polyvec error: " << err << std::endl;
            return 1;
        }
    }

    std::cout << "[dna-pqcore-learn] polyvec bytes ok"
              << " k=" << kK
              << " polyvec_bytes=" << kPolyVecBytes
              << std::endl;

    return 0;
}