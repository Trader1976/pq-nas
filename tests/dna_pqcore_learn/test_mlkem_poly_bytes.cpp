#include "dna_mlkem_poly_bytes.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    Poly p;
    poly_zero(&p);

    // Fill with a deterministic canonical pattern.
    for (std::size_t i = 0; i < kN; ++i) {
        p.coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i * 17 + 23));
    }

    if (!poly_is_canonical(p)) return 1;

    std::vector<std::uint8_t> enc;
    std::string err;
    if (!poly_to_bytes(p, &enc, &err)) {
        std::cerr << "poly_to_bytes failed: " << err << std::endl;
        return 1;
    }

    if (enc.size() != kPolyBytes) {
        std::cerr << "encoded size mismatch" << std::endl;
        return 1;
    }

    Poly dec;
    if (!poly_from_bytes(enc, &dec, &err)) {
        std::cerr << "poly_from_bytes failed: " << err << std::endl;
        return 1;
    }

    if (!poly_equal(p, dec)) {
        std::cerr << "roundtrip mismatch" << std::endl;
        return 1;
    }

    // Corrupt one decoded coefficient to exceed q after unpacking.
    {
        std::vector<std::uint8_t> bad = enc;

        // Pair 0:
        // t0 = b0 | ((b1 & 0x0f) << 8)
        // Make t0 = 4095, which is outside canonical range [0, 3329).
        bad[0] = 0xff;
        bad[1] = static_cast<std::uint8_t>((bad[1] & 0xf0) | 0x0f);

        Poly tmp;
        if (poly_from_bytes(bad, &tmp, &err)) {
            std::cerr << "expected canonical-range rejection" << std::endl;
            return 1;
        }
        if (err != "decoded_coeff_not_canonical") {
            std::cerr << "unexpected error: " << err << std::endl;
            return 1;
        }
    }

    // Wrong input size must fail.
    {
        std::vector<std::uint8_t> short_in(kPolyBytes - 1, 0);
        Poly tmp;
        if (poly_from_bytes(short_in, &tmp, &err)) {
            std::cerr << "expected length rejection" << std::endl;
            return 1;
        }
        if (err != "bad_poly_bytes_len") {
            std::cerr << "unexpected short input error: " << err << std::endl;
            return 1;
        }
    }

    // Non-canonical polynomial must not serialize.
    {
        Poly bad_poly = p;
        bad_poly.coeffs[7] = static_cast<std::int16_t>(kQ); // not canonical
        if (poly_to_bytes(bad_poly, &enc, &err)) {
            std::cerr << "expected non-canonical serialize rejection" << std::endl;
            return 1;
        }
        if (err != "poly_not_canonical") {
            std::cerr << "unexpected non-canonical error: " << err << std::endl;
            return 1;
        }
    }

    std::cout << "[dna-pqcore-learn] poly bytes ok"
              << " poly_bytes=" << kPolyBytes
              << std::endl;

    return 0;
}