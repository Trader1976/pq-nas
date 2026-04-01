#include "dna_mlkem_compress.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    // Basic coefficient helper checks.
    if (compress_coeff_d4(0) > 15) return 1;
    if (!coeff_is_canonical(decompress_coeff_d4(0))) return 1;
    if (!coeff_is_canonical(decompress_coeff_d4(15))) return 1;

    // Midpoint-ish value should land near the middle of the 4-bit range.
    {
        const std::uint8_t mid = compress_coeff_d4(kQ / 2);
        if (mid < 7 || mid > 8) {
            std::cerr << "unexpected midpoint compress result: " << static_cast<int>(mid) << std::endl;
            return 1;
        }
    }

    Poly p;
    poly_zero(&p);

    // Deterministic canonical pattern across the full polynomial.
    for (std::size_t i = 0; i < kN; ++i) {
        p.coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i * 29 + 17));
    }

    if (!poly_is_canonical(p)) return 1;

    std::vector<std::uint8_t> enc;
    std::string err;
    if (!poly_compress_dv4(p, &enc, &err)) {
        std::cerr << "poly_compress_dv4 failed: " << err << std::endl;
        return 1;
    }

    if (enc.size() != kPolyCompressedBytesDv) {
        std::cerr << "compressed size mismatch" << std::endl;
        return 1;
    }

    Poly dec;
    if (!poly_decompress_dv4(enc, &dec, &err)) {
        std::cerr << "poly_decompress_dv4 failed: " << err << std::endl;
        return 1;
    }

    if (!poly_is_canonical(dec)) {
        std::cerr << "decompressed poly not canonical" << std::endl;
        return 1;
    }

    // Compression is lossy, so we do not require dec == p.
    // Instead, recompress(decompress(compress(p))) must be stable.
    std::vector<std::uint8_t> enc2;
    if (!poly_compress_dv4(dec, &enc2, &err)) {
        std::cerr << "recompress failed: " << err << std::endl;
        return 1;
    }

    if (enc != enc2) {
        std::cerr << "compressed roundtrip not stable" << std::endl;
        return 1;
    }

    // Wrong length must fail.
    {
        std::vector<std::uint8_t> short_in(kPolyCompressedBytesDv - 1, 0);
        Poly tmp;
        if (poly_decompress_dv4(short_in, &tmp, &err)) {
            std::cerr << "expected compressed length rejection" << std::endl;
            return 1;
        }
        if (err != "bad_poly_compressed_dv4_len") {
            std::cerr << "unexpected compressed length error: " << err << std::endl;
            return 1;
        }
    }

    // Non-canonical input must not compress.
    {
        Poly bad = p;
        bad.coeffs[11] = static_cast<std::int16_t>(kQ);
        if (poly_compress_dv4(bad, &enc, &err)) {
            std::cerr << "expected non-canonical compress rejection" << std::endl;
            return 1;
        }
        if (err != "poly_not_canonical") {
            std::cerr << "unexpected non-canonical compress error: " << err << std::endl;
            return 1;
        }
    }

    // Tiny packing sanity check with hand-picked nibble values.
    {
        Poly small;
        poly_zero(&small);

        small.coeffs[0] = 0;
        small.coeffs[1] = kQ / 2;
        small.coeffs[2] = kQ - 1;
        small.coeffs[3] = kQ / 4;

        if (!poly_compress_dv4(small, &enc, &err)) {
            std::cerr << "small compress failed: " << err << std::endl;
            return 1;
        }

        // First byte should contain coeff 0 in low nibble and coeff 1 in high nibble.
        const std::uint8_t t0 = compress_coeff_d4(small.coeffs[0]);
        const std::uint8_t t1 = compress_coeff_d4(small.coeffs[1]);
        if (enc[0] != static_cast<std::uint8_t>((t0 & 0x0f) | ((t1 & 0x0f) << 4))) {
            std::cerr << "packing sanity check failed" << std::endl;
            return 1;
        }
    }

    std::cout << "[dna-pqcore-learn] poly compress dv4 ok"
              << " compressed_bytes=" << kPolyCompressedBytesDv
              << std::endl;

    return 0;
}