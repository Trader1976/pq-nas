#include "dna_mlkem_compress_du10.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    if (compress_coeff_du10(0) > 1023) return 1;
    if (!coeff_is_canonical(decompress_coeff_du10(0))) return 1;
    if (!coeff_is_canonical(decompress_coeff_du10(1023))) return 1;

    {
        const std::uint16_t mid = compress_coeff_du10(kQ / 2);
        if (mid < 511 || mid > 512) {
            std::cerr << "unexpected midpoint compress result: " << mid << std::endl;
            return 1;
        }
    }

    Poly p;
    poly_zero(&p);

    for (std::size_t i = 0; i < kN; ++i) {
        p.coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i * 37 + 21));
    }

    if (!poly_is_canonical(p)) return 1;

    std::vector<std::uint8_t> enc;
    std::string err;
    if (!poly_compress_du10(p, &enc, &err)) {
        std::cerr << "poly_compress_du10 failed: " << err << std::endl;
        return 1;
    }

    if (enc.size() != kPolyCompressedBytesDu) {
        std::cerr << "compressed size mismatch" << std::endl;
        return 1;
    }

    Poly dec;
    if (!poly_decompress_du10(enc, &dec, &err)) {
        std::cerr << "poly_decompress_du10 failed: " << err << std::endl;
        return 1;
    }

    if (!poly_is_canonical(dec)) {
        std::cerr << "decompressed poly not canonical" << std::endl;
        return 1;
    }

    std::vector<std::uint8_t> enc2;
    if (!poly_compress_du10(dec, &enc2, &err)) {
        std::cerr << "recompress failed: " << err << std::endl;
        return 1;
    }

    if (enc != enc2) {
        std::cerr << "compressed roundtrip not stable" << std::endl;
        return 1;
    }

    {
        std::vector<std::uint8_t> short_in(kPolyCompressedBytesDu - 1, 0);
        Poly tmp;
        if (poly_decompress_du10(short_in, &tmp, &err)) {
            std::cerr << "expected compressed length rejection" << std::endl;
            return 1;
        }
        if (err != "bad_poly_compressed_du10_len") {
            std::cerr << "unexpected compressed length error: " << err << std::endl;
            return 1;
        }
    }

    {
        Poly bad = p;
        bad.coeffs[13] = static_cast<std::int16_t>(kQ);
        if (poly_compress_du10(bad, &enc, &err)) {
            std::cerr << "expected non-canonical compress rejection" << std::endl;
            return 1;
        }
        if (err != "poly_not_canonical") {
            std::cerr << "unexpected non-canonical compress error: " << err << std::endl;
            return 1;
        }
    }

    // Packing sanity check for the first 4 coefficients.
    {
        Poly small;
        poly_zero(&small);

        small.coeffs[0] = 0;
        small.coeffs[1] = kQ / 3;
        small.coeffs[2] = kQ / 2;
        small.coeffs[3] = kQ - 1;

        if (!poly_compress_du10(small, &enc, &err)) {
            std::cerr << "small compress failed: " << err << std::endl;
            return 1;
        }

        const std::uint16_t t0 = compress_coeff_du10(small.coeffs[0]);
        const std::uint16_t t1 = compress_coeff_du10(small.coeffs[1]);
        const std::uint16_t t2 = compress_coeff_du10(small.coeffs[2]);
        const std::uint16_t t3 = compress_coeff_du10(small.coeffs[3]);

        const std::uint8_t e0 = static_cast<std::uint8_t>(t0 & 0xff);
        const std::uint8_t e1 = static_cast<std::uint8_t>(((t0 >> 8) & 0x03) | ((t1 & 0x3f) << 2));
        const std::uint8_t e2 = static_cast<std::uint8_t>(((t1 >> 6) & 0x0f) | ((t2 & 0x0f) << 4));
        const std::uint8_t e3 = static_cast<std::uint8_t>(((t2 >> 4) & 0x3f) | ((t3 & 0x03) << 6));
        const std::uint8_t e4 = static_cast<std::uint8_t>((t3 >> 2) & 0xff);

        if (enc[0] != e0 || enc[1] != e1 || enc[2] != e2 || enc[3] != e3 || enc[4] != e4) {
            std::cerr << "packing sanity check failed" << std::endl;
            return 1;
        }
    }

    std::cout << "[dna-pqcore-learn] poly compress du10 ok"
              << " compressed_bytes=" << kPolyCompressedBytesDu
              << std::endl;

    return 0;
}