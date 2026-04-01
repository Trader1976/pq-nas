#include "dna_mlkem_polyvec_compress_du10.h"
#include "dna_mlkem_compress_du10.h"

#include <iostream>
#include <vector>

int main() {
    using namespace dnanexus::pqlearn::mlkem768;

    PolyVec v;
    polyvec_zero(&v);

    // Deterministic canonical pattern across all 3 polynomials.
    for (std::size_t p = 0; p < kK; ++p) {
        for (std::size_t i = 0; i < kN; ++i) {
            v.polys[p].coeffs[i] = coeff_normalize(
                static_cast<std::int32_t>(p * 2000 + i * 41 + 33));
        }
    }

    if (!polyvec_is_canonical(v)) return 1;

    std::vector<std::uint8_t> enc;
    std::string err;
    if (!polyvec_compress_du10(v, &enc, &err)) {
        std::cerr << "polyvec_compress_du10 failed: " << err << std::endl;
        return 1;
    }

    if (enc.size() != kPolyVecCompressedBytesDu) {
        std::cerr << "compressed polyvec size mismatch" << std::endl;
        return 1;
    }

    PolyVec dec;
    if (!polyvec_decompress_du10(enc, &dec, &err)) {
        std::cerr << "polyvec_decompress_du10 failed: " << err << std::endl;
        return 1;
    }

    if (!polyvec_is_canonical(dec)) {
        std::cerr << "decompressed polyvec not canonical" << std::endl;
        return 1;
    }

    // Compression is lossy, so compare compressed stability rather than v == dec.
    std::vector<std::uint8_t> enc2;
    if (!polyvec_compress_du10(dec, &enc2, &err)) {
        std::cerr << "recompress failed: " << err << std::endl;
        return 1;
    }

    if (enc != enc2) {
        std::cerr << "compressed polyvec roundtrip not stable" << std::endl;
        return 1;
    }

    // Wrong length must fail.
    {
        std::vector<std::uint8_t> short_in(kPolyVecCompressedBytesDu - 1, 0);
        PolyVec tmp;
        if (polyvec_decompress_du10(short_in, &tmp, &err)) {
            std::cerr << "expected compressed polyvec length rejection" << std::endl;
            return 1;
        }
        if (err != "bad_polyvec_compressed_du10_len") {
            std::cerr << "unexpected compressed polyvec length error: " << err << std::endl;
            return 1;
        }
    }

    // Non-canonical polyvec must not compress.
    {
        PolyVec bad = v;
        bad.polys[2].coeffs[27] = static_cast<std::int16_t>(kQ);
        if (polyvec_compress_du10(bad, &enc, &err)) {
            std::cerr << "expected non-canonical polyvec compress rejection" << std::endl;
            return 1;
        }
        if (err != "polyvec_not_canonical") {
            std::cerr << "unexpected non-canonical polyvec compress error: " << err << std::endl;
            return 1;
        }
    }

    // Small concatenation sanity check:
    // compressing each polynomial separately and concatenating should match
    // the whole polyvec-compressed output.
    {
        PolyVec small;
        polyvec_zero(&small);

        for (std::size_t i = 0; i < kN; ++i) {
            small.polys[0].coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i));
            small.polys[1].coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i * 2));
            small.polys[2].coeffs[i] = coeff_normalize(static_cast<std::int32_t>(i * 3));
        }

        std::vector<std::uint8_t> whole;
        if (!polyvec_compress_du10(small, &whole, &err)) {
            std::cerr << "small polyvec compress failed: " << err << std::endl;
            return 1;
        }

        std::vector<std::uint8_t> p0, p1, p2;
        if (!poly_compress_du10(small.polys[0], &p0, &err)) return 1;
        if (!poly_compress_du10(small.polys[1], &p1, &err)) return 1;
        if (!poly_compress_du10(small.polys[2], &p2, &err)) return 1;

        if (whole.size() != p0.size() + p1.size() + p2.size()) {
            std::cerr << "concatenation size mismatch" << std::endl;
            return 1;
        }

        for (std::size_t i = 0; i < p0.size(); ++i) {
            if (whole[i] != p0[i]) {
                std::cerr << "concat mismatch in poly 0" << std::endl;
                return 1;
            }
        }
        for (std::size_t i = 0; i < p1.size(); ++i) {
            if (whole[p0.size() + i] != p1[i]) {
                std::cerr << "concat mismatch in poly 1" << std::endl;
                return 1;
            }
        }
        for (std::size_t i = 0; i < p2.size(); ++i) {
            if (whole[p0.size() + p1.size() + i] != p2[i]) {
                std::cerr << "concat mismatch in poly 2" << std::endl;
                return 1;
            }
        }
    }

    std::cout << "[dna-pqcore-learn] polyvec compress du10 ok"
              << " k=" << kK
              << " compressed_bytes=" << kPolyVecCompressedBytesDu
              << std::endl;

    return 0;
}