#include "dna_mlkem_polyvec_compress_du10.h"
#include "dna_mlkem_compress_du10.h"

namespace dnanexus::pqlearn::mlkem768 {

bool polyvec_compress_du10(const PolyVec& v, std::vector<std::uint8_t>* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (!polyvec_is_canonical(v)) {
        if (err) *err = "polyvec_not_canonical";
        return false;
    }

    out->assign(kPolyVecCompressedBytesDu, 0);

    for (std::size_t i = 0; i < kK; ++i) {
        std::vector<std::uint8_t> enc_poly;
        std::string poly_err;
        if (!poly_compress_du10(v.polys[i], &enc_poly, &poly_err)) {
            if (err) *err = poly_err.empty() ? "poly_compress_du10_failed" : poly_err;
            return false;
        }
        if (enc_poly.size() != kPolyCompressedBytesDu) {
            if (err) *err = "poly_compressed_du10_size_mismatch";
            return false;
        }

        const std::size_t off = i * kPolyCompressedBytesDu;
        for (std::size_t j = 0; j < kPolyCompressedBytesDu; ++j) {
            (*out)[off + j] = enc_poly[j];
        }
    }

    return true;
}

bool polyvec_decompress_du10(const std::vector<std::uint8_t>& in, PolyVec* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (in.size() != kPolyVecCompressedBytesDu) {
        if (err) *err = "bad_polyvec_compressed_du10_len";
        return false;
    }

    PolyVec v;
    polyvec_zero(&v);

    for (std::size_t i = 0; i < kK; ++i) {
        const std::size_t off = i * kPolyCompressedBytesDu;
        std::vector<std::uint8_t> enc_poly(kPolyCompressedBytesDu, 0);
        for (std::size_t j = 0; j < kPolyCompressedBytesDu; ++j) {
            enc_poly[j] = in[off + j];
        }

        std::string poly_err;
        if (!poly_decompress_du10(enc_poly, &v.polys[i], &poly_err)) {
            if (err) *err = poly_err.empty() ? "poly_decompress_du10_failed" : poly_err;
            return false;
        }
    }

    *out = v;
    return true;
}

} // namespace dnanexus::pqlearn::mlkem768