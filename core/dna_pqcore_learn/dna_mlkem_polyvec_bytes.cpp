#include "dna_mlkem_polyvec_bytes.h"
#include "dna_mlkem_poly_bytes.h"

namespace dnanexus::pqlearn::mlkem768 {

    bool polyvec_to_bytes(const PolyVec& v, std::vector<std::uint8_t>* out, std::string* err) {
        if (err) err->clear();
        if (!out) {
            if (err) *err = "output_null";
            return false;
        }

        if (!polyvec_is_canonical(v)) {
            if (err) *err = "polyvec_not_canonical";
            return false;
        }

        out->assign(kPolyVecBytes, 0);

        for (std::size_t i = 0; i < kK; ++i) {
            std::vector<std::uint8_t> enc_poly;
            std::string poly_err;
            if (!poly_to_bytes(v.polys[i], &enc_poly, &poly_err)) {
                if (err) *err = poly_err.empty() ? "poly_to_bytes_failed" : poly_err;
                return false;
            }
            if (enc_poly.size() != kPolyBytes) {
                if (err) *err = "poly_bytes_size_mismatch";
                return false;
            }

            const std::size_t off = i * kPolyBytes;
            for (std::size_t j = 0; j < kPolyBytes; ++j) {
                (*out)[off + j] = enc_poly[j];
            }
        }

        return true;
    }

    bool polyvec_from_bytes(const std::vector<std::uint8_t>& in, PolyVec* out, std::string* err) {
        if (err) err->clear();
        if (!out) {
            if (err) *err = "output_null";
            return false;
        }

        if (in.size() != kPolyVecBytes) {
            if (err) *err = "bad_polyvec_bytes_len";
            return false;
        }

        PolyVec v;
        polyvec_zero(&v);

        for (std::size_t i = 0; i < kK; ++i) {
            const std::size_t off = i * kPolyBytes;
            std::vector<std::uint8_t> enc_poly(kPolyBytes, 0);
            for (std::size_t j = 0; j < kPolyBytes; ++j) {
                enc_poly[j] = in[off + j];
            }

            std::string poly_err;
            if (!poly_from_bytes(enc_poly, &v.polys[i], &poly_err)) {
                if (err) *err = poly_err.empty() ? "poly_from_bytes_failed" : poly_err;
                return false;
            }
        }

        *out = v;
        return true;
    }

} // namespace dnanexus::pqlearn::mlkem768