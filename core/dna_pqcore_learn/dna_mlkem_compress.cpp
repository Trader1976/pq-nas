#include "dna_mlkem_compress.h"

namespace dnanexus::pqlearn::mlkem768 {

std::uint8_t compress_coeff_d4(std::int32_t x) {
    const std::int32_t c = mod_q(x);

    // Round c/q onto a 4-bit grid in [0, 16), then wrap to 4 bits.
    // This matches the usual ML-KEM / Kyber-style coefficient compression shape.
    const std::int32_t t = (((c << 4) + (kQ / 2)) / kQ) & 0x0f;
    return static_cast<std::uint8_t>(t);
}

std::int16_t decompress_coeff_d4(std::uint8_t t) {
    const std::int32_t x =
        ((static_cast<std::int32_t>(t & 0x0f) * kQ) + 8) >> 4;
    return static_cast<std::int16_t>(x);
}

bool poly_compress_dv4(const Poly& p, std::vector<std::uint8_t>* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (!poly_is_canonical(p)) {
        if (err) *err = "poly_not_canonical";
        return false;
    }

    out->assign(kPolyCompressedBytesDv, 0);

    // Two 4-bit compressed coefficients per byte.
    for (std::size_t i = 0, j = 0; i < kN; i += 2, ++j) {
        const std::uint8_t t0 = compress_coeff_d4(p.coeffs[i + 0]);
        const std::uint8_t t1 = compress_coeff_d4(p.coeffs[i + 1]);

        (*out)[j] = static_cast<std::uint8_t>((t0 & 0x0f) | ((t1 & 0x0f) << 4));
    }

    return true;
}

bool poly_decompress_dv4(const std::vector<std::uint8_t>& in, Poly* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (in.size() != kPolyCompressedBytesDv) {
        if (err) *err = "bad_poly_compressed_dv4_len";
        return false;
    }

    Poly p;
    poly_zero(&p);

    for (std::size_t i = 0, j = 0; i < kN; i += 2, ++j) {
        const std::uint8_t b = in[j];
        const std::uint8_t t0 = static_cast<std::uint8_t>(b & 0x0f);
        const std::uint8_t t1 = static_cast<std::uint8_t>((b >> 4) & 0x0f);

        p.coeffs[i + 0] = decompress_coeff_d4(t0);
        p.coeffs[i + 1] = decompress_coeff_d4(t1);
    }

    *out = p;
    return true;
}

} // namespace dnanexus::pqlearn::mlkem768