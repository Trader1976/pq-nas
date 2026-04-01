#include "dna_mlkem_compress_du10.h"

namespace dnanexus::pqlearn::mlkem768 {

std::uint16_t compress_coeff_du10(std::int32_t x) {
    const std::int32_t c = mod_q(x);

    // Round c/q onto a 10-bit grid in [0, 1024), then wrap to 10 bits.
    const std::int32_t t = (((c << 10) + (kQ / 2)) / kQ) & 0x03ff;
    return static_cast<std::uint16_t>(t);
}

std::int16_t decompress_coeff_du10(std::uint16_t t) {
    const std::int32_t x =
        ((static_cast<std::int32_t>(t & 0x03ff) * kQ) + 512) >> 10;
    return static_cast<std::int16_t>(x);
}

bool poly_compress_du10(const Poly& p, std::vector<std::uint8_t>* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (!poly_is_canonical(p)) {
        if (err) *err = "poly_not_canonical";
        return false;
    }

    out->assign(kPolyCompressedBytesDu, 0);

    // Four 10-bit compressed coefficients -> 40 bits -> 5 bytes.
    for (std::size_t i = 0, j = 0; i < kN; i += 4, j += 5) {
        const std::uint16_t t0 = compress_coeff_du10(p.coeffs[i + 0]);
        const std::uint16_t t1 = compress_coeff_du10(p.coeffs[i + 1]);
        const std::uint16_t t2 = compress_coeff_du10(p.coeffs[i + 2]);
        const std::uint16_t t3 = compress_coeff_du10(p.coeffs[i + 3]);

        (*out)[j + 0] = static_cast<std::uint8_t>(t0 & 0xff);
        (*out)[j + 1] = static_cast<std::uint8_t>(((t0 >> 8) & 0x03) | ((t1 & 0x3f) << 2));
        (*out)[j + 2] = static_cast<std::uint8_t>(((t1 >> 6) & 0x0f) | ((t2 & 0x0f) << 4));
        (*out)[j + 3] = static_cast<std::uint8_t>(((t2 >> 4) & 0x3f) | ((t3 & 0x03) << 6));
        (*out)[j + 4] = static_cast<std::uint8_t>((t3 >> 2) & 0xff);
    }

    return true;
}

bool poly_decompress_du10(const std::vector<std::uint8_t>& in, Poly* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (in.size() != kPolyCompressedBytesDu) {
        if (err) *err = "bad_poly_compressed_du10_len";
        return false;
    }

    Poly p;
    poly_zero(&p);

    for (std::size_t i = 0, j = 0; i < kN; i += 4, j += 5) {
        const std::uint16_t b0 = static_cast<std::uint16_t>(in[j + 0]);
        const std::uint16_t b1 = static_cast<std::uint16_t>(in[j + 1]);
        const std::uint16_t b2 = static_cast<std::uint16_t>(in[j + 2]);
        const std::uint16_t b3 = static_cast<std::uint16_t>(in[j + 3]);
        const std::uint16_t b4 = static_cast<std::uint16_t>(in[j + 4]);

        const std::uint16_t t0 =
            static_cast<std::uint16_t>(b0 | ((b1 & 0x03) << 8));
        const std::uint16_t t1 =
            static_cast<std::uint16_t>((b1 >> 2) | ((b2 & 0x0f) << 6));
        const std::uint16_t t2 =
            static_cast<std::uint16_t>((b2 >> 4) | ((b3 & 0x3f) << 4));
        const std::uint16_t t3 =
            static_cast<std::uint16_t>((b3 >> 6) | (b4 << 2));

        p.coeffs[i + 0] = decompress_coeff_du10(t0);
        p.coeffs[i + 1] = decompress_coeff_du10(t1);
        p.coeffs[i + 2] = decompress_coeff_du10(t2);
        p.coeffs[i + 3] = decompress_coeff_du10(t3);
    }

    *out = p;
    return true;
}

} // namespace dnanexus::pqlearn::mlkem768