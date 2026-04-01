#include "dna_mlkem_poly_bytes.h"

namespace dnanexus::pqlearn::mlkem768 {

bool poly_to_bytes(const Poly& p, std::vector<std::uint8_t>* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (!poly_is_canonical(p)) {
        if (err) *err = "poly_not_canonical";
        return false;
    }

    out->assign(kPolyBytes, 0);

    // 256 coefficients -> 128 pairs -> 384 bytes
    for (std::size_t i = 0, j = 0; i < kN; i += 2, j += 3) {
        const std::uint16_t t0 = static_cast<std::uint16_t>(p.coeffs[i + 0]);
        const std::uint16_t t1 = static_cast<std::uint16_t>(p.coeffs[i + 1]);

        // Coefficients are canonical and q = 3329 < 2^12, so 12-bit packing is valid.
        (*out)[j + 0] = static_cast<std::uint8_t>(t0 & 0xff);
        (*out)[j + 1] = static_cast<std::uint8_t>(((t0 >> 8) & 0x0f) | ((t1 & 0x0f) << 4));
        (*out)[j + 2] = static_cast<std::uint8_t>((t1 >> 4) & 0xff);
    }

    return true;
}

bool poly_from_bytes(const std::vector<std::uint8_t>& in, Poly* out, std::string* err) {
    if (err) err->clear();
    if (!out) {
        if (err) *err = "output_null";
        return false;
    }

    if (in.size() != kPolyBytes) {
        if (err) *err = "bad_poly_bytes_len";
        return false;
    }

    Poly p;
    poly_zero(&p);

    for (std::size_t i = 0, j = 0; i < kN; i += 2, j += 3) {
        const std::uint16_t b0 = static_cast<std::uint16_t>(in[j + 0]);
        const std::uint16_t b1 = static_cast<std::uint16_t>(in[j + 1]);
        const std::uint16_t b2 = static_cast<std::uint16_t>(in[j + 2]);

        const std::uint16_t t0 = static_cast<std::uint16_t>(b0 | ((b1 & 0x0f) << 8));
        const std::uint16_t t1 = static_cast<std::uint16_t>((b1 >> 4) | (b2 << 4));

        if (!coeff_is_canonical(t0) || !coeff_is_canonical(t1)) {
            if (err) *err = "decoded_coeff_not_canonical";
            return false;
        }

        p.coeffs[i + 0] = static_cast<std::int16_t>(t0);
        p.coeffs[i + 1] = static_cast<std::int16_t>(t1);
    }

    *out = p;
    return true;
}

} // namespace dnanexus::pqlearn::mlkem768