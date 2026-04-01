#pragma once

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/rand.h>

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX dnanexus_mlkem768
#define MLK_CONFIG_NO_SUPERCOP
#define MLK_CONFIG_CUSTOM_RANDOMBYTES

#if !defined(__ASSEMBLER__)
static inline int mlk_randombytes(uint8_t *ptr, size_t len) {
    if (!ptr && len != 0) return -1;
    if (len > (size_t)INT_MAX) return -1;
    if (len == 0) return 0;
    return RAND_bytes((unsigned char*)ptr, (int)len) == 1 ? 0 : -1;
}
#endif