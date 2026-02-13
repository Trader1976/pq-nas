#include <sodium.h>
#include <stdio.h>

static void b64url(const unsigned char *bin, size_t bin_len, char *out, size_t out_max) {
    sodium_bin2base64(out, out_max, bin, bin_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];   // 32
    unsigned char sk[crypto_sign_SECRETKEYBYTES];   // 64
    crypto_sign_keypair(pk, sk);

    unsigned char cookie_key[32];
    randombytes_buf(cookie_key, sizeof(cookie_key));

    char pk_b64[128], sk_b64[256], ck_b64[128];
    b64url(pk, sizeof(pk), pk_b64, sizeof(pk_b64));
    b64url(sk, sizeof(sk), sk_b64, sizeof(sk_b64));
    b64url(cookie_key, sizeof(cookie_key), ck_b64, sizeof(ck_b64));

    printf("PQNAS_SERVER_PK_B64URL=%s\n", pk_b64);
    printf("PQNAS_SERVER_SK_B64URL=%s\n", sk_b64);
    printf("PQNAS_COOKIE_KEY_B64URL=%s\n", ck_b64);


    return 0;
}
