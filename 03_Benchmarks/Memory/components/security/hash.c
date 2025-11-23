#include "hash.h"

// static const char *LOG_TAG = "HASH";

void derive_key_from_shared_secret(
    const unsigned char *input_key_material,
    size_t               ikm_len,
    const unsigned char *salt_prefix,
    size_t               salt_len,
    const unsigned char *info,
    size_t               info_len,
    unsigned char       *output_key,
    size_t               output_key_len
) {
    const mbedtls_md_info_t *md_info     = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_hkdf(
        md_info,
        salt_prefix,
        salt_len,
        input_key_material,
        ikm_len,
        info,
        info_len,
        output_key,
        output_key_len
    );
}

void compute_hmac_sha256(
    const unsigned char *data,
    size_t               data_len,
    unsigned char       *hmac_output,
    const unsigned char *hmac_key
) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t      ctx;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1);  // Enable HMAC
    mbedtls_md_hmac_starts(&ctx, hmac_key, AES_KEY_SIZE);
    mbedtls_md_hmac_update(&ctx, data, data_len);
    mbedtls_md_hmac_finish(&ctx, hmac_output);
    mbedtls_md_free(&ctx);
}

int verify_hmac(
    const unsigned char *received_hmac,
    const unsigned char *ciphertext,
    size_t               padded_len,
    const unsigned char *hmac_key
) {
    unsigned char calculated_hmac[HMAC_SIZE];

    compute_hmac_sha256(ciphertext, padded_len, calculated_hmac, hmac_key);
    return memcmp(received_hmac, calculated_hmac, HMAC_SIZE) == 0;
}
