#pragma once
#include "common.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

static const char SALT_PREFIX[] = "Pseudo-Salt";

void derive_key_from_shared_secret(
    const unsigned char *input_key_material, size_t ikm_len,
    const unsigned char *salt_prefix,
    size_t               salt_len,
    const unsigned char *info, size_t info_len,
    unsigned char *output_key, size_t output_key_len);

void compute_hmac_sha256(
    const unsigned char *data, size_t data_len, 
    unsigned char *hmac_output, 
    const unsigned char *hmac_key);

int verify_hmac(
    const unsigned char *received_hmac, 
    const unsigned char *ciphertext, 
    size_t padded_len,
    const unsigned char *hmac_key);
