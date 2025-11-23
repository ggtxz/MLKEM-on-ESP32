#pragma once
#include "mbedtls/aes.h"
#include <common.h>

size_t aes_encrypt_ctr(
    const char *plaintext, 
    unsigned char **cipher_output, 
    const unsigned char *aes_key, 
    const unsigned char *ctr_nonce);

void aes_decrypt_ctr(
    const unsigned char *ciphertext,
    size_t padded_len, 
    uint16_t original_len, 
    unsigned char **plaintext_out, 
    const unsigned char *aes_key, 
    const unsigned char *ctr_nonce);