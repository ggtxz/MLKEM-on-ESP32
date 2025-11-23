#include "encryption.h"

static const char *LOG_TAG = "ENCRYPTION";

size_t aes_encrypt_ctr( // agora CTR por dentro
    const char           *plaintext,
    unsigned char       **cipher_output,
    const unsigned char  *aes_key,
    const unsigned char  *ctr_nonce  // usado como nonce_counter no CTR
) {
    size_t input_len = strlen(plaintext);

    // Em CTR não tem padding: cifra tem o mesmo tamanho da entrada
    *cipher_output = calloc(input_len, sizeof(unsigned char));
    if (*cipher_output == NULL) {
        ESP_LOGE(LOG_TAG, "Failed to allocate memory for ciphertext");
        return 0;
    }

    mbedtls_aes_context aes;
    unsigned char nonce_counter[AES_BLOCK_SIZE]; // 16 bytes
    unsigned char stream_block[AES_BLOCK_SIZE];  // buffer interno do CTR
    size_t nc_off = 0;

    memcpy(nonce_counter, ctr_nonce, AES_BLOCK_SIZE); // agora é o nonce+counter
    memset(stream_block, 0, sizeof(stream_block));

    mbedtls_aes_init(&aes);

    // AES-128 → 128 bits
    int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    if (ret != 0) {
        ESP_LOGE(LOG_TAG, "mbedtls_aes_setkey_enc failed: %d", ret);
        mbedtls_aes_free(&aes);
        free(*cipher_output);
        *cipher_output = NULL;
        return 0;
    }

    ret = mbedtls_aes_crypt_ctr(
        &aes,
        input_len,
        &nc_off,
        nonce_counter,
        stream_block,
        (const unsigned char *) plaintext, // cast do char* para unsigned char*
        *cipher_output
    );

    mbedtls_aes_free(&aes);

    if (ret != 0) {
        ESP_LOGE(LOG_TAG, "mbedtls_aes_crypt_ctr failed: %d", ret);
        free(*cipher_output);
        *cipher_output = NULL;
        return 0;
    }

    // retorna o tamanho real da cifra
    return input_len;
}

void aes_decrypt_ctr( // agora CTR por dentro
    const unsigned char  *ciphertext,
    size_t                padded_len,   // aqui passa a ser o tamanho real da cifra
    uint16_t              original_len, // tamanho original do texto (para o '\0')
    unsigned char       **plaintext_out,
    const unsigned char  *aes_key,
    const unsigned char  *ctr_nonce       // usado como nonce_counter no CTR
) {
    // espaço +1 para terminador NUL
    *plaintext_out = calloc(padded_len + 1, sizeof(unsigned char));
    if (*plaintext_out == NULL) {
        ESP_LOGE(LOG_TAG, "Failed to allocate memory for plaintext");
        return;
    }

    mbedtls_aes_context aes;
    unsigned char nonce_counter[AES_BLOCK_SIZE];
    unsigned char stream_block[AES_BLOCK_SIZE];
    size_t nc_off = 0;

    memcpy(nonce_counter, ctr_nonce, AES_BLOCK_SIZE);
    memset(stream_block, 0, sizeof(stream_block));

    mbedtls_aes_init(&aes);

    // Em CTR sempre se usa setkey_enc, até para "decriptar"
    int ret = mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    if (ret != 0) {
        ESP_LOGE(LOG_TAG, "mbedtls_aes_setkey_enc failed: %d", ret);
        mbedtls_aes_free(&aes);
        free(*plaintext_out);
        *plaintext_out = NULL;
        return;
    }

    ret = mbedtls_aes_crypt_ctr(
        &aes,
        padded_len,
        &nc_off,
        nonce_counter,
        stream_block,
        ciphertext,
        *plaintext_out
    );

    mbedtls_aes_free(&aes);

    if (ret != 0) {
        ESP_LOGE(LOG_TAG, "mbedtls_aes_crypt_ctr failed: %d", ret);
        free(*plaintext_out);
        *plaintext_out = NULL;
        return;
    }

    // Garante término em '\0' usando original_len
    if (original_len <= padded_len) {
        (*plaintext_out)[original_len] = '\0';
    } else {
        // fallback se algo vier inconsistente
        (*plaintext_out)[padded_len] = '\0';
    }
}
