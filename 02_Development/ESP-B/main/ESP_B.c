#include <stdio.h>
#include "uart.h"
#include "encryption.h"
#include "kem512.h"
#include "hash.h"
#include "esp_random.h"

static const char *TAG = "ESP-B";

uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];

const unsigned char salt_hkdf_encription[]     = "encryption";
const unsigned char salt_hkdf_authentication[] = "authentication";
const unsigned char info_enc[]                 = "ESP32-MLKEM-AES-KEY";
const unsigned char info_mac[]                 = "ESP32-MLKEM-HMAC-KEY";
const unsigned char ctr_nonce[]                = "ESP32-MLKEM-AES-CTR";

uint8_t aes_key[AES_KEY_SIZE];
uint8_t hmac_key[HMAC_KEY_SIZE];

void wait_for_comm(void)
{
    while (1) {
        if (uart_threeway_handshake_receive() == 0) {
            break;
        }
    }
}

void send_ct_task(void *pvParameters)
{
    uint8_t coins_enc[32];
    esp_fill_random(coins_enc, sizeof(coins_enc));

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins_enc);

    uart_write_bytes(
        UART_PORT,
        (const char *)ct,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
    );

    vTaskDelete(NULL);
}

void app_main(void)
{

    uart_setup();
    ESP_LOGI(TAG, "Waiting for communication...\n\n");

    wait_for_comm();

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Communication established!\n\n");

    uart_read_bytes(
        UART_PORT,
        pk,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
        pdMS_TO_TICKS(2000)
    );

    xTaskCreatePinnedToCore(
        send_ct_task,
        "ct_creation",
        32768,
        NULL,
        5,
        NULL,
        1
    );

    vTaskDelay(pdMS_TO_TICKS(1000));

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Secret obtained through MLKEM");

    char ss_str[3 * PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES + 1];
    size_t pos_ss = 0;

    for (size_t i = 0; i < PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES; i++) {
        pos_ss += sprintf(&ss_str[pos_ss], "%02X ", ss[i]);
    }
    ss_str[pos_ss] = '\0';
    ESP_LOGI(TAG, "SS: %s\n\n", ss_str);

    derive_key_from_shared_secret(
        ss,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES,
        salt_hkdf_encription,
        sizeof(salt_hkdf_encription),
        info_enc,
        sizeof(info_enc),
        aes_key,
        AES_KEY_SIZE
    );

    derive_key_from_shared_secret(
        ss,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES,
        salt_hkdf_authentication,
        sizeof(salt_hkdf_authentication),
        info_mac,
        sizeof(info_mac),
        hmac_key,
        HMAC_KEY_SIZE
    );

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Keys derived from the secret using HKDF");

    char aes_str[3 * AES_KEY_SIZE + 1];
    size_t pos_aes = 0;

    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        pos_aes += sprintf(&aes_str[pos_aes], "%02X ", aes_key[i]);
    }
    aes_str[pos_aes] = '\0';
    ESP_LOGI(TAG, "AES_KEY: %s", aes_str);

    char hmac_str[3 * HMAC_KEY_SIZE + 1];
    size_t pos_hmac = 0;

    for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
        pos_hmac += sprintf(&hmac_str[pos_hmac], "%02X ", hmac_key[i]);
    }
    hmac_str[pos_hmac] = '\0';
    ESP_LOGI(TAG, "HMAC_KEY: %s\n\n", hmac_str);

    vTaskDelay(pdMS_TO_TICKS(2000));

    frame_t *frame = calloc(1, sizeof(frame_t));

    while (1) {
        int ret = uart_read_data(frame);
        if (ret == 0) {
            break;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Data received via UART\n\n");

    int hamc_ret = verify_hmac(
        frame->hmac,
        frame->payload,
        frame->payload_len,
        hmac_key
    );

    if (!hamc_ret) {
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "HMAC verification success\n\n");

    unsigned char *plaintext_out = NULL;

    aes_decrypt_ctr(
        frame->payload,
        frame->payload_len,
        frame->payload_len,
        &plaintext_out,
        aes_key,
        ctr_nonce
    );

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Decrypted message: %s", plaintext_out);

    free(frame);
}
