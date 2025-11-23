#include "uart.h"
#include "hash.h"
#include "encryption.h"
#include <esp_check.h>
#include <time.h>
#include "rc522.h"
#include "driver/rc522_spi.h"
#include "picc/rc522_mifare.h"
#include "kem512.h"
#include "esp_random.h"

static const char *TAG = "ESP-A";

#define RC522_SPI_BUS_GPIO_MISO    (25)
#define RC522_SPI_BUS_GPIO_MOSI    (23)
#define RC522_SPI_BUS_GPIO_SCLK    (19)
#define RC522_SCANNER_GPIO_SDA     (22)
#define RC522_SCANNER_GPIO_RST     (-1)

uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];

const unsigned char salt_hkdf_encription[]     = "encryption";
const unsigned char salt_hkdf_authentication[] = "authentication";
const unsigned char info_enc[]                 = "ESP32-MLKEM-AES-KEY";
const unsigned char info_mac[]                 = "ESP32-MLKEM-HMAC-KEY";
const unsigned char ctr_nonce[]                = "ESP32-MLKEM-AES-CTR";

uint8_t aes_key[AES_KEY_SIZE];
uint8_t hmac_key[HMAC_KEY_SIZE];

static rc522_spi_config_t driver_config = {
    .host_id = SPI3_HOST,
    .bus_config = &(spi_bus_config_t){
        .miso_io_num = RC522_SPI_BUS_GPIO_MISO,
        .mosi_io_num = RC522_SPI_BUS_GPIO_MOSI,
        .sclk_io_num = RC522_SPI_BUS_GPIO_SCLK,
    },
    .dev_config = {
        .spics_io_num = RC522_SCANNER_GPIO_SDA,
    },
    .rst_io_num = RC522_SCANNER_GPIO_RST,
};

static rc522_driver_handle_t driver;
static rc522_handle_t scanner;

static esp_err_t read(rc522_handle_t scanner, rc522_picc_t *picc, char *msg)
{
    const uint8_t block_address = 4;

    rc522_mifare_key_t key = {
        .value = { RC522_MIFARE_KEY_VALUE_DEFAULT },
    };

    ESP_RETURN_ON_ERROR(
        rc522_mifare_auth(scanner, picc, block_address, &key),
        TAG,
        "auth fail"
    );

    uint8_t read_buffer[RC522_MIFARE_BLOCK_SIZE];

    ESP_RETURN_ON_ERROR(
        rc522_mifare_read(scanner, picc, block_address, read_buffer),
        TAG,
        "read fail"
    );

    memcpy(msg, read_buffer, RC522_MIFARE_BLOCK_SIZE);
    msg[16] = '\0';

    return ESP_OK;
}

void send_pk_task(void *pvParameters)
{
    uint8_t coins_keypair[64];
    esp_fill_random(coins_keypair, sizeof(coins_keypair));

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, coins_keypair);

    uart_write_bytes(
        UART_PORT,
        (const char *)pk,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
    );

    vTaskDelete(NULL);
}

void dec_task(void *pvParameters)
{
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);

    vTaskDelete(NULL);
}

static void on_picc_state_changed(
    void *arg,
    esp_event_base_t base,
    int32_t event_id,
    void *data
)
{
    rc522_picc_state_changed_event_t *event = (rc522_picc_state_changed_event_t *)data;
    rc522_picc_t *picc = event->picc;
    char msg[17];

    if (picc->state != RC522_PICC_STATE_ACTIVE) {
        return;
    }

    if (!rc522_mifare_type_is_classic_compatible(picc->type)) {
        ESP_LOGW(TAG, "Card is not supported by this example");
        return;
    }
    
    if (read(scanner, picc, msg) == ESP_OK) {
        ESP_LOGI(TAG, "Read success, message: %s\n\n", msg);
    } else {
        ESP_LOGE(TAG, "Read failed");
    }

    if (uart_threeway_handshake_init() == 0) {
        vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
        ESP_LOGI(TAG, "UART Handshake successful\n\n");
    } else {
        ESP_LOGE(TAG, "UART Handshake failed");
        return;
    }

    xTaskCreatePinnedToCore(
        send_pk_task,
        "pk_creation",
        32768,
        NULL,
        5,
        NULL,
        1
    );

    uart_read_bytes(
        UART_PORT,
        ct,
        PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        pdMS_TO_TICKS(2000)
    );

    xTaskCreatePinnedToCore(
        dec_task,
        "dec",
        32768,
        NULL,
        5,
        NULL,
        1
    );

    vTaskDelay(pdMS_TO_TICKS(500));

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

    char hmac_key_str[3 * HMAC_KEY_SIZE + 1];
    size_t pos_hmac = 0;

    for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
        pos_hmac += sprintf(&hmac_key_str[pos_hmac], "%02X ", hmac_key[i]);
    }
    hmac_key_str[pos_hmac] = '\0';
    ESP_LOGI(TAG, "HMAC_KEY: %s\n\n", hmac_key_str);

    unsigned char *ciphertext = NULL;

    size_t cipher_len = aes_encrypt_ctr(
        msg,
        &ciphertext,
        aes_key,
        ctr_nonce
    );

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Encrypted message using AES");

    char ct_str[3 * cipher_len + 1];
    size_t pos_ct = 0;

    for (size_t i = 0; i < cipher_len; i++) {
        pos_ct += sprintf(&ct_str[pos_ct], "%02X ", ciphertext[i]);
    }

    ct_str[pos_ct] = '\0';

    ESP_LOGI(TAG, "CT: %s\n\n", ct_str);

    unsigned char hmac_output[HMAC_SIZE];

    compute_hmac_sha256(
        ciphertext,
        cipher_len,
        hmac_output,
        hmac_key
    );

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Message signed via HMAC-SHA256");

    char hmac_str[3 * HMAC_SIZE + 1];
    size_t pos_hmac_str = 0;

    for (int i = 0; i < HMAC_SIZE; i++) {
        pos_hmac_str += sprintf(&hmac_str[pos_hmac_str], "%02X ", hmac_output[i]);
    }

    hmac_str[pos_hmac_str] = '\0';

    ESP_LOGI(TAG, "HMAC: %s\n\n", hmac_str);

    frame_t frame;
    frame.frame_type = FRAME_TYPE_DATA;
    frame.payload_len = cipher_len;
    frame.payload = ciphertext;
    memcpy(frame.hmac, hmac_output, HMAC_SIZE);

    uart_send_data(&frame);

    vTaskDelay(pdMS_TO_TICKS(4000)); // REMOVE
    ESP_LOGI(TAG, "Data sent over UART");

    free(ciphertext);

    if (rc522_mifare_deauth(scanner, picc) != ESP_OK) {
        ESP_LOGW(TAG, "Deauth failed");
    }
}

void app_main(void)
{
    uart_setup();
    srand(time(NULL));

    rc522_spi_create(&driver_config, &driver);
    rc522_driver_install(driver);

    rc522_config_t scanner_config = {
        .driver = driver,
    };
    rc522_create(&scanner_config, &scanner);
    rc522_register_events(scanner, RC522_EVENT_PICC_STATE_CHANGED, on_picc_state_changed, NULL);
    rc522_start(scanner);
}
