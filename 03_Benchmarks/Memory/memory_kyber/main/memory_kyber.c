// mem_heap_peak_kyber.c — Medição de pico de HEAP e STACK + CSV + Wi-Fi/HTTP
// Fluxo:
//   app_main -> init NVS + SPIFFS -> cria task_bench (CPU1)
//   task_bench:
//      • aquecimento 100 iterações
//      • benchmark 1000 iterações (keygen+enc+dec)
//      • mede pico de heap e stack
//      • escreve CSV com UMA linha de resultado
//      • liga Wi-Fi e expõe o CSV via HTTP

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_heap_caps.h"

#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "esp_vfs.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"

#include "kem1024.h"  // PQCLEAN_MLKEM1024_CLEAN_crypto_kem_*
#include "coins.h"    // COINS_KEYPAIR[1000][64], COINS_ENC[1000][32]

// ===== Configurações gerais =====

static const char *TAG = "MEM_HEAP_PEAK";

#define WIFI_SSID  "VIVOFIBRA-8991"
#define WIFI_PASS  "FaMaGu@24!"

#define CSV_PATH   "/spiffs/mem_mlkem1024.csv"

#define WARMUP_ITERS  100
#define BENCH_ITERS   1000

// Tamanho de stack da task em BYTES (deve casar com xTaskCreatePinnedToCore)
#define TASK_STACK   (64 * 1024)

// ===== Wi-Fi (station) =====

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT &&
               event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Wi-Fi desconectado, tentando reconectar...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT &&
               event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "Wi-Fi conectado, IP obtido.");
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               ESP_EVENT_ANY_ID,
                                               &wifi_event_handler,
                                               NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,
                                               IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler,
                                               NULL));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID,
            sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, WIFI_PASS,
            sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando ao Wi-Fi...");

    xEventGroupWaitBits(s_wifi_event_group,
                        WIFI_CONNECTED_BIT,
                        pdFALSE,
                        pdFALSE,
                        portMAX_DELAY);

    ESP_LOGI(TAG, "Wi-Fi conectado, pronto para iniciar HTTP server.");
}

// ===== HTTP server (serve o CSV) =====

static esp_err_t csv_get_handler(httpd_req_t *req)
{
    FILE *f = fopen(CSV_PATH, "r");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV (%s) para leitura", CSV_PATH);
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/csv");

    char buf[128];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) {
            fclose(f);
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0); // termina resposta

    ESP_LOGI(TAG, "CSV enviado ao cliente.");
    return ESP_OK;
}

static httpd_handle_t start_file_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    esp_err_t ret = httpd_start(&server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao iniciar HTTP server (%s)", esp_err_to_name(ret));
        return NULL;
    }

    httpd_uri_t csv_uri = {
        .uri       = "/mem_mlkem1024.csv",
        .method    = HTTP_GET,
        .handler   = csv_get_handler,
        .user_ctx  = NULL
    };

    httpd_register_uri_handler(server, &csv_uri);
    ESP_LOGI(TAG,
             "HTTP server iniciado. Acesse http://<IP>%s para baixar o CSV.",
             csv_uri.uri);

    return server;
}

// ===== SPIFFS =====

static void init_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = NULL,
        .max_files              = 4,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao montar SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "SPIFFS montado, total=%d, usado=%d",
                 (int) total, (int) used);
    }
}

// ===== Helpers de medição de memória =====

// Pico de uso da stack da task (em bytes)
static inline size_t stack_used_peak_bytes(void)
{
    UBaseType_t words_min_free = uxTaskGetStackHighWaterMark(NULL);
    size_t bytes_min_free = (size_t)words_min_free * sizeof(StackType_t);
    return (TASK_STACK - bytes_min_free);
}

// Pico de uso de heap via queda do heap livre
typedef struct {
    size_t free_start;
    size_t min_free_end;
} heap_scope_t;

static inline void heap_scope_begin(heap_scope_t *s)
{
    s->free_start = heap_caps_get_free_size(MALLOC_CAP_8BIT);
}

static inline void heap_scope_end(heap_scope_t *s)
{
    s->min_free_end = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
}

static inline size_t heap_peak_bytes(const heap_scope_t *s)
{
    if (s->free_start >= s->min_free_end) {
        return s->free_start - s->min_free_end;
    }
    return 0;
}

// ===== CSV =====

static esp_err_t write_csv_peaks(size_t heap_peak_B, size_t stack_peak_B)
{
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV (%s) para escrita", CSV_PATH);
        return ESP_FAIL;
    }

    // Apenas pico de cada memória (uma linha de dados)
    fprintf(f, "alg,heap_peak_B,stack_peak_B\n");
    fprintf(f, "ML-KEM-1024,%zu,%zu\n", heap_peak_B, stack_peak_B);

    fclose(f);
    ESP_LOGI(TAG, "CSV gravado em %s", CSV_PATH);
    return ESP_OK;
}

// ===== Task de benchmark (CPU1) =====

static void task_bench(void *arg)
{
    // Buffers Kyber
    uint8_t pk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ss1[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
    uint8_t ct[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];

    // Escopo de heap para medir pico de uso do algoritmo
    heap_scope_t hs;
    heap_scope_begin(&hs);

    // Aquecimento
    ESP_LOGI(TAG, "Aquecimento de %d iterações...", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        int idx = i % 1000;
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk,
                                                          COINS_KEYPAIR[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss1, pk,
                                                      COINS_ENC[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);
        if ((i & 31) == 0) {
            vTaskDelay(0);
        }
    }

    // Benchmark principal
    ESP_LOGI(TAG, "Benchmark de %d iterações...", BENCH_ITERS);
    for (int i = 0; i < BENCH_ITERS; i++) {
        int idx = i % 1000;
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk,
                                                          COINS_KEYPAIR[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss1, pk,
                                                      COINS_ENC[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);
        if ((i & 31) == 0) {
            vTaskDelay(0);
        }
    }

    // Fecha escopo de heap e obtém picos
    heap_scope_end(&hs);
    size_t heap_peak_B  = heap_peak_bytes(&hs);
    size_t stack_peak_B = stack_used_peak_bytes();

    ESP_LOGI(TAG, "Pico de uso de HEAP [B]  = %zu", heap_peak_B);
    ESP_LOGI(TAG, "Pico de uso de STACK [B] = %zu", stack_peak_B);

    // Linha “máquina” para log (única, sem linhas por iteração)
    printf("HEAP_RESULT,ALG=ML-KEM-1024,"
           "HEAP_PEAK_B=%zu,STACK_PEAK_B=%zu\n",
           heap_peak_B, stack_peak_B);

    // Grava CSV (apenas picos)
    ESP_ERROR_CHECK(write_csv_peaks(heap_peak_B, stack_peak_B));

    // Liga Wi-Fi e inicia HTTP server para disponibilizar o CSV
    wifi_init_sta();
    start_file_server();

    // Task fica viva só para manter HTTP server rodando
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ===== app_main =====

void app_main(void)
{
    // Inicia NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Monta SPIFFS
    init_spiffs();

    // Cria task_bench na CPU1
    xTaskCreatePinnedToCore(task_bench,
                            "task_bench",
                            TASK_STACK / sizeof(StackType_t),
                            NULL,
                            5,
                            NULL,
                            1);  // CPU1
}

