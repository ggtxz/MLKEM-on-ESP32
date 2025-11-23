// ecdh_mem_peak.c — Pico de HEAP/STACK para ECDH + CSV + Wi-Fi/HTTP
// Fluxo:
//   app_main -> init NVS + SPIFFS -> cria task_bench (CPU1)
//   task_bench:
//      • aquecimento 100 iterações (sessão ECDH completa A/B)
//      • benchmark 1000 iterações
//      • mede pico de HEAP e STACK
//      • grava UMA linha no CSV
//      • liga Wi-Fi e disponibiliza CSV via HTTP

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

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

#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

static const char *TAG = "ECDH_MEM_PEAK";

// ====== Parametrização da curva ======
// Troque aqui para P-384/P-521 se quiser medir outras curvas.
#ifndef ECDH_GID
#define ECDH_GID   MBEDTLS_ECP_DP_SECP256R1
#endif

// ====== Stack da task ======
#define TASK_STACK   (64 * 1024)  // bytes; mantenha em sincronia com xTaskCreate

// ====== Warmup e benchmark ======
#define WARMUP_ITERS   100
#define BENCH_ITERS   1000

// ====== Wi-Fi / SPIFFS / CSV ======

#define WIFI_SSID  "VIVOFIBRA-8991"
#define WIFI_PASS  "FaMaGu@24!"

#define CSV_PATH   "/spiffs/mem_ecdh.csv"

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
    httpd_resp_send_chunk(req, NULL, 0);

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
        .uri       = "/mem_ecdh.csv",
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

// ===== Helpers de heap/stack =====

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

static inline size_t stack_used_peak_bytes(void)
{
    UBaseType_t words_min_free = uxTaskGetStackHighWaterMark(NULL);
    size_t bytes_min_free = (size_t)words_min_free * sizeof(StackType_t);
    return (TASK_STACK - bytes_min_free);
}

// ===== DRBG determinístico (A/B) =====

static void hmac_sha256(const void *key, size_t klen,
                        const void *msg, size_t mlen,
                        unsigned char out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md,
                    (const unsigned char *) key, klen,
                    (const unsigned char *) msg, mlen,
                    out);
}

static void make_seed(int iter, char side, unsigned char out[32])
{
    static const char KEY[] = "TCC|ECDH|SEED|mem";
    char msg[64];
    int n = snprintf(msg, sizeof(msg),
                     "gid=%d|side=%c|iter=%d",
                     (int) ECDH_GID, side, iter);
    hmac_sha256(KEY, sizeof(KEY) - 1, msg, (size_t) n, out);
}

// ===== CSV =====

static esp_err_t write_csv_peaks(const char *alg_name,
                                 size_t heap_peak_B,
                                 size_t stack_peak_B)
{
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV (%s) para escrita", CSV_PATH);
        return ESP_FAIL;
    }

    fprintf(f, "alg,heap_peak_B,stack_peak_B\n");
    fprintf(f, "%s,%zu,%zu\n", alg_name, heap_peak_B, stack_peak_B);

    fclose(f);
    ESP_LOGI(TAG, "CSV gravado em %s", CSV_PATH);
    return ESP_OK;
}

// ===== Utilitário: nome da curva =====

static const char* curve_name_from_gid(mbedtls_ecp_group_id gid)
{
    switch (gid) {
        case MBEDTLS_ECP_DP_SECP256R1: return "ECDH-P256";
        case MBEDTLS_ECP_DP_SECP384R1: return "ECDH-P384";
        case MBEDTLS_ECP_DP_SECP521R1: return "ECDH-P521";
        default:                        return "ECDH-UNK";
    }
}

// ===== Uma sessão completa ECDH A↔B =====

static void run_one_session(mbedtls_ecp_group *grp,
                            mbedtls_hmac_drbg_context *drbgA,
                            mbedtls_hmac_drbg_context *drbgB,
                            size_t pub_len)
{
    // MPI e pontos para A e B
    mbedtls_mpi dA, dB, zA, zB;
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&zA); mbedtls_mpi_init(&zB);

    mbedtls_ecp_point QA, QB, QpeerA, QpeerB;
    mbedtls_ecp_point_init(&QA); mbedtls_ecp_point_init(&QB);
    mbedtls_ecp_point_init(&QpeerA); mbedtls_ecp_point_init(&QpeerB);

    // Gera chaves públicas
    (void) mbedtls_ecdh_gen_public(grp, &dA, &QA,
                                   mbedtls_hmac_drbg_random, drbgA);
    (void) mbedtls_ecdh_gen_public(grp, &dB, &QB,
                                   mbedtls_hmac_drbg_random, drbgB);

    // Serializa
    unsigned char A_pub[133], B_pub[133];
    size_t A_len = 0, B_len = 0;
    (void) mbedtls_ecp_point_write_binary(grp, &QA,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &A_len, A_pub, pub_len);
    (void) mbedtls_ecp_point_write_binary(grp, &QB,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &B_len, B_pub, pub_len);

    // Lê/valida
    (void) mbedtls_ecp_point_read_binary(grp, &QpeerA, B_pub, B_len);
    (void) mbedtls_ecp_check_pubkey(grp, &QpeerA);
    (void) mbedtls_ecp_point_read_binary(grp, &QpeerB, A_pub, A_len);
    (void) mbedtls_ecp_check_pubkey(grp, &QpeerB);

    // Segredo compartilhado
    (void) mbedtls_ecdh_compute_shared(grp, &zA, &QpeerA, &dA,
                                       mbedtls_hmac_drbg_random, drbgA);
    (void) mbedtls_ecdh_compute_shared(grp, &zB, &QpeerB, &dB,
                                       mbedtls_hmac_drbg_random, drbgB);

    // Libera tudo
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
    mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
    mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
    mbedtls_ecp_point_free(&QpeerA); mbedtls_ecp_point_free(&QpeerB);
}

// ===== Task principal de benchmark =====

static void task_bench(void *arg)
{
    // Grupo ECP
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    int rc = mbedtls_ecp_group_load(&grp, ECDH_GID);
    if (rc != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_group_load falhou: %d", rc);
        goto end_task;
    }

    const size_t nbytes  = (grp.nbits + 7) / 8;
    const size_t PUB_LEN = 1 + 2 * nbytes; // formato uncompressed

    // DRBG determinístico para A e B
    mbedtls_hmac_drbg_context drbgA, drbgB;
    mbedtls_hmac_drbg_init(&drbgA);
    mbedtls_hmac_drbg_init(&drbgB);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char seedA[32], seedB[32];
    make_seed(0, 'A', seedA);
    make_seed(0, 'B', seedB);

    mbedtls_hmac_drbg_seed_buf(&drbgA, md, seedA, sizeof(seedA));
    mbedtls_hmac_drbg_seed_buf(&drbgB, md, seedB, sizeof(seedB));
    mbedtls_hmac_drbg_set_reseed_interval(&drbgA, 0x7fffffff);
    mbedtls_hmac_drbg_set_reseed_interval(&drbgB, 0x7fffffff);

    // Escopo de heap para medir pico global (warmup + benchmark)
    heap_scope_t hs;
    heap_scope_begin(&hs);

    // Aquecimento
    ESP_LOGI(TAG, "Aquecimento de %d iteracoes...", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        run_one_session(&grp, &drbgA, &drbgB, PUB_LEN);
        if ((i & 31) == 0) {
            vTaskDelay(0);
        }
    }

    // Benchmark principal
    ESP_LOGI(TAG, "Benchmark de %d iteracoes...", BENCH_ITERS);
    for (int i = 0; i < BENCH_ITERS; i++) {
        run_one_session(&grp, &drbgA, &drbgB, PUB_LEN);
        if ((i & 31) == 0) {
            vTaskDelay(0);
        }
    }

    heap_scope_end(&hs);

    size_t heap_peak_B  = heap_peak_bytes(&hs);
    size_t stack_peak_B = stack_used_peak_bytes();

    const char *alg_name = curve_name_from_gid(ECDH_GID);

    ESP_LOGI(TAG, "Pico de uso de HEAP [B]  = %zu", heap_peak_B);
    ESP_LOGI(TAG, "Pico de uso de STACK [B] = %zu", stack_peak_B);

    printf("HEAP_RESULT,ALG=%s,HEAP_PEAK_B=%zu,STACK_PEAK_B=%zu\n",
           alg_name, heap_peak_B, stack_peak_B);

    // CSV com uma única linha de picos
    ESP_ERROR_CHECK(write_csv_peaks(alg_name, heap_peak_B, stack_peak_B));

    // Libera contexto ECDH antes de ligar Wi-Fi
    mbedtls_hmac_drbg_free(&drbgA);
    mbedtls_hmac_drbg_free(&drbgB);
    mbedtls_ecp_group_free(&grp);

    // Wi-Fi + HTTP server para download do CSV
    wifi_init_sta();
    start_file_server();

    // Mantém task viva para manter o servidor
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

end_task:
    // Se der erro antes, apenas dorme para não resetar em loop
    for (;;)
        vTaskDelay(pdMS_TO_TICKS(1000));
}

// ===== app_main =====

void app_main(void)
{
    // NVS (necessário para Wi-Fi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // SPIFFS
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

