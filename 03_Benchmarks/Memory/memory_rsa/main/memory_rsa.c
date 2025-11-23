// rsa_mem_bench.c — Benchmark de MEMÓRIA (heap/stack) durante RSA-OAEP -> CSV -> Wi-Fi -> HTTP
// Somente memória: mede heap (8-bit/internal), maior bloco, mínimo histórico e stack watermark.
// Progresso: imprime um '.' no UART após cada iteração (sem interferir nas medições).

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_err.h"

#include "esp_spiffs.h"
#include "esp_vfs.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs_flash.h"

#include "esp_heap_caps.h"   // heap_caps_get_*
#include "esp_rom_uart.h"    // progresso no UART

#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/error.h"   // mbedtls_strerror (se MBEDTLS_ERROR_C estiver ativo)

#include "coins_rsa.h"       // SEED[1000][RSA_SEED_BYTES], input[1000][32]

/* ======= Sanity p/ chaves grandes (se defines existirem no port) ======= */
#if defined(MBEDTLS_MPI_MAX_SIZE) && (MBEDTLS_MPI_MAX_SIZE < 960)
#error "MBEDTLS_MPI_MAX_SIZE muito pequeno p/ RSA-7680 (>=960; recomendado 1024)."
#endif
#if defined(MBEDTLS_MPI_MAX_BITS) && (MBEDTLS_MPI_MAX_BITS < 7680)
#error "MBEDTLS_MPI_MAX_BITS muito pequeno p/ RSA-7680 (>=7680; recomendado 8192)."
#endif
#ifndef MBEDTLS_GENPRIME
#define MBEDTLS_GENPRIME
#endif

#ifndef RSA_SEED_BYTES
#define RSA_SEED_BYTES 32
#endif
#ifndef RSA_SEED_COUNT
#define RSA_SEED_COUNT 1000
#endif

/* ======= Configs ======= */
static const char *TAG = "RSA_MEM";

#define WIFI_SSID  "VIVOFIBRA-8991"
#define WIFI_PASS  "FaMaGu@24!"

#define RSA_KEY_SIZE       7680
#define RSA_EXPONENT       65537
#define SECRET_SIZE        32

#define N_ITERS            1000
#define KEYGEN_EVERY       20
#define WARMUP             1

#define TASK_STACK         (64 * 1024) // bytes
#define TASK_CORE_ID       1
#define TASK_PRIO          5

#define CSV_PATH           "/spiffs/rsa_mem.csv"

/* ======= OAEP label fixo (igual em enc/dec) ======= */
static const unsigned char OAEP_LABEL[] = "TCC|RSA-OAEP|SHA256";
#define OAEP_LABEL_LEN (sizeof(OAEP_LABEL) - 1)

/* ======= Log de erro Mbed TLS (string se disponível) ======= */
static void log_mbedtls_err(const char* where, int ret) {
#if defined(MBEDTLS_ERROR_C)
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "%s: ret=%d (-%04X) %s", where, ret, -ret, buf);
#else
    ESP_LOGE(TAG, "%s: ret=%d (-%04X)", where, ret, -ret);
#endif
}

/* ======= Progresso no UART (não aloca, não interfere no heap medido) ======= */
#ifndef PROGRESS_LINE_BREAK
#define PROGRESS_LINE_BREAK 50
#endif
static inline void progress_tick(int i) {
    esp_rom_output_tx_one_char('.');
    if ((i % PROGRESS_LINE_BREAK) == PROGRESS_LINE_BREAK - 1)
        esp_rom_output_tx_one_char('\n');
}

/* ======= Wi-Fi/HTTP ======= */
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;
static char s_ip_str[16] = "0.0.0.0";

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data){
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG, "Wi-Fi caiu, reconectando...");
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *e = (const ip_event_got_ip_t *)data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&e->ip_info.ip));
        ESP_LOGI(TAG, "Wi-Fi OK. IP: %s", s_ip_str);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}
static void wifi_init_sta(const char *ssid, const char *pass){
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_instance_t h1, h2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &h2));
    wifi_config_t c = (wifi_config_t){0};
    strlcpy((char *)c.sta.ssid, ssid, sizeof(c.sta.ssid));
    strlcpy((char *)c.sta.password, pass, sizeof(c.sta.password));
    c.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Conectando no AP: %s ...", ssid);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, false, true, portMAX_DELAY);
}

static esp_err_t send_file_handler(httpd_req_t *req, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found"); return ESP_FAIL; }
    httpd_resp_set_type(req, "text/csv");
    char buf[1024]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) httpd_resp_send_chunk(req, buf, n);
    fclose(f); httpd_resp_send_chunk(req, NULL, 0); return ESP_OK;
}
static esp_err_t csv_handler(httpd_req_t *req) { return send_file_handler(req, CSV_PATH); }

static httpd_handle_t start_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri = {.uri="/rsa_mem.csv", .method=HTTP_GET, .handler=csv_handler};
        httpd_register_uri_handler(server, &uri);
        return server;
    }
    return NULL;
}

static void spiffs_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "spiffs",
        .max_files = 8,
        .format_if_mount_failed = true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
    size_t total=0, used=0;
    ESP_ERROR_CHECK(esp_spiffs_info(conf.partition_label, &total, &used));
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u", (unsigned)total, (unsigned)used);
}

/* ======= DRBG determinístico ======= */
static inline int rng_fixed(void *p_rng, unsigned char *buf, size_t len){
    return mbedtls_hmac_drbg_random((mbedtls_hmac_drbg_context *)p_rng, buf, len);
}

/* ======= Métricas de memória ======= */
typedef struct {
    size_t heap_free_before,  heap_free_after;
    size_t heap_int_free_before, heap_int_free_after;
    size_t largest_free_block_before, largest_free_block_after;
    size_t heap_min_ever;
    size_t stack_min_free_bytes, stack_used_peak_bytes;
} mem_metrics_t;

static inline void capture_heap(mem_metrics_t *m, bool before)
{
    size_t heap_free      = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t heap_int_free  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block  = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    size_t min_ever       = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    if (before) {
        m->heap_free_before          = heap_free;
        m->heap_int_free_before      = heap_int_free;
        m->largest_free_block_before = largest_block;
    } else {
        m->heap_free_after           = heap_free;
        m->heap_int_free_after       = heap_int_free;
        m->largest_free_block_after  = largest_block;
    }
    m->heap_min_ever = min_ever;
}

static inline void capture_stack(mem_metrics_t *m)
{
    UBaseType_t words_min = uxTaskGetStackHighWaterMark(NULL);
    size_t bytes_min_free = (size_t)words_min * sizeof(StackType_t);
    m->stack_min_free_bytes = bytes_min_free;
    m->stack_used_peak_bytes = (TASK_STACK - bytes_min_free);
}

/* ======= Benchmark de MEMÓRIA ======= */
static void rsa_mem_task(void *arg)
{
    ESP_LOGI(TAG, "RSA-%d OAEP | N_ITERS=%d | KEYGEN_EVERY=%d | Warmup=%d — MEMÓRIA APENAS",
             RSA_KEY_SIZE, N_ITERS, KEYGEN_EVERY, WARMUP);
    ESP_LOGI(TAG, "Progresso no console: '.' por iteração, quebra a cada %d.", PROGRESS_LINE_BREAK);

    // ---------- Warmup: 1 chave + algumas enc/dec (estabiliza alocações) ----------
    {
        mbedtls_rsa_context ctx_w; mbedtls_hmac_drbg_context drbg_k, drbg_e, drbg_d;
        mbedtls_rsa_init(&ctx_w); mbedtls_hmac_drbg_init(&drbg_k);
        mbedtls_hmac_drbg_init(&drbg_e); mbedtls_hmac_drbg_init(&drbg_d);
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        mbedtls_hmac_drbg_seed_buf(&drbg_k, md, SEED[0], RSA_SEED_BYTES);
        mbedtls_rsa_set_padding(&ctx_w, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
        mbedtls_rsa_gen_key(&ctx_w, rng_fixed, &drbg_k, RSA_KEY_SIZE, RSA_EXPONENT);

        size_t k = mbedtls_rsa_get_len(&ctx_w);
        unsigned char *ct = (unsigned char*) malloc(k);
        if (ct) {
            for (int i = 0; i < WARMUP; i++) {
                int idx = i % RSA_SEED_COUNT;
                mbedtls_hmac_drbg_seed_buf(&drbg_e, md, SEED[idx], RSA_SEED_BYTES);
                mbedtls_hmac_drbg_seed_buf(&drbg_d, md, SEED[idx], RSA_SEED_BYTES);
                (void) mbedtls_rsa_rsaes_oaep_encrypt(&ctx_w, rng_fixed, &drbg_e,
                                                      OAEP_LABEL, OAEP_LABEL_LEN,
                                                      SECRET_SIZE, input[idx], ct);
                unsigned char out[SECRET_SIZE]; size_t olen = 0;
                (void) mbedtls_rsa_rsaes_oaep_decrypt(&ctx_w, rng_fixed, &drbg_d,
                                                      OAEP_LABEL, OAEP_LABEL_LEN,
                                                      &olen, ct, out, sizeof out);
            }
            free(ct);
        }
        ESP_LOGI(TAG, "Warmup: modulus len = %u bytes", (unsigned)k);
        mbedtls_hmac_drbg_free(&drbg_k); mbedtls_hmac_drbg_free(&drbg_e); mbedtls_hmac_drbg_free(&drbg_d);
        mbedtls_rsa_free(&ctx_w);
    }

    // ---------- CSV ----------
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) { ESP_LOGE(TAG, "Falha ao abrir %s", CSV_PATH); goto after_bench; }
    setvbuf(f, NULL, _IOLBF, 0);
    fprintf(f,
        "iter,key_id,did_keygen,phase,"
        "heap_free_B_before,heap_free_B_after,heap_delta_B,"
        "heap_int_free_B_before,heap_int_free_B_after,heap_int_delta_B,"
        "largest_free_block_B_before,largest_free_block_B_after,"
        "heap_min_ever_B,"
        "stack_min_free_B,stack_used_peak_B\n");

    // ---------- Loop principal ----------
    mbedtls_rsa_context ctx; mbedtls_hmac_drbg_context drbg_keygen;
    mbedtls_rsa_init(&ctx); mbedtls_hmac_drbg_init(&drbg_keygen);
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    size_t k_ct = 0;
    unsigned char *ct = NULL;
    uint16_t current_key_id = 0;
    int warned_oaep_limit = 0;

    for (int i = 0; i < N_ITERS; i++) {
        const int idx = i % RSA_SEED_COUNT;
        int did_keygen = 0;
        mem_metrics_t m;

        // KEYGEN (quando devido)
        if (i % KEYGEN_EVERY == 0) {
            int seed_k = (current_key_id % RSA_SEED_COUNT);
            mbedtls_hmac_drbg_seed_buf(&drbg_keygen, md, SEED[seed_k], RSA_SEED_BYTES);

            mbedtls_rsa_free(&ctx);
            mbedtls_rsa_init(&ctx);

            int ret_pad = mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
            if (ret_pad != 0) { log_mbedtls_err("set_padding", ret_pad); }

            capture_heap(&m, true);
            int ret = mbedtls_rsa_gen_key(&ctx, rng_fixed, &drbg_keygen, RSA_KEY_SIZE, RSA_EXPONENT);
            capture_heap(&m, false);
            capture_stack(&m);

            if (ret != 0) {
                log_mbedtls_err("keygen", ret);
            } else {
                size_t knew = mbedtls_rsa_get_len(&ctx);
                if (knew != k_ct) {
                    free(ct); ct = NULL;
                    k_ct = knew;
                    ct = (unsigned char*) malloc(k_ct);
                    if (!ct) { ESP_LOGE(TAG, "[%d] malloc(ct=%u) falhou", i, (unsigned)k_ct); }
                }
                // Checagem de limite OAEP: k - 2*hLen - 2
                if (!warned_oaep_limit) {
                    size_t hLen = 32; // SHA-256
                    size_t max_oaep = (k_ct >= (2*hLen + 2)) ? (k_ct - 2*hLen - 2) : 0;
                    if (SECRET_SIZE > max_oaep) {
                        ESP_LOGE(TAG, "SECRET_SIZE=%u > max_OAEP=%u (k=%u). Ajuste necessário.",
                                 (unsigned)SECRET_SIZE, (unsigned)max_oaep, (unsigned)k_ct);
                    } else {
                        ESP_LOGI(TAG, "OAEP OK: SECRET_SIZE=%u <= max_OAEP=%u (k=%u).",
                                 (unsigned)SECRET_SIZE, (unsigned)max_oaep, (unsigned)k_ct);
                    }
                    warned_oaep_limit = 1;
                }
            }

            fprintf(f, "%d,%u,%d,keygen,%zu,%zu,%ld,%zu,%zu,%ld,%zu,%zu,%zu,%zu,%zu\n",
                i, (unsigned)current_key_id, 1,
                m.heap_free_before, m.heap_free_after,  (long)(m.heap_free_after - m.heap_free_before),
                m.heap_int_free_before, m.heap_int_free_after, (long)(m.heap_int_free_after - m.heap_int_free_before),
                m.largest_free_block_before, m.largest_free_block_after,
                m.heap_min_ever,
                m.stack_min_free_bytes, m.stack_used_peak_bytes);

            did_keygen = 1;
            current_key_id++;
        }

        const uint16_t key_id_in_use = (uint16_t)(current_key_id ? current_key_id - 1 : 0);

        // ENC
        mbedtls_hmac_drbg_context drbg_enc; mbedtls_hmac_drbg_init(&drbg_enc);
        mbedtls_hmac_drbg_seed_buf(&drbg_enc, md, SEED[idx], RSA_SEED_BYTES);

        capture_heap(&m, true);
        int ret = mbedtls_rsa_rsaes_oaep_encrypt(&ctx, rng_fixed, &drbg_enc,
                                                 OAEP_LABEL, OAEP_LABEL_LEN,
                                                 SECRET_SIZE, input[idx], ct);
        capture_heap(&m, false);
        capture_stack(&m);

        fprintf(f, "%d,%u,%d,enc,%zu,%zu,%ld,%zu,%zu,%ld,%zu,%zu,%zu,%zu,%zu\n",
            i, (unsigned)key_id_in_use, did_keygen,
            m.heap_free_before, m.heap_free_after,  (long)(m.heap_free_after - m.heap_free_before),
            m.heap_int_free_before, m.heap_int_free_after, (long)(m.heap_int_free_after - m.heap_int_free_before),
            m.largest_free_block_before, m.largest_free_block_after,
            m.heap_min_ever,
            m.stack_min_free_bytes, m.stack_used_peak_bytes);

        if (ret != 0) {
            log_mbedtls_err("encrypt", ret);
        }

        // DEC
        unsigned char out[SECRET_SIZE]; size_t olen = 0;
        mbedtls_hmac_drbg_context drbg_dec; mbedtls_hmac_drbg_init(&drbg_dec);
        mbedtls_hmac_drbg_seed_buf(&drbg_dec, md, SEED[idx], RSA_SEED_BYTES);

        capture_heap(&m, true);
        ret = mbedtls_rsa_rsaes_oaep_decrypt(&ctx, rng_fixed, &drbg_dec,
                                             OAEP_LABEL, OAEP_LABEL_LEN,
                                             &olen, ct, out, sizeof out);
        capture_heap(&m, false);
        capture_stack(&m);

        fprintf(f, "%d,%u,%d,dec,%zu,%zu,%ld,%zu,%zu,%ld,%zu,%zu,%zu,%zu,%zu\n",
            i, (unsigned)key_id_in_use, did_keygen,
            m.heap_free_before, m.heap_free_after,  (long)(m.heap_free_after - m.heap_free_before),
            m.heap_int_free_before, m.heap_int_free_after, (long)(m.heap_int_free_after - m.heap_int_free_before),
            m.largest_free_block_before, m.largest_free_block_after,
            m.heap_min_ever,
            m.stack_min_free_bytes, m.stack_used_peak_bytes);

        if (ret != 0 || olen != SECRET_SIZE || memcmp(input[idx], out, SECRET_SIZE) != 0) {
            log_mbedtls_err("decrypt/compare", ret);
        }

        mbedtls_hmac_drbg_free(&drbg_enc);
        mbedtls_hmac_drbg_free(&drbg_dec);

        // TOTAL (observa drift acumulado)
        capture_heap(&m, true);
        capture_heap(&m, false);
        capture_stack(&m);
        fprintf(f, "%d,%u,%d,total,%zu,%zu,%ld,%zu,%zu,%ld,%zu,%zu,%zu,%zu,%zu\n",
            i, (unsigned)key_id_in_use, did_keygen,
            m.heap_free_before, m.heap_free_after,  (long)(m.heap_free_after - m.heap_free_before),
            m.heap_int_free_before, m.heap_int_free_after, (long)(m.heap_int_free_after - m.heap_int_free_before),
            m.largest_free_block_before, m.largest_free_block_after,
            m.heap_min_ever,
            m.stack_min_free_bytes, m.stack_used_peak_bytes);

        // Progresso (após concluir medições/CSV da iteração)
        progress_tick(i);

        if ((i % 10) == 0) vTaskDelay(0);
    } // for

    free(ct);
    mbedtls_hmac_drbg_free(&drbg_keygen);
    mbedtls_rsa_free(&ctx);

    fclose(f);
    ESP_LOGI(TAG, "CSV gravado em %s", CSV_PATH);

after_bench:
    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if (srv) {
        ESP_LOGI(TAG, "Servidor HTTP ativo");
        ESP_LOGI(TAG, "===> http://%s/rsa_mem.csv <===", s_ip_str);
    } else {
        ESP_LOGE(TAG, "Falha ao iniciar servidor HTTP");
    }

    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    spiffs_init();
    xTaskCreatePinnedToCore(rsa_mem_task, "rsa_mem",
                            TASK_STACK / sizeof(StackType_t), NULL, TASK_PRIO, NULL, TASK_CORE_ID);
}
