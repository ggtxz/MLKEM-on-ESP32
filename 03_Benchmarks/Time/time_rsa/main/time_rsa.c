// rsa_time_bench.c — Benchmark de TEMPO (us/ciclos) de RSA-OAEP
// Fluxo: app_main -> NVS + SPIFFS + task na CPU1
// task: warmup 100 -> benchmark 1000 (buffers de tempo) -> escreve CSV -> Wi-Fi + HTTP

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

#include "esp_timer.h"
#include "esp_cpu.h"
#include "esp_pm.h"

#include "esp_rom_uart.h"    // progresso com esp_rom_output_tx_one_char
#include "esp_heap_caps.h"   // opcional, mas mantive se quiser debugar heap

#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"

#include "coins_rsa.h"  // SEED[1000][RSA_SEED_BYTES], input[1000][32]

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
static const char *TAG = "RSA_TIME";

#define WIFI_SSID  "VIVOFIBRA-8991"
#define WIFI_PASS  "FaMaGu@24!"

#define RSA_KEY_SIZE       7680
#define RSA_EXPONENT       65537
#define SECRET_SIZE        32

#define N_ITERS            1000
#define WARMUP             100   // aquecimento de 100 iterações

#define TASK_STACK         (64 * 1024) // bytes
#define TASK_CORE_ID       1
#define TASK_PRIO          5

#define CSV_PATH           "/spiffs/rsa_mem.csv"   // mantém o mesmo nome do arquivo

// Máximo de bytes para o módulo (1024 cobre até 8192 bits)
#define RSA_MAX_MOD_BYTES  1024

/* ======= Progresso no UART (não afeta heap/time de forma relevante) ======= */
#ifndef PROGRESS_LINE_BREAK
#define PROGRESS_LINE_BREAK 50
#endif
static inline void progress_tick(int i) {
    esp_rom_output_tx_one_char('.');               // 1 char por iteração
    if ((i % PROGRESS_LINE_BREAK) == PROGRESS_LINE_BREAK - 1)
        esp_rom_output_tx_one_char('\n');          // quebra a linha a cada 50
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
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &h2));

    wifi_config_t c = (wifi_config_t){0};
    strlcpy((char *)c.sta.ssid, ssid, sizeof(c.sta.ssid));
    strlcpy((char *)c.sta.password, pass, sizeof(c.sta.password));
    c.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando no AP: %s ...", ssid);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
}

static esp_err_t send_file_handler(httpd_req_t *req, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/csv");
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        httpd_resp_send_chunk(req, buf, n);
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t csv_handler(httpd_req_t *req) {
    return send_file_handler(req, CSV_PATH);
}

static httpd_handle_t start_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri = {
            .uri = "/rsa_mem.csv",
            .method = HTTP_GET,
            .handler = csv_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &uri);
        return server;
    }
    return NULL;
}

/* ======= SPIFFS ======= */
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
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u",
             (unsigned)total, (unsigned)used);
}

/* ======= DRBG determinístico ======= */
static inline int rng_fixed(void *p_rng, unsigned char *buf, size_t len){
    return mbedtls_hmac_drbg_random((mbedtls_hmac_drbg_context *)p_rng, buf, len);
}

/* ======= Buffers de tempo/ciclos ======= */
static uint32_t t_keygen_us[N_ITERS], t_enc_us[N_ITERS],
                t_dec_us[N_ITERS],   t_total_us[N_ITERS];
static uint32_t c_keygen[N_ITERS],   c_enc[N_ITERS],
                c_dec[N_ITERS],      c_total[N_ITERS];

/* ======= Warmup: 100 iteracoes com keygen+enc+dec (sem guardar tempos) ======= */
static void rsa_warmup(void)
{
    ESP_LOGI(TAG, "Aquecimento de %d iteracoes (RSA keygen+enc+dec).", WARMUP);

    mbedtls_rsa_context ctx;
    mbedtls_hmac_drbg_context drbg_k, drbg_enc, drbg_dec;

    mbedtls_rsa_init(&ctx);
    mbedtls_hmac_drbg_init(&drbg_k);
    mbedtls_hmac_drbg_init(&drbg_enc);
    mbedtls_hmac_drbg_init(&drbg_dec);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char ct[RSA_MAX_MOD_BYTES];

    for (int i = 0; i < WARMUP; i++) {
        int idx = i % RSA_SEED_COUNT;
        int ret;

        // KEYGEN
        mbedtls_hmac_drbg_seed_buf(&drbg_k, md, SEED[idx], RSA_SEED_BYTES);
        mbedtls_rsa_free(&ctx);
        mbedtls_rsa_init(&ctx);
        mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

        ret = mbedtls_rsa_gen_key(&ctx, rng_fixed, &drbg_k, RSA_KEY_SIZE, RSA_EXPONENT);
        if (ret != 0) {
            ESP_LOGE(TAG, "[warmup %d] keygen falhou: -0x%04X", i, -ret);
            continue;
        }

        size_t mod_len = mbedtls_rsa_get_len(&ctx);
        if (mod_len > RSA_MAX_MOD_BYTES) {
            ESP_LOGE(TAG, "Modulo demasiado grande (%u bytes) para buffer %u.",
                     (unsigned)mod_len, (unsigned)RSA_MAX_MOD_BYTES);
            break;
        }

        // ENC
        mbedtls_hmac_drbg_seed_buf(&drbg_enc, md, SEED[idx], RSA_SEED_BYTES);
        ret = mbedtls_rsa_rsaes_oaep_encrypt(&ctx, rng_fixed, &drbg_enc,
                                             NULL, 0, SECRET_SIZE, input[idx], ct);
        if (ret != 0) {
            ESP_LOGE(TAG, "[warmup %d] enc falhou: -0x%04X", i, -ret);
            continue;
        }

        // DEC
        unsigned char out[SECRET_SIZE];
        size_t olen = 0;
        mbedtls_hmac_drbg_seed_buf(&drbg_dec, md, SEED[idx], RSA_SEED_BYTES);
        ret = mbedtls_rsa_rsaes_oaep_decrypt(&ctx, rng_fixed, &drbg_dec,
                                             NULL, 0, &olen, ct, out, sizeof out);
        if (ret != 0 || olen != SECRET_SIZE ||
            memcmp(input[idx], out, SECRET_SIZE) != 0) {
            ESP_LOGE(TAG, "[warmup %d] dec/compare falhou (ret=%d, olen=%u)",
                     i, ret, (unsigned)olen);
        }

        if ((i % 10) == 0) vTaskDelay(0);
    }

    mbedtls_hmac_drbg_free(&drbg_k);
    mbedtls_hmac_drbg_free(&drbg_enc);
    mbedtls_hmac_drbg_free(&drbg_dec);
    mbedtls_rsa_free(&ctx);

    ESP_LOGI(TAG, "Warmup concluido.");
}

/* ======= Benchmark de TEMPO ======= */
static void rsa_time_task(void *arg)
{
#if CONFIG_PM_ENABLE
    // trava CPU em freq. máxima e evita light sleep durante o benchmark
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "rsa_bench", &lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "rsa_bench", &lock_ls));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_ls));
#endif

    ESP_LOGI(TAG, "RSA-%d OAEP | N_ITERS=%d | Warmup=%d — TEMPO (us + ciclos)",
             RSA_KEY_SIZE, N_ITERS, WARMUP);
    ESP_LOGI(TAG, "Progresso: '.' por iteracao, quebra a cada %d.", PROGRESS_LINE_BREAK);

    // 1) Aquecimento
    rsa_warmup();

    // 2) Benchmark principal
    mbedtls_rsa_context ctx;
    mbedtls_hmac_drbg_context drbg_k, drbg_enc, drbg_dec;

    mbedtls_rsa_init(&ctx);
    mbedtls_hmac_drbg_init(&drbg_k);
    mbedtls_hmac_drbg_init(&drbg_enc);
    mbedtls_hmac_drbg_init(&drbg_dec);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char ct[RSA_MAX_MOD_BYTES];

    for (int i = 0; i < N_ITERS; i++) {
        const int idx = i % RSA_SEED_COUNT;
        int ret;

        // ===== KEYGEN (medido, em TODAS as iterações) =====
        mbedtls_hmac_drbg_seed_buf(&drbg_k, md, SEED[idx], RSA_SEED_BYTES);
        mbedtls_rsa_free(&ctx);
        mbedtls_rsa_init(&ctx);
        mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

        uint64_t t0 = esp_timer_get_time();
        uint32_t c0 = esp_cpu_get_cycle_count();
        ret = mbedtls_rsa_gen_key(&ctx, rng_fixed, &drbg_k, RSA_KEY_SIZE, RSA_EXPONENT);
        uint64_t t1 = esp_timer_get_time();
        uint32_t c1 = esp_cpu_get_cycle_count();

        if (ret != 0) {
            ESP_LOGE(TAG, "[%d] keygen falhou: -0x%04X", i, -ret);
            // ainda assim grava tempos medidos até aqui
        }

        size_t mod_len = mbedtls_rsa_get_len(&ctx);
        if (mod_len > RSA_MAX_MOD_BYTES) {
            ESP_LOGE(TAG, "[%d] Modulo demasiado grande (%u bytes) para buffer %u.",
                     i, (unsigned)mod_len, (unsigned)RSA_MAX_MOD_BYTES);
            mod_len = RSA_MAX_MOD_BYTES; // evita overflow no encrypt
        }

        // ===== ENC =====
        mbedtls_hmac_drbg_seed_buf(&drbg_enc, md, SEED[idx], RSA_SEED_BYTES);

        uint64_t t2 = esp_timer_get_time();
        uint32_t c2 = esp_cpu_get_cycle_count();
        ret = mbedtls_rsa_rsaes_oaep_encrypt(&ctx, rng_fixed, &drbg_enc,
                                             NULL, 0, SECRET_SIZE, input[idx], ct);
        uint64_t t3 = esp_timer_get_time();
        uint32_t c3 = esp_cpu_get_cycle_count();

        if (ret != 0) {
            ESP_LOGE(TAG, "[%d] enc falhou: -0x%04X", i, -ret);
        }

        // ===== DEC =====
        unsigned char out[SECRET_SIZE];
        size_t olen = 0;
        mbedtls_hmac_drbg_seed_buf(&drbg_dec, md, SEED[idx], RSA_SEED_BYTES);

        uint64_t t4 = esp_timer_get_time();
        uint32_t c4 = esp_cpu_get_cycle_count();
        ret = mbedtls_rsa_rsaes_oaep_decrypt(&ctx, rng_fixed, &drbg_dec,
                                             NULL, 0, &olen, ct, out, sizeof out);
        uint64_t t5 = esp_timer_get_time();
        uint32_t c5 = esp_cpu_get_cycle_count();

        if (ret != 0 || olen != SECRET_SIZE ||
            memcmp(input[idx], out, SECRET_SIZE) != 0) {
            ESP_LOGE(TAG, "[%d] dec/compare falhou (ret=%d, olen=%u)",
                     i, ret, (unsigned)olen);
        }

        // ===== Guarda tempos/ciclos nos buffers =====
        t_keygen_us[i] = (uint32_t)(t1 - t0);
        t_enc_us[i]    = (uint32_t)(t3 - t2);
        t_dec_us[i]    = (uint32_t)(t5 - t4);
        t_total_us[i]  = (uint32_t)(t5 - t0);

        c_keygen[i] = (c1 - c0);
        c_enc[i]    = (c3 - c2);
        c_dec[i]    = (c5 - c4);
        c_total[i]  = (c5 - c0);

        // Progresso
        progress_tick(i);
        if ((i % 10) == 0) vTaskDelay(0);
    }

    mbedtls_hmac_drbg_free(&drbg_k);
    mbedtls_hmac_drbg_free(&drbg_enc);
    mbedtls_hmac_drbg_free(&drbg_dec);
    mbedtls_rsa_free(&ctx);

    // 3) Escreve CSV (igual formato do Kyber)
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir %s", CSV_PATH);
        goto after_bench;
    }
    fprintf(f, "iter,keypair_us,enc_us,dec_us,total_us,"
               "keypair_cycles,enc_cycles,dec_cycles,total_cycles\n");

    for (int i = 0; i < N_ITERS; i++) {
        fprintf(f, "%d,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ","
                   "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 "\n",
                i,
                t_keygen_us[i], t_enc_us[i], t_dec_us[i], t_total_us[i],
                c_keygen[i],    c_enc[i],    c_dec[i],    c_total[i]);
    }
    fclose(f);
    ESP_LOGI(TAG, "CSV gravado em %s", CSV_PATH);

after_bench:

#if CONFIG_PM_ENABLE
    // libera locks antes de ligar Wi-Fi
    if (lock_ls) { esp_pm_lock_release(lock_ls); esp_pm_lock_delete(lock_ls); }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    // 4) Liga Wi-Fi e disponibiliza CSV via HTTP
    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if (srv) {
        ESP_LOGI(TAG, "Servidor HTTP ativo");
        ESP_LOGI(TAG, "===> http://%s/rsa_mem.csv <===", s_ip_str);
    } else {
        ESP_LOGE(TAG, "Falha ao iniciar servidor HTTP");
    }

    // Mantém o servidor vivo
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

/* ======= app_main ======= */
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    spiffs_init();

    // Cria task de benchmark na CPU1, como no fluxograma
    xTaskCreatePinnedToCore(
        rsa_time_task, "rsa_time",
        TASK_STACK / sizeof(StackType_t),
        NULL, TASK_PRIO, NULL, TASK_CORE_ID
    );
}

