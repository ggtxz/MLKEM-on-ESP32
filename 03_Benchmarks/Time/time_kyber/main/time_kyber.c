// bench_kyber.c — App_main -> task_bench(CPU1)
// task_bench: warmup 100 -> benchmark 1000 (buffers) -> escreve CSV -> liga Wi-Fi e serve HTTP

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_cpu.h"
#include "esp_pm.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs_flash.h"

#include "esp_spiffs.h"
#include "esp_vfs.h"

// === Kyber (seus headers) ===
#include "kem1024.h"   // PQCLEAN_MLKEM1024_CLEAN_CRYPTO_*
#include "coins.h"     // COINS_KEYPAIR[1000][64], COINS_ENC[1000][32]

static const char *TAG = "KYBER_BENCH";

#define WIFI_SSID   "VIVOFIBRA-8991"
#define WIFI_PASS   "FaMaGu@24!"

#define N_ITERS     1000     // benchmark principal
#define WARMUP      100      // aquecimento

#define CSV_PATH    "/spiffs/kyber_times.csv"

// ====== Wi-Fi (STA) ======
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;
static char s_ip_str[16] = "0.0.0.0";

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG, "Wi-Fi caiu, reconectando...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)event_data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Wi-Fi OK. IP: %s", s_ip_str);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(const char *ssid, const char *pass)
{
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

    wifi_config_t c = {0};
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

// ====== HTTP server (serve /kyber.csv) ======
static esp_err_t csv_handler(httpd_req_t *req)
{
    FILE *f = fopen(CSV_PATH, "r");
    if (!f) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/csv");
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        httpd_resp_send_chunk(req, buf, n);
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0); // termina resposta
    return ESP_OK;
}

static httpd_handle_t start_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri = {
            .uri     = "/kyber.csv",
            .method  = HTTP_GET,
            .handler = csv_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &uri);
        return server;
    }

    return NULL;
}

// ====== SPIFFS ======
static void spiffs_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "spiffs",   // deve casar com a partition table
        .max_files = 4,
        .format_if_mount_failed = true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));

    size_t total = 0, used = 0;
    ESP_ERROR_CHECK(esp_spiffs_info(conf.partition_label, &total, &used));
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u",
             (unsigned) total, (unsigned) used);
}

// ====== task_bench (CPU1) ======
static void task_bench(void *arg)
{
    // (Opcional) travar freq. e evitar light sleep durante o benchmark
#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "bench", &lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "bench", &lock_ls));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_ls));
#endif

    // Buffers Kyber
    uint8_t pk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ss1[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
    uint8_t ct[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];

    // Buffers de tempos (us) e ciclos para cada iteração
    static uint32_t t_keypair_us[N_ITERS], t_enc_us[N_ITERS],
                    t_dec_us[N_ITERS],     t_total_us[N_ITERS];
    static uint32_t c_keypair[N_ITERS],    c_enc[N_ITERS],
                    c_dec[N_ITERS],        c_total[N_ITERS];

    ESP_LOGI(TAG, "Aquecimento de %d iteracoes (sem registro)", WARMUP);

    // 1) Aquecimento de 100 iterações (sem gravar em buffer)
    for (int i = 0; i < WARMUP; i++) {
        int idx = i % 1000; // usa as coins pré-geradas
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk, COINS_KEYPAIR[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss1, pk, COINS_ENC[idx]);
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);

        if ((i % 25) == 0) {
            vTaskDelay(0); // alimenta o scheduler / WDT
        }
    }

    ESP_LOGI(TAG, "Iniciando benchmark de %d iteracoes", N_ITERS);

    // 2) Benchmark de 1000 iterações com marcação de tempo
    for (int i = 0; i < N_ITERS; i++) {
        int idx = i % 1000;

        uint64_t t0 = esp_timer_get_time();
        uint32_t c0 = esp_cpu_get_cycle_count();
        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk, COINS_KEYPAIR[idx]);
        uint64_t t1 = esp_timer_get_time();
        uint32_t c1 = esp_cpu_get_cycle_count();

        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss1, pk, COINS_ENC[idx]);
        uint64_t t2 = esp_timer_get_time();
        uint32_t c2 = esp_cpu_get_cycle_count();

        PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);
        uint64_t t3 = esp_timer_get_time();
        uint32_t c3 = esp_cpu_get_cycle_count();

        // registra tempos em us
        t_keypair_us[i] = (uint32_t)(t1 - t0);
        t_enc_us[i]     = (uint32_t)(t2 - t1);
        t_dec_us[i]     = (uint32_t)(t3 - t2);
        t_total_us[i]   = (uint32_t)(t3 - t0);

        // registra ciclos de CPU
        c_keypair[i] = (c1 - c0);
        c_enc[i]     = (c2 - c1);
        c_dec[i]     = (c3 - c2);
        c_total[i]   = (c3 - c0);

        if ((i % 25) == 0) {
            vTaskDelay(0);
        }
    }

    // 3) Escreve os valores dos buffers no CSV
    ESP_LOGI(TAG, "Gravando CSV em %s", CSV_PATH);
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV para escrita");
        goto after_bench;
    }

    fprintf(f, "iter,keypair_us,enc_us,dec_us,total_us,"
               "keypair_cycles,enc_cycles,dec_cycles,total_cycles\n");

    for (int i = 0; i < N_ITERS; i++) {
        fprintf(f, "%d,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ","
                   "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 "\n",
                i,
                t_keypair_us[i], t_enc_us[i], t_dec_us[i], t_total_us[i],
                c_keypair[i],    c_enc[i],    c_dec[i],    c_total[i]);
    }

    fclose(f);
    ESP_LOGI(TAG, "CSV gravado com sucesso");

after_bench:
    // 4) Libera locks e inicia Wi-Fi + HTTP para disponibilizar CSV
#if CONFIG_PM_ENABLE
    if (lock_ls) {
        esp_pm_lock_release(lock_ls);
        esp_pm_lock_delete(lock_ls);
    }
    if (lock_cpu) {
        esp_pm_lock_release(lock_cpu);
        esp_pm_lock_delete(lock_cpu);
    }
#endif

    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if (srv) {
        ESP_LOGI(TAG, "Servidor HTTP ativo");
        ESP_LOGI(TAG, "CSV disponivel em: http://%s/kyber.csv", s_ip_str);
    } else {
        ESP_LOGE(TAG, "Falha ao iniciar servidor HTTP");
    }

    // Mantém a task viva apenas para manter o servidor HTTP
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ====== app_main ======
void app_main(void)
{
    // Inicia NVS (necessário pro Wi-Fi depois)
    ESP_ERROR_CHECK(nvs_flash_init());

    // Monta SPIFFS (para salvar o CSV)
    spiffs_init();

    // Cria task_bench na CPU1, como no fluxograma
    xTaskCreatePinnedToCore(
        task_bench,
        "task_bench",
        32768,   // ajuste se precisar mais/menos stack
        NULL,
        5,
        NULL,
        1        // CPU1
    );
}

