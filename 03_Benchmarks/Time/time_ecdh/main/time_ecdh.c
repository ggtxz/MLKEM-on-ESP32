// ecdh_time_bench.c — Benchmark ECDH (CPU1) -> grava CSV -> liga Wi-Fi -> serve HTTP

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

// mbedTLS
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/error.h"

static const char *TAG = "ECDH_BENCH";

#define WIFI_SSID  "VIVOFIBRA-8991"
#define WIFI_PASS  "FaMaGu@24!"

#define N_ITERS    1000
#define WARMUP     100

// Aqui está configurado para P-521; para P-256/P-384 basta trocar GID e tamanhos.
#define ECDH_GID   MBEDTLS_ECP_DP_SECP521R1
#define PUB_MAX    133
#define SEC_LEN    66

#define CSV_PATH   "/spiffs/ecdh_times.csv"

// ---- util erro ----
static void log_mbedtls_err(const char *where, int ret){
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "%s: ret=%d (%s)", where, ret, buf);
}
#define OK_OR_GOTO(call, label) \
    do{int _r=(call); if(_r!=0){log_mbedtls_err(#call,_r); goto label;}}while(0)

// ---- Wi-Fi / HTTP / SPIFFS ----
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;
static char s_ip_str[16] = "0.0.0.0";

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data){
    if (base==WIFI_EVENT && id==WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base==WIFI_EVENT && id==WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG,"Wi-Fi caiu, reconectando...");
    } else if (base==IP_EVENT && id==IP_EVENT_STA_GOT_IP) {
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

    esp_event_handler_instance_t h1,h2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &h2));

    wifi_config_t c = {0};
    strlcpy((char*)c.sta.ssid, ssid, sizeof(c.sta.ssid));
    strlcpy((char*)c.sta.password, pass, sizeof(c.sta.password));
    c.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando no AP: %s ...", ssid);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
}

static esp_err_t csv_handler(httpd_req_t *req){
    FILE *f = fopen(CSV_PATH, "r");
    if(!f){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/csv");
    char buf[1024]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)
        httpd_resp_send_chunk(req, buf, n);
    fclose(f);
    httpd_resp_send_chunk(req,NULL,0);
    return ESP_OK;
}

static httpd_handle_t start_server(void){
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server=NULL;
    if(httpd_start(&server,&config)==ESP_OK){
        httpd_uri_t uri={
            .uri="/ecdh.csv",
            .method=HTTP_GET,
            .handler=csv_handler,
            .user_ctx=NULL
        };
        httpd_register_uri_handler(server,&uri);
        return server;
    }
    return NULL;
}

static void spiffs_init(void){
    esp_vfs_spiffs_conf_t conf = {
        .base_path="/spiffs",
        .partition_label="spiffs",
        .max_files=4,
        .format_if_mount_failed=true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
    size_t total=0, used=0;
    ESP_ERROR_CHECK(esp_spiffs_info(conf.partition_label, &total, &used));
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u",
             (unsigned)total, (unsigned)used);
}

// ---- HMAC seed determinística (A/B por iteração) ----
static void hmac_sha256(const void *key, size_t klen,
                        const void *msg, size_t mlen,
                        unsigned char out[32]){
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md,
                    (const unsigned char*)key, klen,
                    (const unsigned char*)msg, mlen,
                    out);
}
static void make_seed(int iter, char side, unsigned char out[32]){
    static const char KEY[] = "TCC|ECDH|SEED|v2";
    char msg[64];
    int n = snprintf(msg,sizeof(msg),"gid=%d|side=%c|iter=%d",
                     (int)ECDH_GID, side, iter);
    hmac_sha256(KEY,sizeof(KEY)-1,msg,(size_t)n,out);
}

// ===== Benchmark task =====
static void ecdh_bench_task(void *arg)
{
#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu=NULL, lock_ls=NULL;
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX,0,"ecdh_bench",&lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP,0,"ecdh_bench",&lock_ls));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_ls));
#endif

    if(!mbedtls_ecdh_can_do(ECDH_GID)){
        ESP_LOGE(TAG,"Curva %d não suportada no build", (int)ECDH_GID);
        goto after_bench;
    }

    // Buffers de medição (tempo em us e ciclos)
    static uint32_t t_genA_us[N_ITERS], t_genB_us[N_ITERS];
    static uint32_t t_serA_us[N_ITERS], t_serB_us[N_ITERS];
    static uint32_t t_readA_us[N_ITERS], t_readB_us[N_ITERS];
    static uint32_t t_calcA_us[N_ITERS], t_calcB_us[N_ITERS];
    static uint32_t t_total_us[N_ITERS];

    static uint32_t c_genA[N_ITERS], c_genB[N_ITERS];
    static uint32_t c_serA[N_ITERS], c_serB[N_ITERS];
    static uint32_t c_readA[N_ITERS], c_readB[N_ITERS];
    static uint32_t c_calcA[N_ITERS], c_calcB[N_ITERS];
    static uint32_t c_total[N_ITERS];

    static uint8_t  ok_equal[N_ITERS];

    ESP_LOGI(TAG,"Warmup (%d) + benchmark (%d) ECDH no CPU1 (sem Wi-Fi)",
             WARMUP, N_ITERS);

    // ---------- 1) Aquecimento ----------
    for(int i=0;i<WARMUP;i++){
        mbedtls_ecp_group grp; mbedtls_ecp_group_init(&grp);
        mbedtls_mpi dA,dB,zA,zB;
        mbedtls_mpi_init(&dA); mbedtls_mpi_init(&dB);
        mbedtls_mpi_init(&zA); mbedtls_mpi_init(&zB);

        mbedtls_ecp_point QA,QB,QpeerA,QpeerB;
        mbedtls_ecp_point_init(&QA); mbedtls_ecp_point_init(&QB);
        mbedtls_ecp_point_init(&QpeerA); mbedtls_ecp_point_init(&QpeerB);

        mbedtls_hmac_drbg_context drbgA,drbgB;
        mbedtls_hmac_drbg_init(&drbgA);
        mbedtls_hmac_drbg_init(&drbgB);

        unsigned char seedA[32], seedB[32];
        make_seed(i,'A',seedA);
        make_seed(i,'B',seedB);

        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if(md==NULL){
            ESP_LOGE(TAG,"MBEDTLS_MD_SHA256 não habilitado");
            goto warmup_cleanup;
        }

        mbedtls_hmac_drbg_seed_buf(&drbgA, md, seedA, sizeof(seedA));
        mbedtls_hmac_drbg_seed_buf(&drbgB, md, seedB, sizeof(seedB));
        mbedtls_hmac_drbg_set_reseed_interval(&drbgA, 0x7fffffff);
        mbedtls_hmac_drbg_set_reseed_interval(&drbgB, 0x7fffffff);

        mbedtls_ecp_group_load(&grp, ECDH_GID);

        // gera pares
        mbedtls_ecdh_gen_public(&grp, &dA, &QA, mbedtls_hmac_drbg_random, &drbgA);
        mbedtls_ecdh_gen_public(&grp, &dB, &QB, mbedtls_hmac_drbg_random, &drbgB);

        // serializa e reimporta
        unsigned char A_pub[PUB_MAX], B_pub[PUB_MAX];
        size_t A_len=0,B_len=0;
        mbedtls_ecp_point_write_binary(&grp, &QA, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &A_len, A_pub, sizeof(A_pub));
        mbedtls_ecp_point_write_binary(&grp, &QB, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &B_len, B_pub, sizeof(B_pub));
        mbedtls_ecp_point_read_binary(&grp, &QpeerA, B_pub, B_len);
        mbedtls_ecp_check_pubkey(&grp, &QpeerA);
        mbedtls_ecp_point_read_binary(&grp, &QpeerB, A_pub, A_len);
        mbedtls_ecp_check_pubkey(&grp, &QpeerB);

        // segredo
        mbedtls_ecdh_compute_shared(&grp, &zA, &QpeerA, &dA,
                                    mbedtls_hmac_drbg_random, &drbgA);
        mbedtls_ecdh_compute_shared(&grp, &zB, &QpeerB, &dB,
                                    mbedtls_hmac_drbg_random, &drbgB);

warmup_cleanup:
        mbedtls_hmac_drbg_free(&drbgA); mbedtls_hmac_drbg_free(&drbgB);
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
        mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
        mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
        mbedtls_ecp_point_free(&QpeerA); mbedtls_ecp_point_free(&QpeerB);

        if((i%25)==0) vTaskDelay(0);
    }
    ESP_LOGI(TAG, "Warmup concluído.");

    // ---------- 2) Benchmark (1000 iterações, grava nos buffers) ----------
    for(int i=0;i<N_ITERS;i++){
        uint64_t t0=esp_timer_get_time();
        uint32_t c0=esp_cpu_get_cycle_count();

        mbedtls_ecp_group grp; mbedtls_ecp_group_init(&grp);
        mbedtls_mpi dA,dB,zA,zB;
        mbedtls_mpi_init(&dA); mbedtls_mpi_init(&dB);
        mbedtls_mpi_init(&zA); mbedtls_mpi_init(&zB);

        mbedtls_ecp_point QA,QB,QpeerA,QpeerB;
        mbedtls_ecp_point_init(&QA); mbedtls_ecp_point_init(&QB);
        mbedtls_ecp_point_init(&QpeerA); mbedtls_ecp_point_init(&QpeerB);

        mbedtls_hmac_drbg_context drbgA,drbgB;
        mbedtls_hmac_drbg_init(&drbgA);
        mbedtls_hmac_drbg_init(&drbgB);

        unsigned char seedA[32], seedB[32];
        make_seed(i,'A',seedA);
        make_seed(i,'B',seedB);

        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if(md==NULL){
            ESP_LOGE(TAG,"MBEDTLS_MD_SHA256 não habilitado");
            goto iter_fail;
        }

        if(mbedtls_hmac_drbg_seed_buf(&drbgA, md, seedA, sizeof(seedA))!=0) goto iter_fail;
        if(mbedtls_hmac_drbg_seed_buf(&drbgB, md, seedB, sizeof(seedB))!=0) goto iter_fail;
        mbedtls_hmac_drbg_set_reseed_interval(&drbgA, 0x7fffffff);
        mbedtls_hmac_drbg_set_reseed_interval(&drbgB, 0x7fffffff);

        OK_OR_GOTO( mbedtls_ecp_group_load(&grp, ECDH_GID), iter_fail );

        // --- gen A ---
        OK_OR_GOTO( mbedtls_ecdh_gen_public(&grp, &dA, &QA,
                                            mbedtls_hmac_drbg_random, &drbgA),
                    iter_fail );
        uint64_t t1=esp_timer_get_time(); uint32_t c1=esp_cpu_get_cycle_count();

        // --- gen B ---
        OK_OR_GOTO( mbedtls_ecdh_gen_public(&grp, &dB, &QB,
                                            mbedtls_hmac_drbg_random, &drbgB),
                    iter_fail );
        uint64_t t2=esp_timer_get_time(); uint32_t c2=esp_cpu_get_cycle_count();

        // --- serialize A ---
        unsigned char A_pub[PUB_MAX], B_pub[PUB_MAX];
        size_t A_len=0,B_len=0;
        OK_OR_GOTO( mbedtls_ecp_point_write_binary(&grp, &QA,
                                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &A_len, A_pub, sizeof(A_pub)),
                    iter_fail );
        uint64_t t3=esp_timer_get_time(); uint32_t c3=esp_cpu_get_cycle_count();

        // --- serialize B ---
        OK_OR_GOTO( mbedtls_ecp_point_write_binary(&grp, &QB,
                                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                   &B_len, B_pub, sizeof(B_pub)),
                    iter_fail );
        if (A_len!=PUB_MAX || B_len!=PUB_MAX || A_pub[0]!=0x04 || B_pub[0]!=0x04){
            ESP_LOGE(TAG,"Pub malformada: A_len=%u B_len=%u A0=0x%02x B0=0x%02x",
                     (unsigned)A_len,(unsigned)B_len,A_pub[0],B_pub[0]);
            goto iter_fail_after_allocs;
        }
        uint64_t t4=esp_timer_get_time(); uint32_t c4=esp_cpu_get_cycle_count();

        // --- read/validate em A (B -> A) ---
        OK_OR_GOTO( mbedtls_ecp_point_read_binary(&grp, &QpeerA, B_pub, B_len),
                    iter_fail_after_allocs );
        OK_OR_GOTO( mbedtls_ecp_check_pubkey(&grp, &QpeerA),
                    iter_fail_after_allocs );
        uint64_t t5=esp_timer_get_time(); uint32_t c5=esp_cpu_get_cycle_count();

        // --- read/validate em B (A -> B) ---
        OK_OR_GOTO( mbedtls_ecp_point_read_binary(&grp, &QpeerB, A_pub, A_len),
                    iter_fail_after_allocs );
        OK_OR_GOTO( mbedtls_ecp_check_pubkey(&grp, &QpeerB),
                    iter_fail_after_allocs );
        uint64_t t6=esp_timer_get_time(); uint32_t c6=esp_cpu_get_cycle_count();

        // --- compute_shared A ---
        OK_OR_GOTO( mbedtls_ecdh_compute_shared(&grp, &zA, &QpeerA, &dA,
                                                mbedtls_hmac_drbg_random, &drbgA),
                    iter_fail_after_allocs );
        uint64_t t7=esp_timer_get_time(); uint32_t c7=esp_cpu_get_cycle_count();

        // --- compute_shared B ---
        OK_OR_GOTO( mbedtls_ecdh_compute_shared(&grp, &zB, &QpeerB, &dB,
                                                mbedtls_hmac_drbg_random, &drbgB),
                    iter_fail_after_allocs );
        uint64_t t8=esp_timer_get_time(); uint32_t c8=esp_cpu_get_cycle_count();

        // exporta segredos e confere igualdade
        unsigned char sA[SEC_LEN], sB[SEC_LEN];
        memset(sA,0,sizeof(sA)); memset(sB,0,sizeof(sB));
        OK_OR_GOTO( mbedtls_mpi_write_binary(&zA, sA, SEC_LEN),
                    iter_fail_after_allocs );
        OK_OR_GOTO( mbedtls_mpi_write_binary(&zB, sB, SEC_LEN),
                    iter_fail_after_allocs );
        ok_equal[i] = (memcmp(sA,sB,SEC_LEN)==0);

        // ===== tempos (us) =====
        t_genA_us[i] = (uint32_t)(t1 - t0);
        t_genB_us[i] = (uint32_t)(t2 - t1);
        t_serA_us[i] = (uint32_t)(t3 - t2);
        t_serB_us[i] = (uint32_t)(t4 - t3);
        t_readA_us[i]= (uint32_t)(t5 - t4);
        t_readB_us[i]= (uint32_t)(t6 - t5);
        t_calcA_us[i]= (uint32_t)(t7 - t6);
        t_calcB_us[i]= (uint32_t)(t8 - t7);
        t_total_us[i]= (uint32_t)(t8 - t0);

        // ===== ciclos =====
        c_genA[i] = (c1 - c0);
        c_genB[i] = (c2 - c1);
        c_serA[i] = (c3 - c2);
        c_serB[i] = (c4 - c3);
        c_readA[i]= (c5 - c4);
        c_readB[i]= (c6 - c5);
        c_calcA[i]= (c7 - c6);
        c_calcB[i]= (c8 - c7);
        c_total[i]= (c8 - c0);

iter_fail_after_allocs:
        mbedtls_hmac_drbg_free(&drbgA); mbedtls_hmac_drbg_free(&drbgB);
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
        mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
        mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
        mbedtls_ecp_point_free(&QpeerA); mbedtls_ecp_point_free(&QpeerB);

        if((i%25)==0) vTaskDelay(0);
        continue;

iter_fail:
        ok_equal[i]=0;
        t_genA_us[i]=t_genB_us[i]=t_serA_us[i]=t_serB_us[i]=
            t_readA_us[i]=t_readB_us[i]=t_calcA_us[i]=t_calcB_us[i]=t_total_us[i]=0;
        c_genA[i]=c_genB[i]=c_serA[i]=c_serB[i]=
            c_readA[i]=c_readB[i]=c_calcA[i]=c_calcB[i]=c_total[i]=0;

        mbedtls_hmac_drbg_free(&drbgA); mbedtls_hmac_drbg_free(&drbgB);
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
        mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
        mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
        mbedtls_ecp_point_free(&QpeerA); mbedtls_ecp_point_free(&QpeerB);

        if((i%25)==0) vTaskDelay(0);
    }

    // ---------- 3) Escreve buffers no CSV ----------
    {
        FILE *f=fopen(CSV_PATH,"w");
        if(!f){
            ESP_LOGE(TAG,"Falha ao abrir CSV para escrita");
            goto after_bench;
        }
        fprintf(f,"iter,genA_us,genB_us,serA_us,serB_us,readA_us,readB_us,"
                  "calcA_us,calcB_us,total_us,"
                  "genA_cycles,genB_cycles,serA_cycles,serB_cycles,"
                  "readA_cycles,readB_cycles,calcA_cycles,calcB_cycles,"
                  "total_cycles,ok\n");
        for(int i=0;i<N_ITERS;i++){
            fprintf(f,
                "%d,%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32","
                "%"PRIu32",%"PRIu32",%"PRIu32","
                "%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32","
                "%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32","
                "%"PRIu32",%u\n",
                i,
                t_genA_us[i],t_genB_us[i],t_serA_us[i],t_serB_us[i],
                t_readA_us[i],t_readB_us[i],t_calcA_us[i],t_calcB_us[i],
                t_total_us[i],
                c_genA[i],c_genB[i],c_serA[i],c_serB[i],
                c_readA[i],c_readB[i],c_calcA[i],c_calcB[i],
                c_total[i],
                (unsigned)ok_equal[i]);
        }
        fclose(f);
        ESP_LOGI(TAG,"CSV gravado em %s", CSV_PATH);
    }

after_bench:
#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls); }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    // ---------- 4) Liga Wi-Fi e disponibiliza o CSV ----------
    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if(srv){
        ESP_LOGI(TAG,"Servidor HTTP ativo");
        ESP_LOGI(TAG,"===> ARQUIVO: http://%s/ecdh.csv <===", s_ip_str);
    } else {
        ESP_LOGE(TAG,"Falha ao iniciar servidor HTTP");
    }
    for(;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ===== app_main =====
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    spiffs_init();

    // Cria task de benchmark no CPU1 (task_bench do fluxograma)
    xTaskCreatePinnedToCore(
        ecdh_bench_task,
        "ecdh_bench",
        32768,
        NULL,
        5,
        NULL,
        1   // CPU1
    );
}

