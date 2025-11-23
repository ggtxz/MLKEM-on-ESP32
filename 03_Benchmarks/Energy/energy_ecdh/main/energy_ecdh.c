// main/energy_ecdh.c — ECDH bench + energia média (sem Wi-Fi/HTTP, só impressão final)
// Coerente com o fluxograma:
//
// CPU 0 -> task_ina (Core 0)
//   - Fase idle: PHASE_IDLE      -> coleta P_idle e escreve no acumulador
//   - Fase bench: PHASE_BENCH    -> coleta P_bench e escreve no acumulador
//   - Fases neutras: PHASE_NEUTRAL -> não acumula nada
//
// CPU 1 -> bench_task (Core 1)
//   - Fase idle: delay para coleta do P_idle
//   - Fase neutra: aquecimento de WARMUP iterações
//   - Fase bench: benchmark de N_ITERS com marcação de tempo
//   - Fase neutra final: lê acumulador, calcula P_idle, P_bench, Δt, E_total_mJ,
//                        E_por_op_µJ e imprime CSV (linha única ENERGY,...)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_timer.h"
#include "esp_cpu.h"
#include "esp_pm.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

#include "driver/i2c.h"
#include "driver/gpio.h"

#include "ina.h"

// mbedTLS (ECDH)
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"

// ===== Parâmetros =====
#define N_ITERS              1000
#define WARMUP               100
#define BENCH_START_DELAY_MS 60000  // Fase idle: janela para medir P_idle

#ifndef INA226_I2C_ADDR
#define INA226_I2C_ADDR 0x40
#endif

#define INA_TASK_STACK   (4096)
#define INA_TASK_PRIO    (4)
#define INA_TASK_CORE    (0)

#define BENCH_TASK_STACK (40960)
#define BENCH_TASK_PRIO  (5)
#define BENCH_TASK_CORE  (1)

// ===== Curva (ajuste aqui) =====
// P-256 (não comprimido): PUB=1 + 2*32 = 65, segredo=32
#define ECDH_GID   MBEDTLS_ECP_DP_SECP256R1
// P-256: 0x04 + X(32) + Y(32) = 65 bytes; segredo exportado em 32 bytes
#define PUB_MAX    65
#define SEC_LEN    32

// ===== Fases de energia (fluxograma) =====
typedef enum {
    PHASE_IDLE    = 0,  // coleta P_idle
    PHASE_BENCH   = 1,  // coleta P_bench
    PHASE_NEUTRAL = 2   // não acumula (fases neutras)
} phase_t;

static volatile phase_t g_phase = PHASE_IDLE;

// ===== "Acumulador" de potência (mW) =====
typedef struct {
    uint64_t idle_sum_mw;
    uint32_t idle_n;
    uint64_t bench_sum_mw;
    uint32_t bench_n;
} energy_acc_t;

static volatile energy_acc_t g_acc = {0};

// Janela temporal do bench
static volatile uint64_t g_bench_t0_us = 0;
static volatile uint64_t g_bench_t1_us = 0;

// Flag: INA disponível?
static volatile bool g_ina_ok = false;

// ====== INA stream task (CPU0) ======
static void ina_task(void *arg)
{
    ina226_t dev;
    ina226_cfg_t cfg = {
        .port           = I2C_NUM_0,
        .sda_io         = GPIO_NUM_21,
        .scl_io         = GPIO_NUM_22,
        .clk_hz         = 100000,
        .i2c_addr       = INA226_I2C_ADDR,
        .shunt_ohms     = 0.100f,
        .max_current_A  = 0.2048f, // ajuste se seu pico < ~410 mA para mais resolução
        .install_driver = true
    };

    if (ina226_init(&dev, &cfg) != ESP_OK) {
        g_ina_ok = false;
        vTaskDelete(NULL);
        return;
    }
    g_ina_ok = true;

    // AVG=1, tempos curtos, modo contínuo
    ina226_set_config(&dev, /*avg*/0, /*vbusct*/0, /*vshct*/0);

    const int INA_PERIOD_MS = 10;
    TickType_t period = pdMS_TO_TICKS(INA_PERIOD_MS);
    if (period == 0) period = 1;
    TickType_t last = xTaskGetTickCount();

    for (;;) {
        int32_t mv = 0, ma = 0, mw = 0;
        if (ina226_read_bus_voltage_mv(&dev, &mv) == ESP_OK &&
            ina226_read_current_ma(&dev, &ma) == ESP_OK &&
            ina226_read_power_mw(&dev, &mw) == ESP_OK)
        {
            phase_t ph = g_phase;

            if (ph == PHASE_IDLE) {
                // Fase idle (P_idle) — escreve no acumulador
                g_acc.idle_sum_mw  += (uint64_t) mw;
                g_acc.idle_n       += 1;
            } else if (ph == PHASE_BENCH) {
                // Fase bench (P_bench) — escreve no acumulador
                g_acc.bench_sum_mw += (uint64_t) mw;
                g_acc.bench_n      += 1;
            }
            // PHASE_NEUTRAL → não acumula nada
        }
        vTaskDelayUntil(&last, period);
    }
}

// ====== Guard RTC para evitar rerun acidental ======
typedef struct { uint32_t magic; bool done; } rtc_guard_t;
#define GUARD_MAGIC 0xEC0DEC01u
static RTC_NOINIT_ATTR rtc_guard_t g_guard;

static void guard_init_on_boot(void)
{
    esp_reset_reason_t rr = esp_reset_reason();
    if (rr == ESP_RST_POWERON || rr == ESP_RST_EXT ||
        rr == ESP_RST_BROWNOUT || g_guard.magic != GUARD_MAGIC) {
        g_guard.magic = GUARD_MAGIC;
        g_guard.done  = false;
    }
}

// ====== DRBG determinístico (reprodutível) ======
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
    static const char KEY[] = "TCC|ECDH|SEED|energy";
    char msg[64];
    int n = snprintf(msg, sizeof(msg),
                     "gid=%d|side=%c|iter=%d",
                     (int) ECDH_GID, side, iter);
    hmac_sha256(KEY, sizeof(KEY) - 1, msg, (size_t) n, out);
}

// ====== Corpo de uma iteração ECDH ======
// Faz TUDO de uma vez: gen A/B, serialização, importar/validar, shared A/B.
static inline void ecdh_iter(int iter)
{
    mbedtls_ecp_group grp; mbedtls_ecp_group_init(&grp);
    mbedtls_mpi dA, dB, zA, zB;
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&zA); mbedtls_mpi_init(&zB);

    mbedtls_ecp_point QA, QB, QpeerA, QpeerB;
    mbedtls_ecp_point_init(&QA); mbedtls_ecp_point_init(&QB);
    mbedtls_ecp_point_init(&QpeerA); mbedtls_ecp_point_init(&QpeerB);

    mbedtls_hmac_drbg_context drbgA, drbgB;
    mbedtls_hmac_drbg_init(&drbgA);
    mbedtls_hmac_drbg_init(&drbgB);

    unsigned char seedA[32], seedB[32];
    make_seed(iter, 'A', seedA);
    make_seed(iter, 'B', seedB);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hmac_drbg_seed_buf(&drbgA, md, seedA, sizeof(seedA));
    mbedtls_hmac_drbg_seed_buf(&drbgB, md, seedB, sizeof(seedB));
    mbedtls_hmac_drbg_set_reseed_interval(&drbgA, 0x7fffffff);
    mbedtls_hmac_drbg_set_reseed_interval(&drbgB, 0x7fffffff);

    mbedtls_ecp_group_load(&grp, ECDH_GID);

    // gen A/B
    (void) mbedtls_ecdh_gen_public(&grp, &dA, &QA,
                                   mbedtls_hmac_drbg_random, &drbgA);
    (void) mbedtls_ecdh_gen_public(&grp, &dB, &QB,
                                   mbedtls_hmac_drbg_random, &drbgB);

    // serialize
    unsigned char A_pub[PUB_MAX], B_pub[PUB_MAX];
    size_t A_len = 0, B_len = 0;
    (void) mbedtls_ecp_point_write_binary(&grp, &QA,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &A_len, A_pub, sizeof(A_pub));
    (void) mbedtls_ecp_point_write_binary(&grp, &QB,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &B_len, B_pub, sizeof(B_pub));

    // importar/validar
    (void) mbedtls_ecp_point_read_binary(&grp, &QpeerA, B_pub, B_len);
    (void) mbedtls_ecp_check_pubkey(&grp, &QpeerA);
    (void) mbedtls_ecp_point_read_binary(&grp, &QpeerB, A_pub, A_len);
    (void) mbedtls_ecp_check_pubkey(&grp, &QpeerB);

    // shared secrets
    (void) mbedtls_ecdh_compute_shared(&grp, &zA, &QpeerA, &dA,
                                       mbedtls_hmac_drbg_random, &drbgA);
    (void) mbedtls_ecdh_compute_shared(&grp, &zB, &QpeerB, &dB,
                                       mbedtls_hmac_drbg_random, &drbgB);

    // (opcional) checagem rápida de igualdade sem prints
    (void) mbedtls_mpi_cmp_mpi(&zA, &zB);

    // cleanup
    mbedtls_hmac_drbg_free(&drbgA);
    mbedtls_hmac_drbg_free(&drbgB);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&dB);
    mbedtls_mpi_free(&zA); mbedtls_mpi_free(&zB);
    mbedtls_ecp_point_free(&QA); mbedtls_ecp_point_free(&QB);
    mbedtls_ecp_point_free(&QpeerA); mbedtls_ecp_point_free(&QpeerB);
}

// ====== Benchmark ECDH (CPU1) ======
static void bench_task(void *arg)
{
    if (g_guard.done) {
        for (;;) vTaskDelay(portMAX_DELAY);
    }

#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "bench", &lock_cpu);
    esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "bench", &lock_ls);
    if (lock_cpu) esp_pm_lock_acquire(lock_cpu);
    if (lock_ls)  esp_pm_lock_acquire(lock_ls);
#endif

    // ---------- Fase idle (fluxograma) ----------
    // CPU1: delay para coleta do P_idle
    // CPU0: g_phase = PHASE_IDLE -> task_ina acumula P_idle.
    g_phase = PHASE_IDLE;
    vTaskDelay(pdMS_TO_TICKS(BENCH_START_DELAY_MS));

    // ---------- Fase neutra (warmup) ----------
    g_phase = PHASE_NEUTRAL;

    for (int i = 0; i < WARMUP; i++) {
        ecdh_iter(i);
        if ((i % 25) == 0) vTaskDelay(0);
    }

    // ---------- Fase bench ----------
    g_bench_t0_us = esp_timer_get_time();
    g_phase       = PHASE_BENCH;

    for (int i = 0; i < N_ITERS; i++) {
        ecdh_iter(i);
        if ((i % 25) == 0) vTaskDelay(0);
    }

    g_bench_t1_us = esp_timer_get_time();
    g_phase       = PHASE_NEUTRAL; // volta para neutra

    // Dá tempo de a INA task registrar últimas amostras
    vTaskDelay(pdMS_TO_TICKS(20));

    // ---------- Fase neutra final: lê acumulador e calcula saídas ----------
    if (!g_ina_ok || (g_acc.idle_n == 0 && g_acc.bench_n == 0)) {
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");
        fflush(stdout);
    } else {
        // snapshot do acumulador (fase neutra → sem escrita concorrente)
        uint64_t idle_sum_mw  = g_acc.idle_sum_mw;
        uint32_t idle_n       = g_acc.idle_n;
        uint64_t bench_sum_mw = g_acc.bench_sum_mw;
        uint32_t bench_n      = g_acc.bench_n;

        double P_idle_mW  = (idle_n  ? (double) idle_sum_mw  / (double) idle_n  : 0.0);
        double P_bench_mW = (bench_n ? (double) bench_sum_mw / (double) bench_n : 0.0);
        double dP_mW      = P_bench_mW - P_idle_mW;
        double dt_ms      = (double)(g_bench_t1_us - g_bench_t0_us) / 1000.0;

        double E_total_uJ = dP_mW * dt_ms;       // mW*ms = µJ
        double E_total_mJ = E_total_uJ / 1000.0; // mJ
        double E_per_uJ   = (N_ITERS ? E_total_uJ / (double) N_ITERS : 0.0);

        // ÚNICA linha impressa (resultado final)
        // ENERGY,P_idle_mW,P_bench_mW,delta_mW,dt_ms,E_total_mJ,E_per_iter_uJ
        printf("ENERGY,%.3f,%.3f,%.3f,%.3f,%.6f,%.6f\n",
               P_idle_mW, P_bench_mW, dP_mW, dt_ms, E_total_mJ, E_per_uJ);
        fflush(stdout);
    }

#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls);  }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    g_guard.done = true;
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ====== app_main ======
void app_main(void)
{
    guard_init_on_boot();

    xTaskCreatePinnedToCore(ina_task,
                            "ina_stream",
                            INA_TASK_STACK,
                            NULL,
                            INA_TASK_PRIO,
                            NULL,
                            INA_TASK_CORE);

    xTaskCreatePinnedToCore(bench_task,
                            "ecdh_bench",
                            BENCH_TASK_STACK,
                            NULL,
                            BENCH_TASK_PRIO,
                            NULL,
                            BENCH_TASK_CORE);

    for (;;) vTaskDelay(portMAX_DELAY);
}

