// main/energy_kyber.c
// Kyber bench + energia média ALINHADO AO FLUXOGRAMA:
//
// CPU 0 -> task_ina (Core 0)
//   - Fase idle: g_phase = PHASE_IDLE       -> coleta P_idle e escreve no acumulador
//   - Fase bench: g_phase = PHASE_BENCH     -> coleta P_bench e escreve no acumulador
//   - Fases neutras: g_phase = PHASE_NEUTRAL -> não acumula nada
//
// CPU 1 -> task_bench (Core 1)
//   - Fase idle: Delay para coleta do P_idle
//   - Fase neutra: aquecimento (WARMUP iterações)
//   - Fase bench: benchmark de N_ITERS com marcação de tempo
//   - Fase neutra final: lê o acumulador, calcula P_idle, P_bench, Δt, E_total_mJ,
//                        E_por_op_µJ e registra em formato CSV (linha ENERGY,...)

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
#include "kem768.h"
#include "coins.h"

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

// ===== Fases de energia (para o fluxograma) =====
typedef enum {
    PHASE_IDLE = 0,    // coleta P_idle
    PHASE_BENCH = 1,   // coleta P_bench
    PHASE_NEUTRAL = 2  // não acumula (fases neutras)
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

// Janela temporal do bench (CPU1 marca início/fim)
static volatile uint64_t g_bench_t0_us = 0;
static volatile uint64_t g_bench_t1_us = 0;

// Flag: INA disponível?
static volatile bool g_ina_ok = false;

// ====== task_ina (CPU0) — segue a coluna da esquerda do fluxograma ======
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
        .max_current_A  = 0.2048f,   // ou 0.4096f se o pico for menor que ~410 mA
        .install_driver = true
    };

    if (ina226_init(&dev, &cfg) != ESP_OK) {
        g_ina_ok = false;
        vTaskDelete(NULL);
        return;
    }
    g_ina_ok = true;

    // Config rápida: AVG=1, VBUSCT=140us, VSHCT=140us, modo contínuo
    ina226_set_config(&dev, /*avg*/0, /*vbusct*/0, /*vshct*/0);

    // Amostragem ~10 ms (>= 1 tick); suficiente para média/energia total
    const int INA_PERIOD_MS = 10;
    TickType_t period = pdMS_TO_TICKS(INA_PERIOD_MS);
    if (period == 0) period = 1;
    TickType_t last = xTaskGetTickCount();

    for (;;) {
        int32_t mv = 0, ma = 0, mw = 0;
        if (ina226_read_bus_voltage_mv(&dev, &mv) == ESP_OK &&
            ina226_read_current_ma(&dev, &ma) == ESP_OK &&
            ina226_read_power_mw(&dev, &mw) == ESP_OK) {

            phase_t ph = g_phase;

            // Fase neutra: não acumula nada
            if (ph == PHASE_IDLE) {
                // Fase neutra (P_idle) no fluxograma:
                // "Coleta amostras para cálculo do P_idle e escreve no acumulador"
                g_acc.idle_sum_mw  += (uint64_t) mw;
                g_acc.idle_n       += 1;
            } else if (ph == PHASE_BENCH) {
                // Fase bench no fluxograma:
                // "Coleta amostras para cálculo do P_bench e escreve no acumulador"
                g_acc.bench_sum_mw += (uint64_t) mw;
                g_acc.bench_n      += 1;
            }
            // PHASE_NEUTRAL -> não faz nada
        }

        vTaskDelayUntil(&last, period);
    }
}

// ===== Guard RTC para evitar rerun acidental =====
typedef struct { uint32_t magic; bool done; } rtc_guard_t;
#define GUARD_MAGIC 0xB16B00B5
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

// ====== task_bench (CPU1) — segue a coluna da direita do fluxograma ======
static void bench_task(void *arg)
{
    if (g_guard.done) {
        // Já rodou uma vez; não roda de novo
        for (;;) {
            vTaskDelay(portMAX_DELAY);
        }
    }

#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "bench", &lock_cpu);
    esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "bench", &lock_ls);
    if (lock_cpu) esp_pm_lock_acquire(lock_cpu);
    if (lock_ls)  esp_pm_lock_acquire(lock_ls);
#endif

    // ---------- Fase idle (fluxograma) ----------
    // CPU1: "Delay para coleta do P_idle"
    // CPU0 (task_ina): g_phase = PHASE_IDLE -> acumula P_idle no acumulador.
    g_phase = PHASE_IDLE;
    vTaskDelay(pdMS_TO_TICKS(BENCH_START_DELAY_MS));

    // ---------- Fase neutra (fluxograma) ----------
    // Pausa a coleta para o warmup, para não contaminar P_idle nem P_bench.
    g_phase = PHASE_NEUTRAL;

    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ss1[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];

    // CPU1: "Aquecimento de 100 iterações"
    for (int i = 0; i < WARMUP; i++) {
        int idx = i % 1000;
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, COINS_KEYPAIR[idx]);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss1, pk, COINS_ENC[idx]);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
        if ((i % 25) == 0) {
            vTaskDelay(0);
        }
    }

    // ---------- Fase bench (fluxograma) ----------
    // Marca t0, muda g_phase para PHASE_BENCH e executa o benchmark.
    g_bench_t0_us = esp_timer_get_time();
    g_phase       = PHASE_BENCH;

    // CPU1: "Benchmark de 1000 iterações com marcação de tempo"
    for (int i = 0; i < N_ITERS; i++) {
        int idx = i % 1000;

        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, COINS_KEYPAIR[idx]);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss1, pk, COINS_ENC[idx]);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);

        if ((i % 25) == 0) {
            vTaskDelay(0);
        }
    }

    g_bench_t1_us = esp_timer_get_time();
    g_phase       = PHASE_NEUTRAL;  // volta para fase neutra

    // Dá um tempo para a task_ina registrar as últimas amostras de bench
    vTaskDelay(pdMS_TO_TICKS(20));

    // ---------- Fase neutra final (fluxograma) ----------
    // Aqui é onde a CPU1:
    //  - "Lê amostras de P_idle e P_bench do acumulador para calcular as saídas"
    //  - "Registra valores de saída no CSV (...)"
    if (!g_ina_ok || (g_acc.idle_n == 0 && g_acc.bench_n == 0)) {
        // Sem INA, ainda assim imprime linha para facilitar parsing
        // Formato: ENERGY,NaN,NaN,NaN,NaN,NaN,NaN
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");
        fflush(stdout);
    } else {
        // Copia o acumulador para variáveis locais (fase neutra, sem escrita concorrente)
        uint64_t idle_sum_mw  = g_acc.idle_sum_mw;
        uint32_t idle_n       = g_acc.idle_n;
        uint64_t bench_sum_mw = g_acc.bench_sum_mw;
        uint32_t bench_n      = g_acc.bench_n;

        double P_idle_mW  = (idle_n  ? (double) idle_sum_mw  / (double) idle_n  : 0.0);
        double P_bench_mW = (bench_n ? (double) bench_sum_mw / (double) bench_n : 0.0);
        double dP_mW      = P_bench_mW - P_idle_mW;
        double dt_ms      = (double)(g_bench_t1_us - g_bench_t0_us) / 1000.0;

        // Energia extra do bench: (P_bench - P_idle) * dt
        double E_total_uJ = dP_mW * dt_ms;       // mW*ms = µJ
        double E_total_mJ = E_total_uJ / 1000.0; // mJ
        double E_per_uJ   = (N_ITERS ? E_total_uJ / (double) N_ITERS : 0.0);

        // Linha única em formato CSV, coerente com o resto dos seus scripts:
        // ENERGY,P_idle_mW,P_bench_mW,delta_mW,dt_ms,E_total_mJ,E_por_op_µJ
        printf("ENERGY,%.3f,%.3f,%.3f,%.3f,%.6f,%.6f\n",
               P_idle_mW, P_bench_mW, dP_mW, dt_ms, E_total_mJ, E_per_uJ);
        fflush(stdout);
    }

#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls);  }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    g_guard.done = true;

    // Mantém a task viva, mas inofensiva
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ====== app_main ======
void app_main(void)
{
    guard_init_on_boot();

    // task_ina -> CPU0 (coluna esquerda)
    xTaskCreatePinnedToCore(ina_task,
                            "ina_stream",
                            INA_TASK_STACK,
                            NULL,
                            INA_TASK_PRIO,
                            NULL,
                            INA_TASK_CORE);

    // task_bench -> CPU1 (coluna direita)
    xTaskCreatePinnedToCore(bench_task,
                            "kyber_bench",
                            BENCH_TASK_STACK,
                            NULL,
                            BENCH_TASK_PRIO,
                            NULL,
                            BENCH_TASK_CORE);

    // app_main fica ocioso
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

