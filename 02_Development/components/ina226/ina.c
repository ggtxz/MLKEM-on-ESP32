#include "ina.h"
#include <math.h>
#include "esp_log.h"
#include "esp_check.h"

#define TAG "INA226"

// Registradores
#define REG_CONFIG       0x00
#define REG_SHUNT_V      0x01
#define REG_BUS_V        0x02
#define REG_POWER        0x03
#define REG_CURRENT      0x04
#define REG_CALIB        0x05
#define REG_MASK_EN      0x06
#define REG_ALERT_LIMIT  0x07
#define REG_DIE_ID       0xFF

// CONFIG default: AVG=16, VBUSCT=1.1ms, VSHCT=1.1ms, MODE=Shunt+Bus contínuo
// Bits: [15:0] = (AVG<<9)|(VBUSCT<<6)|(VSHCT<<3)|MODE(=0b111)
#define CONFIG_DEFAULT   0x4907

static esp_err_t i2c_write16(ina226_t *dev, uint8_t reg, uint16_t v) {
    uint8_t w[3] = {reg, (uint8_t)(v >> 8), (uint8_t)(v & 0xFF)};
    return i2c_master_write_to_device(dev->cfg.port, dev->cfg.i2c_addr, w, sizeof(w), pdMS_TO_TICKS(20));
}

static esp_err_t i2c_read16(ina226_t *dev, uint8_t reg, uint16_t *out) {
    esp_err_t err = i2c_master_write_read_device(dev->cfg.port, dev->cfg.i2c_addr, &reg, 1,
                                                 (uint8_t*)out, 2, pdMS_TO_TICKS(20));
    if (err == ESP_OK) {
        // INA226 é big-endian
        uint8_t *b = (uint8_t*)out;
        *out = ((uint16_t)b[0] << 8) | b[1];
    }
    return err;
}

esp_err_t ina226_init(ina226_t *dev, const ina226_cfg_t *cfg) {
    if (!dev || !cfg || cfg->shunt_ohms <= 0 || cfg->max_current_A <= 0) return ESP_ERR_INVALID_ARG;
    dev->cfg = *cfg;

    if (cfg->install_driver) {
        i2c_config_t conf = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = cfg->sda_io,
            .scl_io_num = cfg->scl_io,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = cfg->clk_hz,
        };
        ESP_RETURN_ON_ERROR(i2c_param_config(cfg->port, &conf), TAG, "i2c_param_config");
        ESP_RETURN_ON_ERROR(i2c_driver_install(cfg->port, I2C_MODE_MASTER, 0, 0, 0), TAG, "i2c_driver_install");
    }

    // Config inicial default
    ESP_RETURN_ON_ERROR(i2c_write16(dev, REG_CONFIG, CONFIG_DEFAULT), TAG, "write CONFIG");

    // Calibração
    // Escolhe current_LSB ~ max_current/32768 (espalha range todo)
    dev->current_LSB_A = cfg->max_current_A / 32768.0f;         // A por LSB
    // Calib = 0.00512 / (current_LSB * R_shunt)
    float cal = 0.00512f / (dev->current_LSB_A * cfg->shunt_ohms);
    if (cal > 0xFFFF) cal = 0xFFFF;
    if (cal < 1.0f)   cal = 1.0f;
    dev->calib_reg = (uint16_t)lroundf(cal);
    ESP_RETURN_ON_ERROR(i2c_write16(dev, REG_CALIB, dev->calib_reg), TAG, "write CALIB");

    dev->power_LSB_W = 25.0f * dev->current_LSB_A;              // datasheet: 25 * current_LSB

    // Teste rápido de ID (opcional)
    uint16_t id = 0;
    if (i2c_read16(dev, REG_DIE_ID, &id) == ESP_OK) {
        ESP_LOGI(TAG, "INA226 ID=0x%04X, CAL=0x%04X, I_LSB=%.6f A/LSB, P_LSB=%.6f W/LSB",
                 id, dev->calib_reg, dev->current_LSB_A, dev->power_LSB_W);
    } else {
        ESP_LOGW(TAG, "Não foi possível ler DIE_ID");
    }
    return ESP_OK;
}

// avg/vbusct/vshct índices 0..7 conforme tabela de tempos do datasheet
esp_err_t ina226_set_config(ina226_t *dev, uint8_t avg, uint8_t vbusct, uint8_t vshct) {
    if (!dev) return ESP_ERR_INVALID_ARG;
    uint16_t cfg = ((uint16_t)(avg & 0x7)    << 9) |
                   ((uint16_t)(vbusct & 0x7) << 6) |
                   ((uint16_t)(vshct  & 0x7) << 3) |
                   0x0007; // MODE=111 (Shunt+Bus contínuo)
    return i2c_write16(dev, REG_CONFIG, cfg);
}

esp_err_t ina226_read_bus_voltage_mv(ina226_t *dev, int32_t *mv) {
    if (!dev || !mv) return ESP_ERR_INVALID_ARG;
    uint16_t r;
    ESP_RETURN_ON_ERROR(i2c_read16(dev, REG_BUS_V, &r), TAG, "read BUS_V");
    // 1 LSB = 1.25 mV
    *mv = (int32_t)((r * 125) / 100);
    return ESP_OK;
}

esp_err_t ina226_read_shunt_voltage_uv(ina226_t *dev, int32_t *uv) {
    if (!dev || !uv) return ESP_ERR_INVALID_ARG;
    uint16_t r;
    ESP_RETURN_ON_ERROR(i2c_read16(dev, REG_SHUNT_V, &r), TAG, "read SHUNT_V");
    int16_t s = (int16_t)r;
    // 1 LSB = 2.5 µV
    *uv = (int32_t)s * 25 / 10;
    return ESP_OK;
}

esp_err_t ina226_read_current_ma(ina226_t *dev, int32_t *ma) {
    if (!dev || !ma) return ESP_ERR_INVALID_ARG;
    uint16_t r;
    ESP_RETURN_ON_ERROR(i2c_read16(dev, REG_CURRENT, &r), TAG, "read CURRENT");
    int16_t s = (int16_t)r;
    float A = (float)s * dev->current_LSB_A;
    *ma = (int32_t)lroundf(A * 1000.0f);
    return ESP_OK;
}

esp_err_t ina226_read_power_mw(ina226_t *dev, int32_t *mw) {
    if (!dev || !mw) return ESP_ERR_INVALID_ARG;
    uint16_t r;
    ESP_RETURN_ON_ERROR(i2c_read16(dev, REG_POWER, &r), TAG, "read POWER");
    float W = (float)r * dev->power_LSB_W;
    *mw = (int32_t)lroundf(W * 1000.0f);
    return ESP_OK;
}

esp_err_t ina226_deinit(ina226_t *dev) {
    if (!dev) return ESP_OK;
    if (dev->cfg.install_driver) {
        i2c_driver_delete(dev->cfg.port);
    }
    return ESP_OK;
}
