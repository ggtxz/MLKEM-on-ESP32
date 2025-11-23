#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_err.h"

#ifndef INA226_I2C_ADDR
#define INA226_I2C_ADDR 0x45   // ajuste p/ seu módulo (muitos usam 0x40)
#endif

typedef struct {
    i2c_port_t port;        // I2C_NUM_0 ou I2C_NUM_1
    gpio_num_t sda_io;      // ex.: GPIO_NUM_21
    gpio_num_t scl_io;      // ex.: GPIO_NUM_22
    uint32_t   clk_hz;      // ex.: 400000
    uint8_t    i2c_addr;    // ex.: 0x40..0x4F
    float      shunt_ohms;  // valor do shunt em ohms
    float      max_current_A;   // corrente máx esperada (calibração)
    bool       install_driver;  // true: instala driver I2C aqui
} ina226_cfg_t;

typedef struct {
    ina226_cfg_t cfg;
    uint16_t     calib_reg;      // valor escrito no REG_CALIB
    float        current_LSB_A;  // A por LSB (derivado de max_current)
    float        power_LSB_W;    // W por LSB (= 25 * current_LSB)
} ina226_t;

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ina226_init(ina226_t *dev, const ina226_cfg_t *cfg);

/** Configura AVG / tempos de conversão e modo contínuo Shunt+Bus.
 *  avg/vbusct/vshct são índices 0..7 conforme datasheet.
 *  Modo fixo = 0b111 (Shunt+Bus contínuo) */
esp_err_t ina226_set_config(ina226_t *dev, uint8_t avg, uint8_t vbusct, uint8_t vshct);

esp_err_t ina226_read_bus_voltage_mv(ina226_t *dev, int32_t *mv);      // LSB = 1.25 mV
esp_err_t ina226_read_shunt_voltage_uv(ina226_t *dev, int32_t *uv);    // LSB = 2.5 µV (signed)
esp_err_t ina226_read_current_ma(ina226_t *dev, int32_t *ma);          // usando calibração
esp_err_t ina226_read_power_mw(ina226_t *dev, int32_t *mw);            // usando calibração

esp_err_t ina226_deinit(ina226_t *dev);

#ifdef __cplusplus
}
#endif
