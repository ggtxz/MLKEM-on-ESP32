idf_component_register(SRCS "energy_rsa.c"
                    INCLUDE_DIRS "."
                    REQUIRES ina226 esp_adc mbedtls nvs_flash vfs esp_wifi esp_event esp_netif esp_http_server spiffs esp_timer esp_pm esp_system)
