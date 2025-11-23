idf_component_register(SRCS "energy_ecdh.c"
                      INCLUDE_DIRS "."
                      REQUIRES mbedtls esp_timer esp_system ina226 nvs_flash esp_event esp_wifi esp_http_server spiffs)
