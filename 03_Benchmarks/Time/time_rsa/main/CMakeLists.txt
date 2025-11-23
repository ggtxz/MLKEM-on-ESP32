idf_component_register(SRCS "time_rsa.c"
                    INCLUDE_DIRS "."
                    REQUIRES mbedtls nvs_flash vfs esp_wifi esp_event esp_netif esp_http_server spiffs esp_timer esp_pm esp_system)
