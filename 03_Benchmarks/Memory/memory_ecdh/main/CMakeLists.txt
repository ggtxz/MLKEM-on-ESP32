idf_component_register(SRCS "memory_ecdh.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash vfs esp_wifi esp_event esp_netif esp_http_server spiffs esp_timer esp_pm esp_system mbedtls)
