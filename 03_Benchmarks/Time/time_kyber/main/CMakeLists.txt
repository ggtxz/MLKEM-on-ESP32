idf_component_register(SRCS "time_kyber.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash vfs esp_wifi esp_event esp_netif esp_http_server spiffs esp_timer esp_pm esp_system kem_kyber_1024)
