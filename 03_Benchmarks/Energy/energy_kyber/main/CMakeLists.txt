idf_component_register(SRCS "energy_kyber.c"
                      INCLUDE_DIRS "."
                      REQUIRES kem_kyber_768 esp_timer esp_system ina226 nvs_flash esp_event esp_wifi esp_http_server spiffs)
