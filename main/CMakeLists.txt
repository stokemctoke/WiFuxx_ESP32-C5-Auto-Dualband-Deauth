idf_component_register(
    SRCS "main.c" "settings.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_timer
        driver
        esp_http_server
        cjson
        mdns
)
