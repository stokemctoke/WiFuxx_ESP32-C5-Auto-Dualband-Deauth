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
        esp_http_client
        esp_https_ota
        app_update
        esp-tls
        cjson
        mdns
        esp_adc
        led_strip
)
