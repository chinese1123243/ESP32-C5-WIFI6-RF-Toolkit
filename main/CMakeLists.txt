# rftool main component
# 显式声明依赖, 避免 GLOB 隐藏头文件解析失败:
#   esp_timer      -> wifi_attack.c (esp_timer.h)
#   esp_driver_rmt -> rgb_led.c     (driver/rmt_tx.h, driver/rmt_encoder.h; v5.5 拆分)
#   esp_rom        -> esp_random.h (transitive, 显式稳妥)
#   driver         -> 兜底 GPIO 等
file(GLOB SRCS "*.c")
idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        console
        driver
        esp_timer
        esp_driver_rmt
        esp_rom
        esp_http_server
)
