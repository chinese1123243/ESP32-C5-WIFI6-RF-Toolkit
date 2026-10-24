# rftool main component
# 显式声明依赖, 避免 GLOB 隐藏头文件解析失败:
#   esp_timer      -> wifi_attack.c (esp_timer.h)
#   esp_driver_rmt -> rgb_led.c     (driver/rmt_tx.h, driver/rmt_encoder.h; v5.5 拆分)
#   esp_rom        -> esp_random.h (transitive, 显式稳妥)
#   driver         -> 兜底 GPIO 等
# 注意: 这里是 configure 期 glob. 新增 .c 文件后必须重新 configure
# (idf.py reconfigure), 否则新文件不会被编进去.
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
        bt
        ieee802154
        app_update
        esp_http_client
        mbedtls          # 仅用于上传镜像的 SHA-256 校验（不链 TLS）
)

# 链接选项:
#   --wrap=_write_r: 拦截 stdout 写入, 实现 BLE 命令输出捕获
#   --allow-multiple-definition: 覆盖 libnet80211 的 ieee80211_raw_frame_sanity_check
#     (本组件先于 esp_wifi 链接, 故本组件定义生效)
target_link_options(${COMPONENT_LIB} PUBLIC
    "-Wl,--wrap=_write_r"
    "-Wl,--allow-multiple-definition"
)
