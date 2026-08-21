/*
 * rgb_led.h — 板载 WS2812B-0807 RGB LED 状态指示
 *
 * 硬件: WS2812 DIN 接 GPIO27 (经 RGB_CTRL 电源门控, 运行时常通).
 *   GPIO27 是 strapping 脚, strapping 仅复位时采样, 运行时作 GPIO 输出无碍
 *   (pancake 项目 + Espressif DevKitC-1 均用 GPIO27 作 NeoPixel, 已实测点亮).
 *
 * 驱动: RMT TX + 自定义 bytes/copy encoder 实现 WS2812 NRZ 时序
 *   (T0H=0.3us T0L=0.9us T1H=0.9us T1L=0.3us reset>=50us).
 * 参考实现: ESP-IDF v5.5.3 examples/peripherals/rmt/led_strip/led_strip_encoder.c
 *
 * 状态语义 (与 wifi_attack 状态机联动):
 *   RGB_OFF     黑 (固件启动早期 / 显式关灯)
 *   RGB_BOOT    启动中 (紫色, init 完成前)
 *   RGB_IDLE    空闲待命 (暗蓝, REPL 可输入)
 *   RGB_SNIFF   嗅探中 (绿色, promiscuous active)
 *   RGB_INJECT  注入中 (红色, deauth/beacon flood active)
 *   RGB_ERROR   错误 (红色快闪 / 亮红)
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RGB_OFF = 0,
    RGB_BOOT,
    RGB_IDLE,
    RGB_SNIFF,
    RGB_INJECT,
    RGB_ERROR,
} rgb_status_t;

/* 初始化 RMT 通道 + encoder, 点亮紫色 (BOOT). 失败返回非 ESP_OK.
 * 多次调用安全: 仅首次生效. */
esp_err_t rgb_led_init(void);

/* 直接设 RGB (0..255). 立即生效. */
esp_err_t rgb_led_set(uint8_t r, uint8_t g, uint8_t b);

/* 按状态枚举设色 (静态映射). */
esp_err_t rgb_led_set_status(rgb_status_t s);

/* 短暂闪烁 (per-packet / per-tx 视觉反馈): 设 (r,g,b), 延时 ms, 恢复上次状态色.
 * 注意: 内部 vTaskDelay, 不可在中断/回调里调用. 高频路径慎用. */
void rgb_led_pulse(uint8_t r, uint8_t g, uint8_t b, uint32_t ms);

#ifdef __cplusplus
}
#endif
