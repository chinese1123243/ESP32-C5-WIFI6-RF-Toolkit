/*
 * wifi_attack.h — Wi-Fi 攻击模块 (嗅探 / deauth 注入 / beacon flood / probe flood)
 *
 * 设计: 状态机 + 独立 FreeRTOS 注入任务. 嗅探在 promiscuous 回调内直接打印
 *   PKT/HEX 行 (低延迟, 不经队列). 注入由独立 task 循环 esp_wifi_80211_tx.
 *
 * 约束: 同一时刻仅一个注入任务运行; 启动新注入会停止旧任务. 嗅探与注入
 *   理论可并发 (STA 模式 RF 前端分时), 但实测注入会显著打断 RX, 故建议
 *   嗅探与 deauth/beacon flood 互斥 (cli 层强制).
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 模块状态 */
typedef enum {
    WIFI_ATK_IDLE = 0,
    WIFI_ATK_SNIFF,
    WIFI_ATK_INJECT,
} wifi_atk_state_t;

/* 初始化 Wi-Fi: NVS / netif / event_loop / STA 模式 / start / PS_NONE.
 * 调用前 rgb_led_init 已就绪. 失败 RGB_ERROR. */
esp_err_t wifi_attack_init(void);

/* 启动 promiscuous 嗅探. channel: 1..13 (2.4G), count=0 表示持续直到 stop.
 * 返回 ESP_ERR_INVALID_STATE 若当前非 IDLE. */
esp_err_t wifi_attack_sniff_start(uint8_t channel, uint32_t count);

/* 停止嗅探. */
esp_err_t wifi_attack_sniff_stop(void);

/* 启动 deauth 注入任务. count=0 持续直到 stop. interval_ms 每发间隔.
 * bssid: 目标 AP MAC; sta: 目标站 MAC (可为 0:00:..:0 = 广播 deauth, 踢全部). */
esp_err_t wifi_attack_deauth_start(const uint8_t bssid[6], const uint8_t sta[6],
                                   uint32_t count, uint16_t reason, uint32_t interval_ms);

/* 启动 beacon flood 任务. prefix: SSID 前缀 (实际 SSID = prefix+随机N).
 * count=0 持续. interval_ms 每发间隔. */
esp_err_t wifi_attack_beacon_flood_start(const char *prefix, uint32_t count, uint32_t interval_ms);

/* 启动 probe request flood. count=0 持续. */
esp_err_t wifi_attack_probe_flood_start(uint32_t count, uint32_t interval_ms);

/* 停止当前注入任务 (若有). 安全可重复调用. */
esp_err_t wifi_attack_inject_stop(void);

/* 启动信道自动轮询嗅探. dwell_ms: 每信道停留毫秒. */
esp_err_t wifi_attack_sniff_auto_start(uint32_t dwell_ms);

/* 打印 META 状态行 (state / channel / counters). */
void wifi_attack_status(void);

/* 供外部模块 (HTTP) 读取的原子 getter. */
int      wifi_atk_state_val(void);
uint8_t  wifi_atk_channel(void);
bool     wifi_atk_auto_ch(void);
uint32_t wifi_atk_sniff_total(void);
uint32_t wifi_atk_inject_total(void);

#ifdef __cplusplus
}
#endif
