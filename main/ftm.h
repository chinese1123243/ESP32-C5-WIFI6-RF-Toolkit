/*
 * ftm.h: 802.11mc FTM 精细测距
 *
 * RSSI 只能估"远近", FTM (RTT) 能测"多少米". ESP32-C5 原生支持 802.11mc
 * FTM Initiator. 本模块向支持 FTM 的 AP 发起测距会话, 取回 RTT 与距离估计.
 *
 * 前提:
 *   - Wi-Fi 已 init 且处于 STA 模式 (wifi_attack_init 已做)
 *   - sdkconfig: CONFIG_ESP_WIFI_FTM_ENABLE=y
 *   - 目标 AP 必须支持 802.11mc FTM Responder (否则返回 UNSUPPORTED / NO_RESPONSE)
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 注册 FTM 事件处理. 必须在 esp_wifi_init() 之后调用. */
esp_err_t ftm_init(void);

/* 对 bssid 发起一次 FTM 会话, 阻塞等结果 (最多 ~6s) 并打印报告.
 * channel: 目标 AP 主信道; frm_count: 0/16/24/32/64; burst_period: 0..100 (×100ms).
 * 已有会话进行中返回 ESP_ERR_INVALID_STATE; 超时返回 ESP_ERR_TIMEOUT. */
esp_err_t ftm_range(const uint8_t bssid[6], uint8_t channel,
                    uint8_t frm_count, uint16_t burst_period);

bool ftm_is_active(void);

#ifdef __cplusplus
}
#endif
