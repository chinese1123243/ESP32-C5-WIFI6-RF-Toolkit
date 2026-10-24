/*
 * scenario.h: 攻击编排 (一键场景)
 *
 * 单射频约束决定了"同时抓包+注入"是假命题, 所以场景本质是**时分编排**:
 *   handshake = (嗅探 N 秒 -> 定向 deauth -> 再嗅探) 循环, 直到拿到可破解握手
 *   survey    = 自适应信道轮询 + 汇总
 *   pmf       = 先判 PMF, 必需时直接给出"换路径"的结论, 不白打
 *
 * 所有阶段都通过 event_bus 上报, 串口/BLE/HTTP 三端可见.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t scenario_survey(uint32_t secs);
esp_err_t scenario_handshake(const uint8_t bssid[6], uint32_t secs);
esp_err_t scenario_pmf(const uint8_t bssid[6]);

void        scenario_stop(void);
bool        scenario_running(void);
void        scenario_status(void);
const char *scenario_kind_str(void);

/* 目标 AP 是否强制 PMF (MFPR). 未入库返回 false. */
bool        wifi_target_pmf_required(const uint8_t bssid[6]);

#ifdef __cplusplus
}
#endif
