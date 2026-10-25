/*
 * ble_gatt.h: BLE GATT 枚举 (central 角色)
 *
 * 与 ble_scan (observer) 是两回事: 这里板子当 central, 连上第三方 BLE 设备,
 * 走完 服务 -> 特征 -> 描述符 -> 读值 四步.
 *
 * 约束:
 *   · 扫描与连接不能同时, gatt_start 会先停掉 ble_scan.
 *   · 枚举期间板子自己的 NUS (App 控制链) 不受影响, 前提是
 *     CONFIG_NIMBLE_MAX_CONNECTIONS >= 2 (板子作为 peripheral 被 App 连,
 *     再作为 central 连第三方). 实测见 设计决策 第 16 节.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BG_MAX_SVC 16
#define BG_MAX_CHR 64
#define BG_MAX_DSC 48
#define BG_MAX_VAL 48

/* 开始枚举. 非阻塞, 结果经 META,BTGATT,... 行异步返回.
 * addr 为小端 6 字节 MAC (与 ble_scan 表里一致). */
esp_err_t gatt_start(const uint8_t addr[6], uint32_t timeout_ms);

/* 断开并中止枚举 */
esp_err_t gatt_stop(void);

bool gatt_is_on(void);

/* 打印 META,BTGATT,STATUS */
void gatt_status(void);

#ifdef __cplusplus
}
#endif
