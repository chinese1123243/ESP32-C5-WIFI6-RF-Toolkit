/*
 * zbsniff.h: 802.15.4 (Zigbee / Thread) 混杂嗅探
 *
 * ESP32-C5 内置 802.15.4 射频, 与 Wi-Fi / BLE **分时共存**（共享同一射频前端
 * 与同一 HP 核）。因此本模块与 Wi-Fi 嗅探/注入互斥, 启动前应先
 * wifi_attack_stop_all()（CLI 层负责）。
 *
 * 与 Wi-Fi 嗅探的关键差异：
 *   802.15.4 的 esp_ieee802154_receive_done() 回调运行在 **ISR 上下文**，
 *   里面绝不能碰 flash / PSRAM / printf。故：
 *     - 抓包表放 **内部 RAM 静态数组**（非 PSRAM），避免 flash 操作期间 cache
 *       关闭导致 PSRAM 访问崩溃；
 *     - 只用纯字节拷贝循环（不调 memcpy，因其可能在 flash）；
 *     - 不做任何打印，进度由独立任务在 1s 周期输出。
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 802.15.4 2.4 GHz 信道 11..26 (对应 2405..2480 MHz) */
#define ZB_CH_MIN   11
#define ZB_CH_MAX   26
/* PSDU 上限 (含 FCS) 127 字节 */
#define ZB_FRAME_MAX 127
/* 抓包环形表容量 (放 PSRAM, 不占宝贵内部 RAM) */
#define ZB_TAB_MAX  512

/* 在 channel (11..26) 上启动混杂嗅探. 已运行返回 ESP_ERR_INVALID_STATE. */
esp_err_t zbsniff_start(uint8_t channel);

/* 停止嗅探并释放射频 (回到 Wi-Fi/BLE). 未运行返回 ESP_ERR_INVALID_STATE. */
esp_err_t zbsniff_stop(void);

bool     zbsniff_is_on(void);
uint32_t zbsniff_total(void);      /* 累计收帧数 (含被环形表覆盖的) */
int      zbsniff_count(void);      /* 当前表中条数 (<= ZB_TAB_MAX) */
void     zbsniff_clear(void);      /* 清空表与计数 */

/* 读第 i 条 (0 = 最旧). 返回写入 out 的字节数 (含 1 字节长度域), 0 = 无此条.
 * 任一 out 参数可传 NULL. ts_hi/ts_lo 为硬件 SFD 时间戳 (原样返回). */
int zbsniff_get(int i, uint8_t *out, int out_max, int8_t *rssi,
                uint8_t *lqi, uint8_t *channel, uint64_t *ts);

/* 打印 META,ZB,STATUS 行 */
void zbsniff_status(void);

#ifdef __cplusplus
}
#endif
