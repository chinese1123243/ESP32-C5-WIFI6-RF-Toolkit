/*
 * locate.h: 信号定位 / 采样导出
 *
 * 对单个 AP 或客户端做定点 RSSI 采样 (2Hz), 输出实时趋势与 min/avg/max,
 * 采样点可导出 CSV (ms,rssi,channel) 供 App/PC 画热力图.
 * 只读数据库, 不额外占用射频; 需要嗅探正在跑才有新样本 (RSSI 随包刷新).
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t locate_start(const uint8_t mac[6], bool is_client, uint32_t secs);
void      locate_stop(void);
bool      locate_running(void);
void      locate_status(void);
int       locate_export_csv(void);     /* 打印 CSV, 返回行数 */
int       locate_samples(void);

#ifdef __cplusplus
}
#endif
