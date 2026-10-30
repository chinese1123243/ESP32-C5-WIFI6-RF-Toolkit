#pragma once

/* 射频与平台 HAL.
 *
 * 目的: 领域代码不再直调 esp_wifi_* / esp_random / esp_timer, 改调本接口.
 * 主机端装一份 mock 就能把整条路径搬到 PC 上跑, 不用插板.
 *
 * 边界规则: 只有真的碰硬件或芯片外设的函数才进这张表.
 * 纯字节运算 (组帧, 解析, 校验) 不进 HAL, 那些直接编译上主机.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    /* 发一个已组好的管理帧. sys_seq=true 让驱动填序号.
     * 实现必须与 esp_wifi_80211_tx(WIFI_IF_STA, ...) 语义一致. */
    esp_err_t (*tx_mgmt)(const uint8_t *frame, int len, bool sys_seq);

    /* 生成 n 字节随机数, 用于伪造 MAC 与 SSID 后缀 */
    void (*random_bytes)(void *out, size_t n);

    /* 开机至今毫秒, 单调不回退 */
    uint32_t (*millis)(void);
} radio_hal_t;

/* 取当前 HAL. 未安装时返回一份空实现, 调用不会崩, 只返回 ESP_ERR_INVALID_STATE. */
const radio_hal_t *radio_hal(void);

/* 安装实现. 传 NULL 恢复空实现. 装真机实现用 radio_hal_esp_install(). */
void radio_hal_set(const radio_hal_t *h);

/* 安装真机实现. 只存在于固件构建里 (radio_hal_esp.c); 主机端不链接该文件,
 * 由 test/host/radio_hal_mock.c 里的 radio_hal_mock_install() 代替. */
void radio_hal_esp_install(void);
