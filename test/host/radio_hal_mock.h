#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/* 记录 mock 收到的调用, 供断言"到底发了什么帧". */
typedef struct {
    int      tx_calls;
    uint8_t  last_tx[512];
    int      last_len;
    bool     last_sys_seq;
    esp_err_t tx_ret;     /* 测试可以改成失败码, 验证错误能透传 */
    int      rand_calls;
    uint8_t  rand_fill;
} radio_hal_mock_t;

/* 装上 mock 并清零计数 */
void radio_hal_mock_install(void);

/* 读当前 mock 状态 (可直接改 tx_ret / rand_fill) */
radio_hal_mock_t *radio_hal_mock(void);
