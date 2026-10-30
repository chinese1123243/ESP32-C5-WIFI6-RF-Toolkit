#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 射频资源位. 一个申请者可以同时持有多位 (例如门户同时要 SOFTAP 与 RX_PROMISC). */
typedef enum {
    RES_RX_PROMISC  = 1u << 0,
    RES_TX_INJECT   = 1u << 1,
    RES_SOFTAP      = 1u << 2,
    RES_15_4        = 1u << 3,
    RES_BLE_CENTRAL = 1u << 4,
} radio_res_t;

#define RADIO_RES_BITS 5
#define RADIO_RES_MASK 0x1Fu

/* 创建内部互斥量. 重复调用安全. */
esp_err_t radio_init(void);

/* 非抢占申请. 冲突时最多等 timeout_ms, 0 表示立即返回.
 * 成功拿走 need 的全部位, 失败不动任何位.
 * owner 必须是静态存储期的字符串, 仲裁器只存指针. */
esp_err_t radio_acquire(radio_res_t need, const char *owner, uint32_t timeout_ms);

/* 释放 held 中当前无人竞争的位. 传自己申请的那一组, 不要传 RADIO_RES_MASK. */
void radio_release(radio_res_t held);

/* 当前持有者, 逗号分隔; 无人持有返回 "idle".
 * 返回的是内部静态缓冲, 下次调用会被覆盖, 拿去做参数前先拷走. */
const char *radio_owner(void);

bool        radio_held(radio_res_t res);

/* 当前所有被持有位的掩码. */
uint32_t    radio_held_mask(void);

/* 资源位转 "promisc+inject" 形式. 返回内部静态缓冲, 勿长期持有. */
const char *radio_res_str(uint32_t res);

/* need 与当前持有位的冲突部分, 0 表示可申请. */
radio_res_t radio_conflict(radio_res_t need);

/* 两条冲突规则的说明, 无冲突返回 NULL. */
const char *radio_conflict_reason(radio_res_t a, radio_res_t b);

/* 判例库: 最近 n 条裁决打到 stdout. 返回实际输出条数. */
int radio_case_dump(int n);

/* 判例库容量与累计条数, 供健康检查与测试断言用. */
int radio_case_capacity(void);
uint32_t radio_case_total(void);
