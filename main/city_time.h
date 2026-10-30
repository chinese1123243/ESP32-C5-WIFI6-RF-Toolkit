#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 一次开机内的时间三元组.
 * 只记墙钟的话, 一次跨重启的实验参数轨迹拼不起来 (架构文档 8.3),
 * 所以 boot_count 与单调时钟必须一起带上. */
typedef struct {
    uint32_t monotonic_ms;  /* 开机至今, 单调, 不回退 */
    uint32_t wallclock_s;   /* Unix 秒; 未对时返回 0 */
    uint32_t boot_count;    /* 第几次开机, NVS 持久化, 掉电不减 */
} city_time_t;

/* 读 NVS 的 boot_count 并加一写回. 重复调用安全.
 * 必须在 nvs_flash_init() 之后调用, 否则退化为 boot_count=1. */
esp_err_t   city_time_init(void);

/* 任意任务任意上下文可调. 未初始化时内部自动补一次 init. */
city_time_t city_clock(void);

uint32_t    city_boot_count(void);
