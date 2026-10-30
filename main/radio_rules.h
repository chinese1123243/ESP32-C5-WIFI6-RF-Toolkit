#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 射频资源位. 与 radio_arb.h 的 radio_res_t 必须逐位一致; */
/* 这里单独定义是为了让本文件不依赖 ESP-IDF, 能直接拿到主机上编译测试. */
typedef enum {
    RULE_RX_PROMISC  = 1u << 0,
    RULE_TX_INJECT   = 1u << 1,
    RULE_SOFTAP      = 1u << 2,
    RULE_15_4        = 1u << 3,
    RULE_BLE_CENTRAL = 1u << 4,
} rule_res_t;

#define RULE_RES_BITS 5
#define RULE_RES_MASK 0x1Fu

/* need 与已占用的 held 冲突的位; 0 表示可申请. 纯函数, 无全局状态. */
uint32_t radio_rules_conflict(uint32_t need, uint32_t held);

/* 两条资源位是否被某条规则判为互斥, 是则返回理由, 否则 NULL. */
const char *radio_rules_reason(uint32_t a, uint32_t b);

/* 规则条数, 供测试遍历全表. */
int radio_rules_count(void);

/* 第 i 条规则的两端与理由, 越界返回 false. */
bool radio_rules_at(int i, uint32_t *a, uint32_t *b, const char **why);

/* 资源位转 "promisc+inject". 无位时写 "none". */
void radio_rules_name(uint32_t res, char *out, size_t cap);
