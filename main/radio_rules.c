#include "radio_rules.h"

#include <stdio.h>
#include <string.h>

/* 冲突规则数据化. 比架构文档的五行多一组 TX_INJECT / 15_4:
 * cmd_zbsniff 与 cmd_zbtx 都会先调 wifi_attack_stop_all(), 说明注入与 15.4
 * 实际互斥, 文档漏了这一对. */
typedef struct {
    uint32_t a;
    uint32_t b;
    const char *why;
} rule_t;

static const rule_t k_rules[] = {
    { RULE_RX_PROMISC, RULE_SOFTAP,      "门户独占射频" },
    { RULE_RX_PROMISC, RULE_15_4,        "15.4 与 Wi-Fi 分时共用前端" },
    { RULE_TX_INJECT,  RULE_SOFTAP,      "门户独占射频" },
    { RULE_TX_INJECT,  RULE_15_4,        "注入与 15.4 共用前端" },
    { RULE_15_4,       RULE_BLE_CENTRAL, "控制器需交出射频" },
    { RULE_RX_PROMISC, RULE_BLE_CENTRAL, "枚举需第 2 条连接" },
};

#define RULE_N ((int)(sizeof(k_rules) / sizeof(k_rules[0])))

static const char *const k_names[RULE_RES_BITS] = {
    "promisc", "inject", "softap", "154", "ble_central",
};

uint32_t radio_rules_conflict(uint32_t need, uint32_t held)
{
    uint32_t hit = 0;
    for (int i = 0; i < RULE_N; i++) {
        if ((need & k_rules[i].a) && (held & k_rules[i].b)) hit |= k_rules[i].b;
        if ((need & k_rules[i].b) && (held & k_rules[i].a)) hit |= k_rules[i].a;
    }
    return hit;
}

const char *radio_rules_reason(uint32_t a, uint32_t b)
{
    for (int i = 0; i < RULE_N; i++) {
        uint32_t x = k_rules[i].a, y = k_rules[i].b;
        if (((a & x) && (b & y)) || ((a & y) && (b & x))) return k_rules[i].why;
    }
    return NULL;
}

int radio_rules_count(void) { return RULE_N; }

bool radio_rules_at(int i, uint32_t *a, uint32_t *b, const char **why)
{
    if (i < 0 || i >= RULE_N) return false;
    if (a) *a = k_rules[i].a;
    if (b) *b = k_rules[i].b;
    if (why) *why = k_rules[i].why;
    return true;
}

void radio_rules_name(uint32_t res, char *out, size_t cap)
{
    if (!out || cap == 0) return;
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < RULE_RES_BITS; i++) {
        if (!(res & (1u << i))) continue;
        int n = snprintf(out + used, cap - used, "%s%s",
                         used ? "+" : "", k_names[i]);
        if (n < 0 || (size_t)n >= cap - used) break;
        used += (size_t)n;
    }
    if (!out[0]) snprintf(out, cap, "none");
}
