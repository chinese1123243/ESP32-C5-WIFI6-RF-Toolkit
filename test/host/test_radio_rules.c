#include <stdio.h>
#include <string.h>

#include "radio_rules.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

int main(void)
{
    /* 规则条数钉死: 表里少一条(被误删或被重构吃掉)这条就失败.
     * 只测"能编译"抓不到漏规则. */
    CHECK(radio_rules_count() == 6, "规则条数 6");

    /* 每条规则两端必须互相判冲突, 双向都要成立 */
    for (int i = 0; i < radio_rules_count(); i++) {
        uint32_t a = 0, b = 0;
        const char *why = NULL;
        if (!radio_rules_at(i, &a, &b, &why)) {
            CHECK(0, "radio_rules_at 越界");
            continue;
        }
        CHECK(why && why[0], "规则有理由文本");
        CHECK(radio_rules_conflict(a, b) == b, "need=a held=b 命中 b");
        CHECK(radio_rules_conflict(b, a) == a, "need=b held=a 命中 a");
        CHECK(radio_rules_reason(a, b) == why, "reason(a,b) 取自表");
        CHECK(radio_rules_reason(b, a) == why, "reason(b,a) 取自表");
    }

    /* 无占用时任何申请都放行: 拿全位掩码逐一试 */
    for (uint32_t need = 1; need <= RULE_RES_MASK; need++) {
        CHECK(radio_rules_conflict(need, 0) == 0, "held=0 不冲突");
    }

    /* 明确不互斥的组合, 防止表被写成"见谁咬谁" */
    CHECK(radio_rules_conflict(RULE_TX_INJECT, RULE_RX_PROMISC) == 0,
          "注入与混杂抓包可共存");
    CHECK(radio_rules_conflict(RULE_SOFTAP, RULE_BLE_CENTRAL) == 0,
          "门户与 BLE 中央角色可共存");

    /* 冲突返回值只能是 held 的子集, 不能凭空冒出位 */
    for (int i = 0; i < radio_rules_count(); i++) {
        uint32_t a = 0, b = 0;
        radio_rules_at(i, &a, &b, NULL);
        uint32_t hit = radio_rules_conflict(a, b);
        CHECK((hit & ~b) == 0, "冲突位是 held 的子集");
    }

    /* 资源名拼接 */
    char buf[48];
    radio_rules_name(RULE_RX_PROMISC | RULE_TX_INJECT, buf, sizeof(buf));
    CHECK(strcmp(buf, "promisc+inject") == 0, "多位拼接");
    radio_rules_name(0, buf, sizeof(buf));
    CHECK(strcmp(buf, "none") == 0, "空位写 none");
    radio_rules_name(RULE_15_4, buf, sizeof(buf));
    CHECK(strcmp(buf, "154") == 0, "单位命名");

    /* 截断不能越界: cap 小于实际长度时只写 cap-1 个字符 */
    char tiny[4];
    radio_rules_name(RULE_RX_PROMISC, tiny, sizeof(tiny));
    CHECK(strlen(tiny) < sizeof(tiny), "小缓冲不越界");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
