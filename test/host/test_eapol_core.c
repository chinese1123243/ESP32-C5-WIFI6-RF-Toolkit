#include <stdio.h>
#include <string.h>

#include "eapol_core.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static uint8_t buf[256];

/* 在 99 字节前缀之后放一个 PMKID KDE, 返回总长 */
static int build_pmkid_frame(const uint8_t pmkid[16])
{
    memset(buf, 0, sizeof(buf));
    int p = EAPOL_KD_OFF;
    buf[p++] = 0xDD;
    buf[p++] = 20;                 /* 4 (OUI+type) + 16 (pmkid) */
    buf[p++] = 0x00; buf[p++] = 0x0F; buf[p++] = 0xAC; buf[p++] = 0x04;
    memcpy(buf + p, pmkid, 16); p += 16;
    return p;
}

int main(void)
{
    /* --- 消息号: 逐位验, 尤其 0x0008 是 Key Type 不是 MIC --- */
    CHECK(eapol_msg_no(0x0080) == 1, "0x0080 判 M1 (ACK, 无 MIC)");
    CHECK(eapol_msg_no(0x0100) == 2, "0x0100 判 M2 (MIC, 无 SECURE)");
    CHECK(eapol_msg_no(0x0180) == 3, "0x0180 判 M3 (ACK + MIC)");
    CHECK(eapol_msg_no(0x0300) == 4, "0x0300 判 M4 (MIC + SECURE)");

    /* 历史 bug 的回归锚点: Key Type 位不能参与消息号判定.
     * 当年把 MIC 写成 0x0008, 真实 M1 一直被当 M3, PMKID 提取从未执行. */
    CHECK(eapol_msg_no(0x0008) == 0, "0x0008 (仅 Key Type) 不是任何消息");
    CHECK(eapol_msg_no(0x0088) == 1, "0x0088 仍是 M1, Key Type 不影响");
    CHECK(eapol_msg_no(0x0188) == 3, "0x0188 仍是 M3");
    CHECK(eapol_msg_no(0x0000) == 0, "0x0000 认不出");
    CHECK(eapol_msg_no(0x0200) == 0, "只有 SECURE 认不出");

    /* 真实抓包常见的组合: M1 带 Key Type + ACK = 0x008A */
    CHECK(eapol_msg_no(0x008A) == 1, "0x008A (ACK|KeyType|ver2) 判 M1");

    /* --- PMKID 提取 --- */
    uint8_t pmkid[16], got[16];
    for (int i = 0; i < 16; i++) pmkid[i] = (uint8_t)(0xA0 + i);
    int n = build_pmkid_frame(pmkid);

    memset(got, 0, sizeof(got));
    CHECK(eapol_extract_pmkid(buf, n, got), "找到 PMKID");
    CHECK(memcmp(got, pmkid, 16) == 0, "PMKID 内容正确");

    /* 少一个字节: KDE 长度谎报, 必须拒绝且不写 out */
    memset(got, 0x5A, sizeof(got));
    CHECK(!eapol_extract_pmkid(buf, n - 1, got), "长度谎报时拒绝");
    CHECK(got[0] == 0x5A, "拒绝时不写 out");

    /* 刚好只有前缀: 进不了循环 */
    CHECK(!eapol_extract_pmkid(buf, EAPOL_KD_OFF, got), "只有前缀时拒绝");
    CHECK(!eapol_extract_pmkid(buf, EAPOL_KD_OFF - 1, got), "比前缀还短时拒绝");
    CHECK(!eapol_extract_pmkid(buf, 0, got), "len=0 拒绝");
    CHECK(!eapol_extract_pmkid(NULL, n, got), "eapol=NULL 拒绝");
    CHECK(!eapol_extract_pmkid(buf, n, NULL), "out=NULL 拒绝");

    /* 先放一个同类型但 OUI 不对的 KDE, 再放真的: 必须跳过第一个 */
    memset(buf, 0, sizeof(buf));
    int p = EAPOL_KD_OFF;
    buf[p++] = 0xDD; buf[p++] = 4;
    buf[p++] = 0x00; buf[p++] = 0x50; buf[p++] = 0xF2; buf[p++] = 0x04;  /* 微软 OUI */
    buf[p++] = 0xDD; buf[p++] = 20;
    buf[p++] = 0x00; buf[p++] = 0x0F; buf[p++] = 0xAC; buf[p++] = 0x04;
    memcpy(buf + p, pmkid, 16); p += 16;
    memset(got, 0, sizeof(got));
    CHECK(eapol_extract_pmkid(buf, p, got), "跳过异 OUI 后找到 PMKID");
    CHECK(memcmp(got, pmkid, 16) == 0, "跳过异 OUI 后内容正确");

    /* 非 DD 类型的 IE 也要跳过 */
    memset(buf, 0, sizeof(buf));
    p = EAPOL_KD_OFF;
    buf[p++] = 0x30; buf[p++] = 4; buf[p++] = 1; buf[p++] = 2; buf[p++] = 3; buf[p++] = 4;
    buf[p++] = 0xDD; buf[p++] = 20;
    buf[p++] = 0x00; buf[p++] = 0x0F; buf[p++] = 0xAC; buf[p++] = 0x04;
    memcpy(buf + p, pmkid, 16); p += 16;
    CHECK(eapol_extract_pmkid(buf, p, got), "跳过非 DD 后找到 PMKID");

    /* KDE 长度小于 20 (没有完整 PMKID) 不能当成命中 */
    memset(buf, 0, sizeof(buf));
    p = EAPOL_KD_OFF;
    buf[p++] = 0xDD; buf[p++] = 6;
    buf[p++] = 0x00; buf[p++] = 0x0F; buf[p++] = 0xAC; buf[p++] = 0x04;
    buf[p++] = 0x11; buf[p++] = 0x22;
    CHECK(!eapol_extract_pmkid(buf, p, got), "KDE 太短不算命中");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
