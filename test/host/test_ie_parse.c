#include <stdio.h>
#include <string.h>

#include "ie_parse.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static uint8_t buf[512];

/* 拼一个 IE. 返回写入后的总长 */
static int put_ie(int p, uint8_t id, const uint8_t *val, int n)
{
    buf[p++] = id;
    buf[p++] = (uint8_t)n;
    if (n) { memcpy(buf + p, val, (size_t)n); p += n; }
    return p;
}

/* RSN IE 主体: version + group + pairwise + akm + 可选 caps */
static int build_rsn(uint8_t *o, const uint8_t akm[4], uint16_t caps, int with_caps)
{
    int p = 0;
    o[p++] = 0x01; o[p++] = 0x00;              /* version 1 */
    o[p++] = 0x00; o[p++] = 0x0F; o[p++] = 0xAC; o[p++] = 0x04;  /* group CCMP */
    o[p++] = 0x01; o[p++] = 0x00;              /* pairwise count 1 */
    o[p++] = 0x00; o[p++] = 0x0F; o[p++] = 0xAC; o[p++] = 0x04;
    o[p++] = 0x01; o[p++] = 0x00;              /* akm count 1 */
    memcpy(o + p, akm, 4); p += 4;
    if (with_caps) {
        o[p++] = (uint8_t)(caps & 0xFF);
        o[p++] = (uint8_t)(caps >> 8);
    }
    return p;
}

int main(void)
{
    ap_caps_t c;

    /* 空 IE 区: 全零, 不崩 */
    memset(&c, 0xAA, sizeof(c));
    ie_parse_ies(NULL, 0, &c);
    CHECK(c.enc == CAP_ENC_OPEN, "空 IE 判 OPEN");
    CHECK(!c.ht && !c.vht && !c.he, "空 IE 无 11n/ac/ax");
    CHECK(!c.crackable, "空 IE 不可破");

    /* WPA2-PSK, 无 PMF: 应判 WPA2 + PSK + 可离线破 */
    const uint8_t akm_psk[4] = {0x00, 0x0F, 0xAC, 0x02};
    uint8_t rsn[64];
    int n = build_rsn(rsn, akm_psk, 0x0000, 1);
    memset(&c, 0, sizeof(c));
    int p = put_ie(0, 48, rsn, n);
    ie_parse_ies(buf, p, &c);
    CHECK(c.enc == CAP_ENC_WPA2, "RSN PSK 判 WPA2");
    CHECK((c.akm & CAP_AKM_PSK) != 0, "AKM 含 PSK");
    CHECK((c.akm & CAP_AKM_SAE) == 0, "AKM 不含 SAE");
    CHECK((c.cipher & CAP_CIPHER_CCMP) != 0, "密码套件含 CCMP");
    CHECK(c.crackable, "WPA2-PSK 判可破");

    /* 关键: 两位必须分开验, 一起置的话位序写反也照样通过.
     * 802.11 RSN Capabilities: B6 = MFPR (强制), B7 = MFPC (支持). */

    /* 只置 MFPC (0x0080): 过渡模式 AP, 支持但不强制 → 不能判成 REQUIRED */
    n = build_rsn(rsn, akm_psk, 0x0080, 1);
    memset(&c, 0, sizeof(c));
    p = put_ie(0, 48, rsn, n);
    ie_parse_ies(buf, p, &c);
    CHECK((c.pmf & CAP_PMF_CAPABLE) != 0, "B7 置位读出 MFPC");
    CHECK((c.pmf & CAP_PMF_REQUIRED) == 0, "只置 MFPC 时不判 MFPR");

    /* 只置 MFPR (0x0040): 强制 PMF, 按规范隐含 MFPC */
    n = build_rsn(rsn, akm_psk, 0x0040, 1);
    memset(&c, 0, sizeof(c));
    p = put_ie(0, 48, rsn, n);
    ie_parse_ies(buf, p, &c);
    CHECK((c.pmf & CAP_PMF_REQUIRED) != 0, "B6 置位读出 MFPR");
    CHECK((c.pmf & CAP_PMF_CAPABLE) != 0, "MFPR 隐含 MFPC");

    /* SAE 单独存在: 判 WPA3, 不可离线破 */
    const uint8_t akm_sae[4] = {0x00, 0x0F, 0xAC, 0x08};
    n = build_rsn(rsn, akm_sae, 0x0000, 1);
    memset(&c, 0, sizeof(c));
    p = put_ie(0, 48, rsn, n);
    ie_parse_ies(buf, p, &c);
    CHECK(c.enc == CAP_ENC_WPA3, "SAE 判 WPA3");
    CHECK((c.akm & CAP_AKM_SAE) != 0, "AKM 含 SAE");
    CHECK(!c.crackable, "WPA3-SAE 不可离线破");

    /* HT 元素 (id 45) 只要存在就该置 ht */
    uint8_t ht[26];
    memset(ht, 0, sizeof(ht));
    memset(&c, 0, sizeof(c));
    p = put_ie(0, 45, ht, (int)sizeof(ht));
    ie_parse_ies(buf, p, &c);
    CHECK(c.ht, "HT 元素置 11n");

    /* 未知 IE 忽略, 不影响已知 IE */
    memset(&c, 0, sizeof(c));
    p = put_ie(0, 250, (const uint8_t *)"abcd", 4);
    p = put_ie(p, 45, ht, (int)sizeof(ht));
    ie_parse_ies(buf, p, &c);
    CHECK(c.ht, "未知 IE 不影响后续解析");

    /* 截断: 长度字段说 200 但只剩 3 字节, 不能越界读 */
    uint8_t trunc[8] = {48, 200, 0x01, 0x00, 0x00};
    memset(&c, 0xAA, sizeof(c));
    ie_parse_ies(trunc, (int)sizeof(trunc), &c);
    CHECK(1, "截断 IE 不崩");

    /* 长度正好用尽: id+len 后没有值 */
    uint8_t zero[8] = {45, 0};
    memset(&c, 0xAA, sizeof(c));
    ie_parse_ies(zero, 2, &c);
    CHECK(1, "零长 IE 不崩");

    /* 两个字节只有 id 没有 len */
    memset(&c, 0xAA, sizeof(c));
    ie_parse_ies(zero, 1, &c);
    CHECK(1, "只剩 id 时不越界");

    /* 字符串接口 */
    memset(&c, 0, sizeof(c));
    c.he = true;
    CHECK(strcmp(caps_std_str(&c), "11ax") == 0, "HE 判 11ax");
    c.he = false; c.vht = true;
    CHECK(strcmp(caps_std_str(&c), "11ac") == 0, "VHT 判 11ac");
    c.vht = false; c.ht = true;
    CHECK(strcmp(caps_std_str(&c), "11n") == 0, "HT 判 11n");
    c.ht = false;
    CHECK(strcmp(caps_std_str(&c), "11a/g") == 0, "都没有判 11a/g");

    memset(&c, 0, sizeof(c));
    c.akm = CAP_AKM_PSK | CAP_AKM_SAE;
    char s[32];
    caps_akm_str(&c, s, sizeof(s));
    CHECK(strstr(s, "PSK") != NULL, "AKM 串含 PSK");
    CHECK(strstr(s, "SAE") != NULL, "AKM 串含 SAE");

    /* 小缓冲不能越界 */
    char tiny[2];
    memset(tiny, 0x7F, sizeof(tiny));
    caps_akm_str(&c, tiny, sizeof(tiny));
    CHECK(tiny[sizeof(tiny) - 1] == 0, "AKM 串小缓冲以 NUL 结尾");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
