#include <stdio.h>
#include <string.h>

#include "frame_build.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static const uint8_t BSSID[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t STA[6]   = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};

static int has_bytes(const uint8_t *p, int len, const uint8_t *need, int n)
{
    for (int i = 0; i + n <= len; i++) {
        if (memcmp(p + i, need, (size_t)n) == 0) return 1;
    }
    return 0;
}

int main(void)
{
    uint8_t f[512];
    const uint8_t SSID[] = {'T', 'E', 'S', 'T'};

    /* Deauth: FC=0xC0, 26 字节, reason 用小端放在 24 */
    memset(f, 0xAA, sizeof(f));
    int n = fb_deauth(f, (int)sizeof(f), BSSID, STA, 7);
    CHECK(n == 26, "deauth 长度 26");
    CHECK(f[0] == 0xC0, "deauth FC 0xC0");
    /* deauth 由 AP 发给客户端: addr1=DA=被踢的 STA, addr2=SA=AP 的 BSSID */
    CHECK(memcmp(f + 4, STA, 6) == 0, "deauth addr1=STA (目的)");
    CHECK(memcmp(f + 10, BSSID, 6) == 0, "deauth addr2=BSSID (源)");
    CHECK(f[24] == 7 && f[25] == 0, "deauth reason 小端");

    /* Auth: FC=0xB0, 30 字节, algo/seq/status 三对小端 */
    memset(f, 0xAA, sizeof(f));
    n = fb_auth(f, (int)sizeof(f), BSSID, STA, 1, 0);
    CHECK(n == 30, "auth 长度 30");
    CHECK(f[0] == 0xB0, "auth FC 0xB0");
    CHECK(f[24] == 0 && f[25] == 0, "auth algo=0 (Open)");
    CHECK(f[26] == 1 && f[27] == 0, "auth seq=1");
    CHECK(f[28] == 0 && f[29] == 0, "auth status=0");

    /* Beacon: FC=0x80, SSID 原文出现在帧里 */
    memset(f, 0xAA, sizeof(f));
    n = fb_beacon(f, (int)sizeof(f), BSSID, SSID, (int)sizeof(SSID), 6);
    CHECK(n > 0, "beacon 构造成功");
    CHECK(f[0] == 0x80, "beacon FC 0x80");
    CHECK(has_bytes(f, n, SSID, (int)sizeof(SSID)), "beacon 含 SSID");

    /* Probe Response: FC=0x50 */
    memset(f, 0xAA, sizeof(f));
    n = fb_probe_resp(f, (int)sizeof(f), STA, BSSID, SSID, (int)sizeof(SSID), 6);
    CHECK(n > 0, "probe_resp 构造成功");
    CHECK(f[0] == 0x50, "probe_resp FC 0x50");

    /* Assoc Req: FC=0x00; 带 RSN 的那版必须更长 */
    memset(f, 0xAA, sizeof(f));
    int plain = fb_assoc_req(f, (int)sizeof(f), BSSID, STA, SSID, (int)sizeof(SSID), 6);
    CHECK(plain > 0, "assoc_req 构造成功");
    CHECK(f[0] == 0x00, "assoc_req FC 0x00");
    memset(f, 0xAA, sizeof(f));
    int rsn = fb_assoc_req_rsn(f, (int)sizeof(f), BSSID, STA, SSID, (int)sizeof(SSID), 6);
    CHECK(rsn > plain, "assoc_req_rsn 比普通版长 (多 RSN IE)");

    /* CSA: 追加 5 字节, 内容为 [37, 3, 0, ch, count] */
    memset(f, 0xAA, sizeof(f));
    n = fb_beacon(f, (int)sizeof(f), BSSID, SSID, (int)sizeof(SSID), 6);
    int base = n;
    n = fb_append_csa(f, n, (int)sizeof(f), 11, 1);
    CHECK(n == base + 5, "CSA 追加 5 字节");
    CHECK(f[base] == 37, "CSA Element ID 37");
    CHECK(f[base + 1] == 3, "CSA 长度 3");
    CHECK(f[base + 2] == 0, "CSA switch mode 0");
    CHECK(f[base + 3] == 11, "CSA 新信道 11");
    CHECK(f[base + 4] == 1, "CSA count 1");

    /* 边界: cap 差 1 字节就必须拒绝, 且不能写坏原帧 */
    uint8_t g[64];
    memset(g, 0x5A, sizeof(g));
    n = fb_beacon(g, (int)sizeof(g), BSSID, SSID, (int)sizeof(SSID), 6);
    int before = n;
    CHECK(fb_append_csa(g, n, n + 4, 11, 1) == 0, "cap 不足 5 字节拒绝");
    CHECK(g[n] == 0x5A, "拒绝时不写越界");
    CHECK(before == n, "拒绝时不改长度");

    /* 边界: len<=0 拒绝 */
    CHECK(fb_append_csa(g, 0, (int)sizeof(g), 11, 1) == 0, "len=0 拒绝");
    CHECK(fb_append_csa(NULL, 10, 100, 11, 1) == 0, "frame=NULL 拒绝");

    /* 边界: cap 小于帧长时构造器必须返回 0, 不能写爆 */
    uint8_t small[8];
    CHECK(fb_deauth(small, (int)sizeof(small), BSSID, STA, 7) == 0, "小 cap 拒绝 deauth");
    CHECK(fb_auth(small, (int)sizeof(small), BSSID, STA, 1, 0) == 0, "小 cap 拒绝 auth");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
