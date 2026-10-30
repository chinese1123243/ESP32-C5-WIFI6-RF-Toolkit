#include <stdio.h>
#include <string.h>

#include "wifi_names.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

int main(void)
{
    /* --- 编码编号 -> 字符串 --- */
    CHECK(strcmp(wifi_enc_str(0), "OPEN") == 0, "0 = OPEN");
    CHECK(strcmp(wifi_enc_str(1), "WEP") == 0, "1 = WEP");
    CHECK(strcmp(wifi_enc_str(2), "WPA") == 0, "2 = WPA");
    CHECK(strcmp(wifi_enc_str(3), "WPA2") == 0, "3 = WPA2");
    CHECK(strcmp(wifi_enc_str(4), "WPA3") == 0, "4 = WPA3");
    CHECK(strcmp(wifi_enc_str(5), "WPA/W2") == 0, "5 = WPA/W2");
    CHECK(strcmp(wifi_enc_str(99), "?") == 0, "未知编号回 ?");

    /* --- 密码套件: 优先级 GCMP > CCMP > TKIP --- */
    CHECK(strcmp(wifi_cipher_str(0), "-") == 0, "无套件写 -");
    CHECK(strcmp(wifi_cipher_str(CAP_CIPHER_TKIP), "TKIP") == 0, "TKIP");
    CHECK(strcmp(wifi_cipher_str(CAP_CIPHER_CCMP), "CCMP") == 0, "CCMP");
    CHECK(strcmp(wifi_cipher_str(CAP_CIPHER_GCMP), "GCMP") == 0, "GCMP");
    CHECK(strcmp(wifi_cipher_str(CAP_CIPHER_TKIP | CAP_CIPHER_CCMP), "CCMP") == 0,
          "同时有 TKIP 与 CCMP 时报 CCMP");
    CHECK(strcmp(wifi_cipher_str(CAP_CIPHER_CCMP | CAP_CIPHER_GCMP), "GCMP") == 0,
          "同时有 CCMP 与 GCMP 时报 GCMP");

    /* --- 表项 -> caps --- */
    ap_entry_t e;
    memset(&e, 0, sizeof(e));
    e.akm = CAP_AKM_PSK;
    e.cipher = CAP_CIPHER_CCMP;
    e.ht = true;
    e.he = true;
    e.bw = 80;
    e.pmf_cap = true;
    e.pmf = false;
    ap_caps_t c;
    wifi_caps_from_entry(&e, &c);
    CHECK(c.akm == CAP_AKM_PSK, "caps 带过 akm");
    CHECK(c.cipher == CAP_CIPHER_CCMP, "caps 带过 cipher");
    CHECK(c.ht && c.he && !c.vht, "caps 带过 ht/he/vht");
    CHECK(c.bw == 80, "caps 带过带宽");
    CHECK((c.pmf & CAP_PMF_CAPABLE) != 0, "pmf_cap 置 CAPABLE");
    CHECK((c.pmf & CAP_PMF_REQUIRED) == 0, "pmf=0 不置 REQUIRED");
    CHECK(strcmp(caps_std_str(&c), "11ax") == 0, "caps 走 std 串得到 11ax");

    /* pmf 必需时也必须置 REQUIRED */
    memset(&e, 0, sizeof(e));
    e.pmf = true;
    wifi_caps_from_entry(&e, &c);
    CHECK((c.pmf & CAP_PMF_REQUIRED) != 0, "pmf=1 置 REQUIRED");

    /* --- RSSI 环形缓冲起始下标 --- */
    CHECK(wifi_hist_start(0, 0) == 0, "n=0 回 0");
    CHECK(wifi_hist_start(5, 3) == 2, "i=5,n=3 起始 2");
    CHECK(wifi_hist_start(0, 3) == 13, "i=0,n=3 起始回绕到 13");
    CHECK(wifi_hist_start(0, 16) == 0, "满 16 且 i=0 起始 0");
    CHECK(wifi_hist_start(15, 16) == 15, "满 16 且 i=15 起始 15");
    CHECK(wifi_hist_start(15, 1) == 14, "i=15,n=1 起始 14");

    /* 不变量: 排序后的最后一个样本必须是最新写入的那个位置 */
    for (int i = 0; i < WIFI_DB_RSSI_HIST; i++) {
        for (int n = 1; n <= WIFI_DB_RSSI_HIST; n++) {
            int st = wifi_hist_start((uint8_t)i, (uint8_t)n);
            int last = (st + n - 1) % WIFI_DB_RSSI_HIST;
            int newest = (i - 1 + WIFI_DB_RSSI_HIST) % WIFI_DB_RSSI_HIST;
            if (last != newest) {
                printf("  FAIL  不变量 i=%d n=%d start=%d last=%d newest=%d\n",
                       i, n, st, last, newest);
                g_fail++;
                goto done;
            }
            if (st < 0 || st >= WIFI_DB_RSSI_HIST) {
                printf("  FAIL  起始下标越界 i=%d n=%d start=%d\n", i, n, st);
                g_fail++;
                goto done;
            }
            g_pass++;
        }
    }
done:
    /* n 超过容量时按容量算, 不越界 */
    CHECK(wifi_hist_start(3, 200) == wifi_hist_start(3, WIFI_DB_RSSI_HIST),
          "n 超容量按容量处理");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
