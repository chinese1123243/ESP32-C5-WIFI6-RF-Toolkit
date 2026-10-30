#include <stdio.h>
#include <string.h>

#include "ie_parse.h"
#include "wifi_export.h"

static int g_fail;
static int g_pass;

#define CHECK_STR(got, want, what)                                          \
    do {                                                                    \
        if (strcmp((got), (want)) == 0) { g_pass++; }                        \
        else {                                                              \
            printf("  FAIL  %s\n    got : %s\n    want: %s\n", what, got, want); \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

int main(void)
{
    char line[WIFI_EXPORT_LINE_MAX];

    /* --- AP, 字段全部非默认值, 便于发现顺序错位 --- */
    ap_entry_t e;
    memset(&e, 0, sizeof(e));
    const uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(e.bssid, bssid, 6);
    strcpy(e.ssid, "TESTAP");
    e.channel = 6;
    e.rssi = -55;
    e.encryption = 3;                    /* WPA2 */
    e.hidden = false;
    e.pmf = 0;
    e.beacon_count = 10;
    e.data_count = 3;
    strcpy(e.vendor, "Acme");
    e.akm = CAP_AKM_PSK;
    e.cipher = CAP_CIPHER_CCMP;
    e.bw = 20;
    e.he = true;
    e.wps = true;
    e.pmf_cap = false;
    e.crackable = true;

    wifi_export_csv_ap(&e, line, sizeof(line));
    CHECK_STR(line,
              "AP,00:11:22:33:44:55,\"TESTAP\",6,-55,WPA2,N,0,10,3,Acme,PSK,CCMP,20,11ax,1,0,1",
              "CSV AP 完整行");

    wifi_export_json_ap(&e, line, sizeof(line));
    CHECK_STR(line,
              "{\"bssid\":\"00:11:22:33:44:55\",\"ssid\":\"TESTAP\",\"channel\":6,"
              "\"rssi\":-55,\"encryption\":\"WPA2\",\"hidden\":false,\"pmf\":0,"
              "\"beacons\":10,\"data\":3,\"vendor\":\"Acme\",\"akm\":\"PSK\","
              "\"cipher\":\"CCMP\",\"bw\":20,\"std\":\"11ax\",\"wps\":true,"
              "\"pmf_cap\":false,\"crackable\":true}",
              "JSON AP 完整对象");

    /* 隐藏 SSID + PMF 必需 + 不支持 WPS: 布尔与 0/1 都要跟随 */
    e.hidden = true;
    e.pmf = 1;
    e.pmf_cap = true;
    e.wps = false;
    e.crackable = false;
    e.he = false;
    e.ht = true;
    wifi_export_csv_ap(&e, line, sizeof(line));
    CHECK_STR(line,
              "AP,00:11:22:33:44:55,\"TESTAP\",6,-55,WPA2,Y,1,10,3,Acme,PSK,CCMP,20,11n,0,1,0",
              "CSV AP 隐藏/PMF/11n");
    wifi_export_json_ap(&e, line, sizeof(line));
    CHECK(strstr(line, "\"hidden\":true") != NULL, "JSON hidden 用 true");
    CHECK(strstr(line, "\"wps\":false") != NULL, "JSON wps 用 false");
    CHECK(strstr(line, "\"crackable\":false") != NULL, "JSON crackable 用 false");

    /* --- 客户端 --- */
    client_entry_t c;
    memset(&c, 0, sizeof(c));
    const uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    memcpy(c.mac, mac, 6);
    memcpy(c.bssid, bssid, 6);
    c.rssi = -60;
    c.pkt_count = 7;
    strcpy(c.vendor, "Acme");
    /* rssi_i=3 表示下一次写入 3, 已写 3 个: 下标 0,1,2 */
    c.rssi_i = 3;
    c.rssi_n = 3;
    c.rssi_hist[0] = -70;
    c.rssi_hist[1] = -68;
    c.rssi_hist[2] = -66;

    wifi_export_csv_client(&c, line, sizeof(line));
    CHECK_STR(line, "CLIENT,aa:bb:cc:dd:ee:ff,00:11:22:33:44:55,-60,7,Acme,\"-70|-68|-66\"",
              "CSV 客户端行 (| 分隔)");

    wifi_export_json_client(&c, line, sizeof(line));
    CHECK_STR(line,
              "{\"mac\":\"aa:bb:cc:dd:ee:ff\",\"bssid\":\"00:11:22:33:44:55\","
              "\"rssi\":-60,\"pkts\":7,\"vendor\":\"Acme\",\"rssi_hist\":[-70,-68,-66]}",
              "JSON 客户端对象 (, 分隔)");

    /* 环形回绕: rssi_i=0 且满 3 个, 起点应为 13 */
    c.rssi_i = 0;
    c.rssi_n = 3;
    c.rssi_hist[13] = -80;
    c.rssi_hist[14] = -78;
    c.rssi_hist[15] = -76;
    wifi_export_csv_client(&c, line, sizeof(line));
    CHECK_STR(line, "CLIENT,aa:bb:cc:dd:ee:ff,00:11:22:33:44:55,-60,7,Acme,\"-80|-78|-76\"",
              "CSV 客户端环形回绕顺序");

    /* 空 hist: CSV 写 -, JSON 写空数组 */
    c.rssi_n = 0;
    wifi_export_csv_client(&c, line, sizeof(line));
    CHECK_STR(line, "CLIENT,aa:bb:cc:dd:ee:ff,00:11:22:33:44:55,-60,7,Acme,\"-\"",
              "CSV 空趋势写 -");
    wifi_export_json_client(&c, line, sizeof(line));
    CHECK(strstr(line, "\"rssi_hist\":[]") != NULL, "JSON 空趋势写 []");

    /* --- EAPOL --- */
    eapol_entry_t p;
    memset(&p, 0, sizeof(p));
    memcpy(p.src, mac, 6);
    memcpy(p.dst, bssid, 6);
    p.eapol_type = 3;
    p.handshake_step = 2;
    wifi_export_csv_eapol(&p, line, sizeof(line));
    CHECK_STR(line, "EAPOL,aa:bb:cc:dd:ee:ff,00:11:22:33:44:55,3,2", "CSV EAPOL 行");
    wifi_export_json_eapol(&p, line, sizeof(line));
    CHECK_STR(line,
              "{\"src\":\"aa:bb:cc:dd:ee:ff\",\"dst\":\"00:11:22:33:44:55\","
              "\"type\":3,\"step\":2}",
              "JSON EAPOL 对象");

    /* --- 截断: 缓冲很小时只截断, 不越界, 且以 NUL 结尾 --- */
    char tiny[16];
    memset(tiny, 0x7F, sizeof(tiny));
    wifi_export_csv_ap(&e, tiny, sizeof(tiny));
    CHECK(tiny[sizeof(tiny) - 1] == 0, "小缓冲以 NUL 结尾");
    CHECK(strlen(tiny) < sizeof(tiny), "小缓冲不越界");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
