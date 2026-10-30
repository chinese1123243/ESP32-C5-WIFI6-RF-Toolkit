/* 发射与随机地址. 这两件事必须碰驱动, 与纯组帧分开:
 * 组帧留在 frame_build.c, 不依赖任何 ESP 头文件, 主机端可以直接编译测试. */
#include "frame_build.h"

#include <stdint.h>
#include "esp_wifi.h"
#include "esp_random.h"
#include "esp_log.h"

static const char *TAG = "FB";

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
