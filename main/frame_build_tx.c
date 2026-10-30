/* 发射与随机地址. 这两个动作走 radio_hal, 不直调 esp_wifi / esp_random:
 * 主机端装一份 mock 就能验证"发了什么帧", 不必插板.
 * 错误原因改用返回码传递, 不再打日志: 调用方本来就按 esp_err_t 分支. */
#include "frame_build.h"
#include "radio_hal.h"

#include <stdint.h>

void fb_random_local_mac(uint8_t out[6])
{
    radio_hal()->random_bytes(out, 6);
    out[0] = (uint8_t)((out[0] & 0xFE) | 0x02);   /* 单播 + 本地管理 */
}

esp_err_t fb_tx(const uint8_t *frame, int len)
{
    if (!frame || len < 10) return ESP_ERR_INVALID_ARG;
    if (((frame[0] >> 2) & 0x3) != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return radio_hal()->tx_mgmt(frame, len, true);
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
        if (v < 0) { return ESP_ERR_INVALID_ARG; }
        if (hi < 0) { hi = v; continue; }
        if (n >= (int)sizeof(buf)) { return ESP_ERR_INVALID_SIZE; }
        buf[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) { return ESP_ERR_INVALID_ARG; }
    if (n < 10) { return ESP_ERR_INVALID_SIZE; }

    esp_err_t e = fb_tx(buf, n);
    if (out_len) *out_len = n;
    return e;
}
