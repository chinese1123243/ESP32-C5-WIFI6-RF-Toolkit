#pragma once

#include <stdint.h>

#include "ie_parse.h"
#include "wifi_db.h"

/* 三张表的派生层: 编号到字符串的映射, 以及从表项反推 ap_caps_t.
 * 不碰 printf, 不碰硬件, 主机可编. 布局(CSV/JSON 行)仍留在 wifi_db.c. */

/* MAC -> "aa:bb:cc:dd:ee:ff" (小写). 归到这里是为了让导出层不依赖 radio_common. */
void wifi_mac_str(const uint8_t mac[6], char out[18]);

const char *wifi_enc_str(uint8_t enc);
const char *wifi_cipher_str(uint8_t mask);

/* ap_entry_t -> ap_caps_t. 供导出与展示共用, 避免两处各推一套. */
void wifi_caps_from_entry(const ap_entry_t *e, ap_caps_t *c);

/* RSSI 环形缓冲的起始下标: 让 [start, start+n) 按时间先后排列.
 * 原先 CSV 与 JSON 各写了一遍同样的取模, 收在这里一处. */
int wifi_hist_start(uint8_t rssi_i, uint8_t rssi_n);
