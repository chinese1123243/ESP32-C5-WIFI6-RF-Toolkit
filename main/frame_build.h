/*
 * frame_build.h: 802.11 管理帧构造 + 原始注入
 *
 * 为什么需要它:
 *   原有的 deauth/beacon 构造都写死在 wifi_attack.c 里 (static mk_*_frame),
 *   只能服务于固定几种洪泛. Evil Twin 克隆、KARMA 应答、以及「原始帧构造器」
 *   需要一个能按参数拼帧、并能直接发任意字节的通用层.
 *
 * 能力边界 (ESP32 驱动限制):
 *   只能注入管理帧 (type 0). 数据帧会被驱动直接拒收, 所以 PMKID 无客户端
 *   那种需要完整关联状态机 + 数据帧的路子在本硬件上做不扎实.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 发出一个已组好的帧. 走 STA 接口原始注入. */
esp_err_t fb_tx(const uint8_t *frame, int len);

/* 原始帧构造器: 解析 hex 文本并原样发出.
 * 支持 "0102 03" / "01:02:03" / "010203" 三种写法. 返回 ESP_OK 表示已交给驱动. */
esp_err_t fb_tx_hex(const char *hex, int *out_len);

/* 构造器: 返回帧长, 0 表示失败 */
int fb_deauth(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6], uint16_t reason);
int fb_auth(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
            uint16_t seq, uint16_t algo);
int fb_assoc_req(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
                 const uint8_t *ssid, int ssid_len, uint8_t ch);
/* 同上, 但带 RSN IE (PMKID Count=1), 用于无客户端 PMKID 索要 */
int fb_assoc_req_rsn(uint8_t *out, int cap, const uint8_t bssid[6], const uint8_t sta[6],
                     const uint8_t *ssid, int ssid_len, uint8_t ch);
int fb_beacon(uint8_t *out, int cap, const uint8_t bssid[6],
              const uint8_t *ssid, int ssid_len, uint8_t ch);
int fb_probe_resp(uint8_t *out, int cap, const uint8_t dst[6], const uint8_t bssid[6],
                  const uint8_t *ssid, int ssid_len, uint8_t ch);

/* 生成一个本地管理地址 (第一个字节的 bit1 置位) */
void fb_random_local_mac(uint8_t out[6]);
