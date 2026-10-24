/*
 * karma.h: Probe Request SSID 收集 (KARMA 路线的第一步)
 *
 * 为什么不做 hostapd-mana 那种真 KARMA:
 *   ESP32 的 SoftAP 一个接口只能广播一个 SSID, 没法对任意 probe 逐一应答.
 *   所以这里做单射频下真正可行的路径:
 *     嗅探客户端在探测哪些网络 (往往就是它记住的家里/公司 SSID)
 *     → 把门户改名成那个 SSID
 *     → 客户端自动连过来 → 落进 Captive Portal
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define KARMA_MAX 32

/* 混杂回调投喂: 只处理 Probe Request, 其余立即返回 */
void karma_feed(const uint8_t *frame, int len, int8_t rssi);

void karma_clear(void);
int  karma_count(void);

/* 按命中次数降序取第 i 条. 返回 SSID 指针 (可能为空串), 无则 NULL */
const char *karma_get(int i, int *count_out, int8_t *rssi_out);

/* 命中次数最高的非空 SSID; 无则 NULL */
const char *karma_top(int *count_out);
