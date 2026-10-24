/*
 * hs.h: EAPOL 4 次握手跟踪 + hashcat 22000 导出
 *
 * 职责:
 *   在混杂回调里识别 EAPOL-Key M1..M4 与 PMKID, 按 (AP, STA) 归档成握手记录,
 *   凑齐「可用组合」后回报事件, 并能导出 hashcat -m 22000 格式的 hash 文件.
 *
 * 为什么按 AP+STA 归档而不是逐帧:
 *   单条 EAPOL 帧本身不足以离线验证口令, hashcat 需要一对消息
 *   (一条提供 ANonce, 另一条提供带 MIC 的 EAPOL). 所以必须配对.
 *
 * 配对有效性: 要求两条消息的 Replay Counter 相同 (同一次握手).
 *   不做这个校验会产出 nonce 不匹配的「废握手」, hashcat 永远破不出来, *   这是很多自制工具的通病, 这里显式检查.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 单条消息上限 (22000 里 EAPOL 字段限 255 字节, 这里留余量做原始留存) */
#define HS_EAPOL_MAX   255
/* 同时跟踪的握手数 */
#define HS_SLOTS       8

esp_err_t hs_init(void);

/* 混杂回调投喂: 只做分类 + 拷贝, 非阻塞. 可在 WiFi 驱动任务里调用. */
void hs_feed(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t chan);

void hs_clear(void);
int  hs_count(void);                /* 记录条数 */
int  hs_pmkid_count(void);          /* 其中带 PMKID 的条数 */
int  hs_complete_count(void);       /* 其中「可离线破解」的条数 */

/* 列出所有记录 (供 CLI / HTTP 用); 返回条数 */
int  hs_dump(bool only_complete);

/* 生成 hashcat 22000 内容. 每行回调一次; 返回写出行数. */
int  hs_export_22000(void (*sink)(const char *line, void *ctx), void *ctx);

/* 自检: 用构造的 M1/M2/PMKID 走完整链路, 校验分类/配对/22000 格式.
 * 会清空现有记录. 返回 0 表示全部通过. */
int  hs_selftest(void);
