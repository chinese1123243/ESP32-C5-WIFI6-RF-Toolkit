/*
 * cap.h: 原始 802.11 帧落盘 / EAPOL+PMKID 过滤 / 分段拉取
 *
 * 存储: storage 分区 [1MB, 末尾) 直接落成一份线性 pcap 文件
 *   偏移 0      24B   pcap 全局头 (LINKTYPE_IEEE802_11_RADIOTAP = 127)
 *   偏移 24     N     逐条记录: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
 *                     + 16B radiotap + 帧. incl_len 含 radiotap, 帧体按 4 字节
 *                     对齐填充, 保证 flash 写入地址/长度都 4 字节对齐
 *
 * radiotap 只带抓包必需的射频元数据 (flags/rate/channel/signal/noise), 128 字节的
 * 完整 radiotap 会让每条记录多出 100 多字节, 在 500KB 的段里等于少存两成帧.
 * 用 127 而不是 105: 后者没有元数据, Wireshark 里看不到信道和 RSSI, 也没法按
 * 信道过滤, 抓多信道时只能靠猜.
 *
 * 吞吐设计 (关键):
 *   混杂回调运行在 WiFi 驱动任务里, 里面绝不能碰 flash (会阻塞驱动 → 整机假死).
 *   所以回调只做: 分类打标 + memcpy 进 PSRAM 暂存环;
 *   独立 flusher 任务再把暂存区编码成 pcap 记录落盘, 并惰性按 64KB 擦除.
 *
 * 过滤:
 *   回调里识别 EAPOL / EAPOL-Key / PMKID / Deauth 并打标,
 *   这些帧额外登记进关键帧索引 (记录其在 pcap 里的偏移+长度),
 *   App 可以只拉关键帧拼成迷你 pcap, 不必把整块 7MB 走 BLE 传一遍.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 关键帧标记位 */
#define CAP_K_EAPOL     0x01
#define CAP_K_PMKID     0x02
#define CAP_K_DEAUTH    0x04
#define CAP_K_EAPOLKEY  0x08

/* storage 分区前缀留给钓鱼门户的自定义 HTML */
#define CAP_HTML_RESERVE    (1024 * 1024)
/* pcap 全局头长度 */
#define CAP_PCAP_HDR        24
/* 单帧上限 (与 RFTOOL_MAX_FRAME_LEN 一致) */
#define CAP_MAX_FRAME       512
/* 关键帧索引容量 */
#define CAP_KEY_MAX         512

/* 定位分区 + 起 flusher 任务. 幂等. */
esp_err_t cap_init(void);

/* 开始一次抓包会话 (会先擦掉旧数据的头部标记, 实际扇区惰性擦除).
 * key_only=true 时只落关键帧. */
esp_err_t cap_start(bool key_only);
esp_err_t cap_stop(void);
void      cap_clear(void);              /* 清空 (下一帧从 0 开始覆盖) */

bool     cap_is_on(void);
bool     cap_key_only(void);
bool     cap_is_full(void);
uint32_t cap_frames(void);
uint32_t cap_drops(void);
uint32_t cap_key_count(void);
uint32_t cap_pcap_size(void);           /* = 24 + 已写记录字节数 */
uint32_t cap_capacity(void);

/* 分段轮转的当前段号 / 总段数 (每段 512KB) */
int      cap_segment_index(void);
int      cap_segment_count(void);

/* 混杂回调投喂: 只分类 + memcpy 入队, 非阻塞, 可在驱动任务里调用.
 * noise 与 rate 直接来自 rx_ctrl, 写进 radiotap 供 Wireshark 显示. */
void cap_feed(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t chan,
              int8_t noise, uint8_t rate);

/* 关键帧索引查询: 返回条数; 取第 i 条. 任意出参可传 NULL. */
int  cap_key_get(uint32_t i, uint8_t *kind_out, uint32_t *off_out,
                 uint32_t *len_out, uint32_t *ts_ms_out,
                 uint8_t *chan_out, int8_t *rssi_out);

/* 从 pcap 缓冲读取 (off 相对文件起点, 含 24 字节头). 返回实读字节数. */
int  cap_read(uint32_t off, uint8_t *dst, uint32_t len);

/* 24 字节 pcap 全局头 */
void cap_pcap_header(uint8_t *dst);
