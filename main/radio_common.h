/*
 * radio_common.h — rftool 公共辅助: MAC 格式化 / hex 解析打印 / pcap 头常量 / 状态码
 *
 * ESP32-C5-WIFI6-KIT, ESP-IDF v5.5.x
 *
 * 控制台输出约定 (复用 bench 项目的 CSV/META 风格, 供 host 脚本机器解析):
 *   META,WIFI,<key>,<value>[,<key>,<value>...]   状态行 (开始/停止/完成/错误)
 *   PKT,WIFI,<type>,<subtype>,<len>,<rssi>,<src_mac>,<dst_mac>,<bssid>,<ssid_or_->
 *   HEX,<2-hex-bytes-space-separated>            raw 帧 (供 host 重组 pcap, 不含 FCS)
 *   CYC,WIFI,<op>,<cycles>                        (可选) 时序
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===================== 配置常量 ===================== */
/* 板载 RGB LED: WS2812B-0807, DIN 接 GPIO27 (经 RGB_CTRL 电源门控, 运行时 LED 常供电).
 * GPIO27 是 strapping 脚, 但 strapping 仅复位时采样, 运行时作 GPIO 输出无碍
 * (pancake 项目 + Espressif DevKitC-1 均用 GPIO27 作 NeoPixel, 证据一致).
 * 若实测不亮, 改此宏重试 (候选: GPIO28 / GPIO8). */
#define RFTOOL_RGB_GPIO          27
#define RFTOOL_RGB_NUM          1     /* 板载仅 1 颗 WS2812 */

/* 802.11 帧最大长度 (含地址/帧体, 不含 FCS) */
#define RFTOOL_MAX_FRAME_LEN    512

/* pcap DLT: 802.11 (不含 FCS, 与嗅探回调里 sig_len-4 一致) */
#define RFTOOL_PCAP_LINKTYPE    105   /* DLT_IEEE802_11 */

/* ===================== MAC / hex 辅助 ===================== */

/* 把 6 字节 MAC 写成 "aa:bb:cc:dd:ee:ff" 到 dst (至少 18 字节). 返回 dst. */
char *mac_to_str(const uint8_t mac[6], char *dst);

/* 解析 "aa:bb:cc:dd:ee:ff" 或 "aabbccddeeff" 到 out[6]. 失败返回 false. */
bool parse_mac(const char *s, uint8_t out[6]);

/* 解析 16 进制字符串到 dst, 最多 max_bytes. 返回写入字节数, -1 表示非法字符. */
int parse_hex(const char *s, uint8_t *dst, int max_bytes);

/* 打印一行 "HEX,xx xx xx ..." (len 字节), 供 host 重组 pcap. */
void print_hex_line(const uint8_t *buf, int len);

/* ===================== 802.11 帧解析辅助 ===================== */

/* IEEE 802.11 Frame Control 字段位定义 (LSB first, 与空中字节序一致) */
#define FC_TYPE_MGMT      0x00
#define FC_TYPE_CTRL      0x01
#define FC_TYPE_DATA      0x02

/* 常用 subtype (<<4 | type<<2 的高字节布局见 mk_deauth_frame 注释) */
#define FC_DEAUTH         0x00C0   /* type=mgmt(0), subtype=12(Deauth) */
#define FC_DISASSOC       0x00A0   /* subtype=10 */
#define FC_BEACON         0x0080   /* subtype=8 */
#define FC_PROBE_REQ      0x0040   /* subtype=4 */
#define FC_PROBE_RESP     0x0050   /* subtype=5 */

/* 从 frame[0] 取 type (bits 2-3), subtype (bits 4-7) */
static inline uint8_t frame_type(const uint8_t *f)     { return (f[0] >> 2) & 0x03; }
static inline uint8_t frame_subtype(const uint8_t *f)  { return (f[0] >> 4) & 0x0f; }

/* type/subtype -> 可读字符串 ("MGMT"/"BEACON" 等), 未知返回 "?" */
const char *frame_type_str(uint8_t type);
const char *frame_subtype_str(uint8_t type, uint8_t subtype);

/* ===================== 帧构造器 ===================== */

/* 构造 IEEE 802.11 Deauth (FC=0x00C0) 24 字节帧 + 2 字节 reason = 26 字节.
 *   from_ap_to_sta: src=bssid, dst=sta  (欺骗站: "AP 踢你下线")
 *   from_ap_to_sta=false: src=sta, dst=bssid (欺骗 AP: "站主动断开")
 * reason: 1..原因码, 默认 7 (Class 3 frame, from non-associated STA).
 * 返回帧长度 (26). */
int mk_deauth_frame(uint8_t *out, const uint8_t bssid[6], const uint8_t sta[6],
                    bool from_ap_to_sta, uint16_t reason);

/* 构造最小 Beacon 帧 (FC=0x0080).
 *   da=ff:ff:ff:ff:ff:ff (广播), sa/bssid=src (随机或指定)
 *   tsf: 8 字节时间戳, 可 0
 *   interval: 信标间隔 (100 = 102.4ms)
 *   ch: DS parameter set IE (channel)
 *   ssid: UTF-8 SSID (最长 32 字节, 自动截断)
 * 返回帧长度. */
int mk_beacon_frame(uint8_t *out, int max_len, const uint8_t src[6],
                    uint32_t tsf_lo, uint16_t interval, uint8_t ch,
                    const char *ssid);

/* 构造最小 Probe Request (FC=0x0040).
 *   da=ff:ff:ff:ff:ff:ff, sa=src, bssid=00:00:00:00:00:00 (wildcard)
 *   ssid: 可为空 (broadcast probe) */
int mk_probe_req_frame(uint8_t *out, int max_len, const uint8_t src[6],
                       const char *ssid);

#ifdef __cplusplus
}
#endif
