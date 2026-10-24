/*
 * ie_parse.h: 802.11 信息元素解析 (RSN / WPS / HT / VHT / HE)
 *
 * 目的: 把「这个 AP 到底能不能打、怎么打」一次讲清楚, *   · 安全套件 (AKM) 决定握手能不能离线破: WPA2-PSK 能, WPA3-SAE 不能
 *   · PMF 必需 (MFPR) 决定 Deauth 是否有效: 强制 PMF 的客户端会忽略伪造 Deauth
 *   · WPS 开启 = 另一条攻击路径
 *   · HT/VHT/HE + 带宽 = 这个 AP 是 11n 还是 11ax, 是不是 80/160MHz 宽频
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* AKM 套件 (RSN IE 里的 00-0F-AC:<type>) */
#define CAP_AKM_8021X   0x01    /* type 1/3/5  */
#define CAP_AKM_PSK     0x02    /* type 2/6    */
#define CAP_AKM_FTPSK   0x04    /* type 4      */
#define CAP_AKM_SAE     0x08    /* type 8/9    */
#define CAP_AKM_OWE     0x10    /* type 18     */

/* 密码套件 */
#define CAP_CIPHER_TKIP 0x01
#define CAP_CIPHER_CCMP 0x02
#define CAP_CIPHER_GCMP 0x04

/* RSN Capabilities */
#define CAP_PMF_CAPABLE  0x01   /* MFPC: 支持 PMF */
#define CAP_PMF_REQUIRED 0x02   /* MFPR: 强制 PMF */

/* 加密类型 (与既有 enc_str() 的编号保持一致) */
#define CAP_ENC_OPEN 0
#define CAP_ENC_WPA  2
#define CAP_ENC_WPA2 3
#define CAP_ENC_WPA3 4

typedef struct {
    uint8_t enc;        /* CAP_ENC_* */
    uint8_t akm;        /* CAP_AKM_* 位图 */
    uint8_t cipher;     /* CAP_CIPHER_* 位图 */
    uint8_t pmf;        /* CAP_PMF_* 位图 */
    uint8_t bw;         /* 20 / 40 / 80 / 160 (MHz) */
    bool    wps;
    bool    ht;         /* 11n */
    bool    vht;        /* 11ac */
    bool    he;         /* 11ax */
    /* Wi-Fi 6 结构. 这些字段只在 HE Operation / TWT / RNR 元素里出现,
     * 老 AP 全是 0, 用 0 表示"没宣告"而不是"值是 0". */
    uint8_t bss_color;  /* HE Operation 的 6 位 BSS Color, 0 = 未宣告 */
    bool    twt_req;    /* HE Operation 的 TWT Required 位 */
    bool    twt;        /* beacon 里带 TWT 元素 */
    uint8_t rnr_count;  /* RNR 里的邻居数 */
    uint8_t rnr_ch;     /* 第一个邻居的信道 */
    bool    rnr_6g;     /* 第一个邻居属于 6GHz 操作类 (131-137) */
    /* 该 AP 是否值得打: PMC 表示可离线破握手 */
    bool    crackable;
} ap_caps_t;

/* 从整帧 (beacon / probe response) 解析. 自动跳过 24B 管理帧头 + 12B 固定字段.
 * 非 beacon 类帧请传已定位到 IE 区的指针 + 长度, 用 ie_parse_ies(). */
void ie_parse_ap(const uint8_t *frame, int len, ap_caps_t *out);
void ie_parse_ies(const uint8_t *ies, int len, ap_caps_t *out);

/* "11ax" / "11ac" / "11n" / "11a" */
const char *caps_std_str(const ap_caps_t *c);
/* AKM 位图 -> "PSK/SAE" 之类的短串 */
void caps_akm_str(const ap_caps_t *c, char *out, size_t out_sz);
