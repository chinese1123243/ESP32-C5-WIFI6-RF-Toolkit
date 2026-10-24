/*
 * ie_parse.c: 802.11 信息元素解析 (RSN / WPS / HT / VHT / HE)
 *
 * 修的既有 bug: 原 wifi_db.c 的 parse_rsn() 把 AKM 套件当 2 字节读
 *   (ie[off] | ie[off+1]<<8) 再与 0x0008 比较. 但套件是 4 字节:
 *   OUI(00 0F AC) + type, 前两字节恒为 00 0F → 比较永远失败,
 *   于是 SAE (WPA3) 全部被误判成 WPA2, 而 WPA3 的握手是破不了的.
 *   同时 caps & 0x0080 是 MFPR (PMF 必需), 被笼统当成 "支持 PMF".
 */
#include "ie_parse.h"

#include <string.h>
#include <stdio.h>

#define IE_ID_RSN       48
#define IE_ID_HT_CAP    45
#define IE_ID_HT_OP     61
#define IE_ID_VHT_CAP   191
#define IE_ID_VHT_OP    192
#define IE_ID_EXT       255
#define IE_ID_VENDOR    221
#define IE_ID_TWT       216

#define EXT_HE_CAP      35
#define EXT_HE_OP       36
#define EXT_HE_6GHZ_OP  59
#define EXT_RNR         201

/* 0x00-0x0F-0xAC 是 RSN 的标准 OUI, 所有密套件/AKM 都带它 */
static inline bool oui_rsn(const uint8_t *p)
{
    return p[0] == 0x00 && p[1] == 0x0F && p[2] == 0xAC;
}

static void cipher_add(ap_caps_t *c, uint8_t type)
{
    if (type == 2)                          c->cipher |= CAP_CIPHER_TKIP;
    else if (type == 4)                     c->cipher |= CAP_CIPHER_CCMP;
    else if (type == 8 || type == 9)        c->cipher |= CAP_CIPHER_GCMP;
}

static void parse_rsn_ie(const uint8_t *ie, int n, ap_caps_t *c)
{
    if (n < 2) return;
    int off = 2;                                  /* version */

    if (off + 4 <= n) {                           /* 组播密码套件 */
        if (oui_rsn(ie + off)) cipher_add(c, ie[off + 3]);
        off += 4;
    }
    if (off + 2 <= n) {                           /* 单播密码套件列表 */
        int cnt = ie[off] | (ie[off + 1] << 8);
        off += 2;
        for (int i = 0; i < cnt && off + 4 <= n; i++, off += 4) {
            if (oui_rsn(ie + off)) cipher_add(c, ie[off + 3]);
        }
    }
    if (off + 2 <= n) {                           /* AKM 列表 */
        int cnt = ie[off] | (ie[off + 1] << 8);
        off += 2;
        for (int i = 0; i < cnt && off + 4 <= n; i++, off += 4) {
            if (!oui_rsn(ie + off)) continue;
            switch (ie[off + 3]) {
                case 1: case 3: case 5: c->akm |= CAP_AKM_8021X; break;
                case 2: case 6:         c->akm |= CAP_AKM_PSK;   break;
                case 4:                 c->akm |= CAP_AKM_FTPSK; break;
                case 8: case 9:         c->akm |= CAP_AKM_SAE;   break;
                case 18:                c->akm |= CAP_AKM_OWE;   break;
                default: break;
            }
        }
    }
    if (off + 2 <= n) {                           /* RSN Capabilities */
        uint16_t rc = (uint16_t)(ie[off] | (ie[off + 1] << 8));
        /* B6 = MFPC (支持 PMF), B7 = MFPR (强制 PMF).
         * 实测有 AP 只发 MFPR 不发 MFPC (抓到 0x008C: B2 PeerKey | B3 JMB | B7 MFPR),
         * 规范上 MFPR 隐含 MFPC, 所以这里做归一化, 免得 UI 上出现
         * 「必需=1 但支持=0」这种自相矛盾的展示. */
        if (rc & 0x0040) c->pmf |= CAP_PMF_CAPABLE;
        if (rc & 0x0080) c->pmf |= CAP_PMF_CAPABLE | CAP_PMF_REQUIRED;
    }
}

/* HT Operation: byte0 = 主信道, byte1 = HT Op Info
 * (bit0-1 次信道偏移, bit2 STA 信道宽度 0=20 1=任意) */
static void parse_ht_op(const uint8_t *ie, int n, ap_caps_t *c)
{
    if (n < 2) return;
    uint8_t info = ie[1];
    if ((info & 0x04) && (info & 0x03) && c->bw < 40) c->bw = 40;
}

/* VHT Operation: byte0 = 信道宽度 (0 跟 HT / 1 = 80 / 2 = 160 / 3 = 80+80) */
static void parse_vht_op(const uint8_t *ie, int n, ap_caps_t *c)
{
    if (n < 1) return;
    uint8_t w = ie[0];
    if (w == 1) { if (c->bw < 80)  c->bw = 80;  }
    else if (w == 2 || w == 3) { if (c->bw < 160) c->bw = 160; }
}

/* HE Operation: 3 字节 HE Operation Parameters.
 * B0-B5 = BSS Color, B9 = TWT Required. 后面还有 Basic HE-MCS/NSS (2B) 与
 * 可选的 VHT/6GHz Operation Info, 这里只取前两个字段. */
static void parse_he_op(const uint8_t *p, int n, ap_caps_t *c)
{
    if (n < 3) return;
    c->bss_color = (uint8_t)(p[0] & 0x3F);
    c->twt_req   = (p[1] & 0x02) != 0;
}

/* RNR (Reduced Neighbor Report): 邻居 AP 信息 = TBTT Info Header(2) +
 * Operating Class(1) + Channel(1) + TBTT Info Set. 只取第一个邻居的类型与
 * 信道: 走完整 TBTT Info Set 要按 header 里的长度字段跳, 各家实现长度不同,
 * 取多了会越界. 6GHz 的操作类是 131-137. */
static void parse_rnr(const uint8_t *p, int n, ap_caps_t *c)
{
    if (n < 4 || c->rnr_count) return;
    uint16_t hdr = (uint16_t)(p[0] | (p[1] << 8));
    uint8_t cnt = (uint8_t)(hdr >> 8);
    if (cnt == 0 && n > 4) cnt = 1;      /* 有的实现把 1 个邻居写成 0 */
    c->rnr_count = cnt;
    c->rnr_ch    = p[3];
    uint8_t opclass = p[2];
    c->rnr_6g = (opclass >= 131 && opclass <= 137);
}

void ie_parse_ies(const uint8_t *ies, int len, ap_caps_t *out)
{
    ap_caps_t c;
    memset(&c, 0, sizeof(c));
    bool have_wpa = false, have_rsn = false;

    int off = 0;
    while (off + 2 <= len) {
        uint8_t id = ies[off];
        int sl = ies[off + 1];
        if (off + 2 + sl > len) break;
        const uint8_t *p = ies + off + 2;

        switch (id) {
            case IE_ID_RSN:
                have_rsn = true;
                parse_rsn_ie(p, sl, &c);
                break;

            case IE_ID_VENDOR:
                /* 微软 OUI 00-50-F2: type 1 = WPA, type 4 = WPS */
                if (sl >= 4 && p[0] == 0x00 && p[1] == 0x50 && p[2] == 0xF2) {
                    if (p[3] == 0x01)      have_wpa = true;
                    else if (p[3] == 0x04) c.wps = true;
                }
                break;

            case IE_ID_HT_CAP:  c.ht = true;                break;
            case IE_ID_HT_OP:   parse_ht_op(p, sl, &c);     break;
            case IE_ID_VHT_CAP: c.vht = true;               break;
            case IE_ID_VHT_OP:  parse_vht_op(p, sl, &c);    break;

            case IE_ID_EXT:
                if (sl >= 1 && p[0] == EXT_HE_CAP) {
                    c.he = true;
                } else if (sl >= 1 && p[0] == EXT_HE_OP) {
                    c.he = true;
                    parse_he_op(p + 1, sl - 1, &c);
                } else if (sl >= 1 && p[0] == EXT_RNR) {
                    parse_rnr(p + 1, sl - 1, &c);
                }
                /* HE 6GHz Operation 不做带宽推断 (靠 VHT/HT 已足够) */
                break;

            case IE_ID_TWT:
                if (sl >= 1) c.twt = true;
                break;

            default: break;
        }
        off += 2 + sl;
    }

    if (have_rsn)      c.enc = (c.akm & (CAP_AKM_SAE | CAP_AKM_OWE)) ? CAP_ENC_WPA3 : CAP_ENC_WPA2;
    else if (have_wpa) c.enc = CAP_ENC_WPA;
    else               c.enc = CAP_ENC_OPEN;

    /* 只有 PSK / FT-PSK 系的四次握手才可离线爆破; SAE/OWE/802.1X 不行 */
    c.crackable = (c.akm & (CAP_AKM_PSK | CAP_AKM_FTPSK)) != 0;
    if (c.bw == 0) c.bw = 20;

    *out = c;
}

void ie_parse_ap(const uint8_t *frame, int len, ap_caps_t *out)
{
    memset(out, 0, sizeof(*out));
    out->bw = 20;
    /* 管理帧头 24B + beacon/probe-resp 固定字段 12B (时间戳8 + 间隔2 + 能力2) */
    if (len < 24 + 12) return;
    ie_parse_ies(frame + 24 + 12, len - 24 - 12, out);
}

const char *caps_std_str(const ap_caps_t *c)
{
    if (c->he)  return "11ax";
    if (c->vht) return "11ac";
    if (c->ht)  return "11n";
    return "11a/g";
}

void caps_akm_str(const ap_caps_t *c, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    static const struct { uint8_t bit; const char *nm; } m[] = {
        { CAP_AKM_PSK,   "PSK"    },
        { CAP_AKM_SAE,   "SAE"    },
        { CAP_AKM_8021X, "802.1X" },
        { CAP_AKM_OWE,   "OWE"    },
        { CAP_AKM_FTPSK, "FT-PSK" },
    };
    for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        if (!(c->akm & m[i].bit)) continue;
        size_t used = strlen(out);
        if (used + 1 >= out_sz) break;
        if (used) strncat(out, "/", out_sz - used - 1);
        used = strlen(out);
        strncat(out, m[i].nm, out_sz - used - 1);
    }
    if (!out[0]) snprintf(out, out_sz, "-");
}
