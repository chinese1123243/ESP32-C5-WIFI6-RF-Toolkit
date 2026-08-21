/*
 * radio_common.c — 公共辅助实现
 */
#include "radio_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

char *mac_to_str(const uint8_t mac[6], char *dst)
{
    snprintf(dst, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return dst;
}

bool parse_mac(const char *s, uint8_t out[6])
{
    if (!s) return false;
    int n = 0;
    /* 兼容 "aabbccddeeff" 与 "aa:bb:cc:dd:ee:ff" */
    unsigned int v[6];
    /* 用 %1[0-9a-fA-F] 逐个 nibble 过于繁琐, 直接 sscanf 试两种 */
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
        for (n = 0; n < 6; n++) out[n] = (uint8_t)v[n];
        return true;
    }
    if (sscanf(s, "%2x%2x%2x%2x%2x%2x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
        for (n = 0; n < 6; n++) out[n] = (uint8_t)v[n];
        return true;
    }
    return false;
}

int parse_hex(const char *s, uint8_t *dst, int max_bytes)
{
    int cnt = 0;
    while (cnt < max_bytes && *s) {
        /* 跳过空白/逗号/0x */
        while (*s && (isspace((unsigned char)*s) || *s == ',' || *s == 'x' || *s == 'X')) s++;
        if (!*s) break;
        char hi = *s++;
        char lo = *s;
        if (!lo) return -1;       /* 奇数 nibble */
        s++;
        int hv, lv;
        if (hi >= '0' && hi <= '9') hv = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hv = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hv = hi - 'A' + 10;
        else return -1;
        if (lo >= '0' && lo <= '9') lv = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lv = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lv = lo - 'A' + 10;
        else return -1;
        dst[cnt++] = (uint8_t)((hv << 4) | lv);
    }
    return cnt;
}

void print_hex_line(const uint8_t *buf, int len)
{
    if (len <= 0 || len > RFTOOL_MAX_FRAME_LEN) {
        printf("HEX,\n");
        fflush(stdout);
        return;
    }
    /* 估算缓冲: 每字节 3 字符 ("xx ") + "HEX," + 换行 + nul */
    int cap = len * 3 + 8;
    char *line = (char *)malloc(cap);
    if (!line) {
        /* 内存不足时分段打印 */
        printf("HEX,");
        for (int i = 0; i < len; i++) printf("%02x ", buf[i]);
        printf("\n");
        fflush(stdout);
        return;
    }
    int p = 0;
    line[p++] = 'H'; line[p++] = 'E'; line[p++] = 'X'; line[p++] = ',';
    for (int i = 0; i < len; i++) {
        line[p++] = "0123456789abcdef"[buf[i] >> 4];
        line[p++] = "0123456789abcdef"[buf[i] & 0xf];
        line[p++] = ' ';
    }
    /* 去掉末尾空格 */
    if (p > 4) p--;
    line[p++] = '\n';
    line[p] = '\0';
    fputs(line, stdout);
    fflush(stdout);
    free(line);
}

const char *frame_type_str(uint8_t type)
{
    switch (type) {
    case FC_TYPE_MGMT: return "MGMT";
    case FC_TYPE_CTRL: return "CTRL";
    case FC_TYPE_DATA: return "DATA";
    default: return "?";
    }
}

const char *frame_subtype_str(uint8_t type, uint8_t subtype)
{
    if (type == FC_TYPE_MGMT) {
        switch (subtype) {
        case 0x0: return "ASSOC_REQ";
        case 0x1: return "ASSOC_RESP";
        case 0x4: return "PROBE_REQ";
        case 0x5: return "PROBE_RESP";
        case 0x8: return "BEACON";
        case 0xa: return "DISASSOC";
        case 0xb: return "AUTH";
        case 0xc: return "DEAUTH";
        default: return "MGMT_OTHER";
        }
    }
    if (type == FC_TYPE_CTRL) return "CTRL_OTHER";
    if (type == FC_TYPE_DATA) {
        if (subtype == 0x0 || subtype == 0x4 || subtype == 0x8) return "DATA";
        if (subtype == 0x1 || subtype == 0x5) return "DATA_QOS";
        return "DATA_OTHER";
    }
    return "?";
}

/* ===================== 帧构造器 =====================
 * 802.11 帧字节序 (空中传输序, MSB 先发但字节内 bit0 先):
 *   frame[0] = FC byte 0 (protocol 2b | type 2b | subtype 4b, LSB first)
 *   frame[1] = FC byte 1 (flags: ToDS, FromDS, ...)
 *   frame[2..3] = duration (LE)
 *   地址区: addr1 (DA), addr2 (SA), addr3 (BSSID) 各 6 字节
 *   frame[22..23] = seq control (LE)
 *   frame[24..] = frame body
 *
 * 注: 常量宏 FC_DEAUTH=0x00C0 是按"CPU 视角的 16 位值",
 *     空中字节序 = 高字节在后, 故 frame[0]=0xC0, frame[1]=0x00.
 */
int mk_deauth_frame(uint8_t *out, const uint8_t bssid[6], const uint8_t sta[6],
                    bool from_ap_to_sta, uint16_t reason)
{
    /* FC=Deauth: byte0=0xC0 (subtype=12<<4 | type=0 | proto=0), byte1=0x00 */
    out[0] = 0xC0;  /* see note: subtype 12 = 0b1100 -> bits 7-4 */
    out[1] = 0x00;
    out[2] = 0x00; out[3] = 0x00;            /* duration = 0 */

    if (from_ap_to_sta) {
        /* AP -> STA: addr1(DA)=sta, addr2(SA)=bssid, addr3(BSSID)=bssid */
        memcpy(out + 4,  sta,  6);
        memcpy(out + 10, bssid, 6);
        memcpy(out + 16, bssid, 6);
    } else {
        /* STA -> AP: addr1(DA)=bssid, addr2(SA)=sta, addr3(BSSID)=bssid */
        memcpy(out + 4,  bssid, 6);
        memcpy(out + 10, sta,   6);
        memcpy(out + 16, bssid, 6);
    }
    out[22] = 0x00; out[23] = 0x00;          /* seq ctrl = 0 */
    out[24] = (uint8_t)(reason & 0xff);
    out[25] = (uint8_t)(reason >> 8);
    return 26;
}

/* Beacon 帧体 (固定字段 + IE):
 *   [8B tsf][2B interval][2B cap][IE: SSID][IE: DS param][IE: rates]
 */
int mk_beacon_frame(uint8_t *out, int max_len, const uint8_t src[6],
                    uint32_t tsf_lo, uint16_t interval, uint8_t ch,
                    const char *ssid)
{
    int p = 0;
    out[p++] = 0x80;   /* FC byte0: subtype=8(0b1000)<<4 | type=0 -> 0x80 */
    out[p++] = 0x00;   /* FC byte1 */
    out[p++] = 0x00; out[p++] = 0x00;       /* duration */
    /* addr1 = broadcast */
    memset(out + p, 0xff, 6); p += 6;
    /* addr2 = src (SA) */
    memcpy(out + p, src, 6); p += 6;
    /* addr3 = BSSID (这里同 src) */
    memcpy(out + p, src, 6); p += 6;
    out[p++] = 0x00; out[p++] = 0x00;       /* seq ctrl */

    /* 固定字段 */
    /* tsf 8B (LE): 取低 32 位 + 0 */
    out[p++] = (uint8_t)(tsf_lo & 0xff);
    out[p++] = (uint8_t)((tsf_lo >> 8) & 0xff);
    out[p++] = (uint8_t)((tsf_lo >> 16) & 0xff);
    out[p++] = (uint8_t)((tsf_lo >> 24) & 0xff);
    out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0;  /* tsf 高 32 位 */
    /* beacon interval (LE) */
    out[p++] = (uint8_t)(interval & 0xff);
    out[p++] = (uint8_t)(interval >> 8);
    /* capability: ESS (0x0001) | Short-Preamble (0x0020) -> 0x2101 */
    out[p++] = 0x01; out[p++] = 0x21;

    /* IE: SSID (id=0) */
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    if (max_len - p < 2 + ssid_len) return -1;
    out[p++] = 0x00;            /* SSID IE id */
    out[p++] = (uint8_t)ssid_len;
    if (ssid_len) {
        memcpy(out + p, ssid, ssid_len);
        p += ssid_len;
    }

    /* IE: DS Parameter Set (id=3, len=1, channel) */
    if (max_len - p < 3) return -1;
    out[p++] = 0x03; out[p++] = 0x01; out[p++] = ch;

    /* IE: Supported Rates (id=1): 4 个基础速率, bit7=1 表示"基础" */
    if (max_len - p < 6) return -1;
    out[p++] = 0x01; out[p++] = 0x04;
    out[p++] = 0x82;  /* 1 Mbps  basic */
    out[p++] = 0x84;  /* 2 Mbps  basic */
    out[p++] = 0x8b;  /* 5.5 Mbps basic */
    out[p++] = 0x96;  /* 11 Mbps basic */

    return p;
}

int mk_probe_req_frame(uint8_t *out, int max_len, const uint8_t src[6],
                       const char *ssid)
{
    int p = 0;
    out[p++] = 0x40;   /* FC: subtype=4(ProbeReq)<<4 | type=0 -> 0x40 */
    out[p++] = 0x00;
    out[p++] = 0x00; out[p++] = 0x00;       /* duration */
    memset(out + p, 0xff, 6); p += 6;       /* addr1 = broadcast */
    memcpy(out + p, src, 6); p += 6;        /* addr2 = SA */
    memset(out + p, 0x00, 6); p += 6;       /* addr3 = wildcard (00) */
    out[p++] = 0x00; out[p++] = 0x00;       /* seq */

    /* IE: SSID */
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    if (max_len - p < 2 + ssid_len) return -1;
    out[p++] = 0x00;
    out[p++] = (uint8_t)ssid_len;
    if (ssid_len) {
        memcpy(out + p, ssid, ssid_len);
        p += ssid_len;
    }

    /* IE: Supported Rates */
    if (max_len - p < 6) return -1;
    out[p++] = 0x01; out[p++] = 0x04;
    out[p++] = 0x82; out[p++] = 0x84; out[p++] = 0x8b; out[p++] = 0x96;

    return p;
}
