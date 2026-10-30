/*
 * hs.c: EAPOL 4 次握手跟踪 + hashcat 22000 导出
 *
 * 归档键: (AP BSSID, STA MAC). 每个槽位保存 M1..M4 各自的 EAPOL 原文、
 * Replay Counter、Key Descriptor Version, 以及 M1 里可能带出的 PMKID.
 *
 * 配对判定 (决定导出的是不是「能破的」哈希):
 *   真正的依据是 Replay Counter 相等, 同一次握手里 M1/M2 (或 M2/M3)
 *   的 RC 必然一致. 不做这一步校验, 会导出 nonce 不匹配的废哈希,
 *   hashcat 跑到天亮也破不出来.
 *
 * 22000 字段 (已核对 hcxtools 文档):
 *   WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***
 *   WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR
 *   MESSAGEPAIR: 0 = M1+M2 (EAPOL 取 M2) / 2 = M2+M3 (EAPOL 取 M2)
 *   EAPOL 字段上限 255 字节 (hashcat 侧限制).
 */
#include "hs.h"
#include "eapol_core.h"
#include "radio_common.h"
#include "wifi_db.h"
#include "out_stream.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

static const char *TAG = "HS";

/* 位序: M1 M2 M3 M4 PMKID */
#define P_M1    0x01
#define P_M2    0x02
#define P_M3    0x04
#define P_M4    0x08
#define P_PMKID 0x10

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  present;       /* 已见到哪些消息 */
    uint8_t  pair_kind;     /* 0=无 1=M1+M2 2=M2+M3 */
    uint8_t  keyver;
    uint8_t  chan;
    int8_t   rssi;
    uint32_t ts_ms;
    uint8_t  pmkid[16];
    /* 各消息的最新一份 (重传/多轮会被覆盖) */
    uint8_t  eo[4][HS_EAPOL_MAX];
    uint16_t eo_len[4];
    uint8_t  rc[4][8];      /* Replay Counter */
    /* 配对成功当刻的固化快照.
     * 必须固化: live 缓冲会被后续重传覆盖, 而 Deauth 一次会触发多轮重连,
     * 事后再配对就会拿 M2(第1轮) 配 M3(第2轮), RC 不等, 全是废配对. */
    uint8_t  peo[2][HS_EAPOL_MAX];   /* [0] 携带 ANonce, [1] 携带 MIC+EAPOL */
    uint16_t plen[2];
} hs_t;

static hs_t   *s_tab = NULL;
static int     s_used = 0;          /* 已占用的槽位数 (顺序填充) */
static volatile uint32_t s_seen[5]; /* 索引 1..4: 各消息累计见到次数 (诊断用) */


static void hex_into(char *dst, const uint8_t *src, int n)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        dst[i * 2]     = h[src[i] >> 4];
        dst[i * 2 + 1] = h[src[i] & 0xF];
    }
    dst[n * 2] = '\0';
}

/* 802.11 里 EAPOL 帧的 Key Information (大端 16 位) 决定它是第几条消息.
 *
 * 位定义 (802.11-2020 12.7.2):
 *   0x0007 key descriptor version, 0x0008 key type (pairwise=1),
 *   0x0040 install, 0x0080 ack, 0x0100 mic, 0x0200 secure
 * 之前把 MIC 写成 0x0008, 那是 key type, 所有 EAPOL-Key 帧都是 1. 结果真实
 * AP 的 M1 (0x008a) 被判成 M3, PMKID 提取那段从来没执行过. 自检没抓出来,
 * 因为自检构造的 M1 用了 0x0082 (没置 key type), 正好绕开了这个位. */
/* eapol_msg_no / extract_pmkid 已移到 eapol_core.c, 以便主机端单测 */

/* 按 Replay Counter 判有效配对: 同一次握手里 M1/M2/M3/M4 的 RC 必然相同 */
static int try_pair(const hs_t *h)
{
    if ((h->present & P_M1) && (h->present & P_M2) &&
        memcmp(h->rc[0], h->rc[1], 8) == 0) return 1;
    if ((h->present & P_M2) && (h->present & P_M3) &&
        memcmp(h->rc[1], h->rc[2], 8) == 0) return 2;
    return 0;
}

static const char *pair_name(const hs_t *h)
{
    if (h->pair_kind == 1) return "m1m2";
    if (h->pair_kind == 2) return "m2m3";
    if (h->present & P_PMKID) return "pmkid";
    return "none";
}

static bool is_complete(const hs_t *h)
{
    return h->pair_kind != 0 || (h->present & P_PMKID);
}

static void essid_of(const hs_t *h, char *out, size_t out_sz, int *len_out)
{
    out[0] = '\0';
    if (len_out) *len_out = 0;
    int n = 0;
    const ap_entry_t *aps = wifi_db_get_aps(&n);
    for (int i = 0; i < n; i++) {
        if (memcmp(aps[i].bssid, h->bssid, 6) == 0) {
            snprintf(out, out_sz, "%s", aps[i].ssid);
            if (len_out) *len_out = (int)strlen(aps[i].ssid);
            return;
        }
    }
}

static void notify(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void notify(const char *fmt, ...)
{
    char buf[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    out_raw(buf);
}

/* 投喂 (WiFi 驱动任务上下文) */

void hs_feed(const uint8_t *f, uint16_t len, int8_t rssi, uint8_t chan)
{
    if (!s_tab || len < 24) return;
    if (((f[0] >> 2) & 0x3) != FC_TYPE_DATA) return;

    uint8_t fsub = (f[0] >> 4) & 0xF;
    int off = 24;
    if (fsub & 0x08) off += 2;
    if (f[1] & 0x80) off += 4;
    if (off + 8 > len) return;
    if (!(f[off] == 0xAA && f[off + 1] == 0xAA && f[off + 2] == 0x03)) return;
    if (!(f[off + 6] == 0x88 && f[off + 7] == 0x8E)) return;     /* 非 EAPOL */

    int eo = off + 8;
    if (eo + 99 > len) return;
    if (f[eo + 1] != 3) return;                                  /* 只要 EAPOL-Key */

    uint16_t ki = (uint16_t)((f[eo + 5] << 8) | f[eo + 6]);
    int msg = eapol_msg_no(ki);
    if (msg < 1 || msg > 4) return;

    int eo_len = len - eo;
    if (eo_len > HS_EAPOL_MAX) eo_len = HS_EAPOL_MAX;

    /* 方向: M1/M3 是 AP→STA, M2/M4 是 STA→AP */
    const uint8_t *bssid, *sta;
    if (msg == 1 || msg == 3) { bssid = f + 10; sta = f + 4; }
    else                      { bssid = f + 4;  sta = f + 10; }

    /* 查槽位 */
    hs_t *h = NULL;
    for (int i = 0; i < s_used; i++) {
        if (memcmp(s_tab[i].bssid, bssid, 6) == 0 &&
            memcmp(s_tab[i].sta, sta, 6) == 0) { h = &s_tab[i]; break; }
    }
    if (!h) {
        if (s_used >= HS_SLOTS) return;              /* 槽满: 丢弃新目标 */
        h = &s_tab[s_used++];
        memset(h, 0, sizeof(*h));
        memcpy(h->bssid, bssid, 6);
        memcpy(h->sta, sta, 6);
        h->chan = chan;
    }

    int idx = msg - 1;
    memcpy(h->rc[idx], f + eo + 9, 8);               /* Replay Counter */
    h->keyver = (uint8_t)(ki & 0x7);
    memcpy(h->eo[idx], f + eo, eo_len);
    h->eo_len[idx] = (uint16_t)eo_len;
    h->present |= (uint8_t)(1 << idx);
    h->rssi = rssi;
    h->chan = chan;
    h->ts_ms = (uint32_t)(esp_timer_get_time() / 1000);

    s_seen[msg]++;

    if (msg == 1) {
        uint8_t pm[16];
        if (eapol_extract_pmkid(h->eo[0], h->eo_len[0], pm)) {
            memcpy(h->pmkid, pm, 16);
            h->present |= P_PMKID;
        }
    }

    /* 配对: 必须在到达当刻判定并固化, live 缓冲马上会被下一轮重传/重连覆盖 */
    if (h->pair_kind == 0) {
        int pk = try_pair(h);
        if (pk == 1) {
            memcpy(h->peo[0], h->eo[0], h->eo_len[0]); h->plen[0] = h->eo_len[0];
            memcpy(h->peo[1], h->eo[1], h->eo_len[1]); h->plen[1] = h->eo_len[1];
            h->pair_kind = 1;
        } else if (pk == 2) {
            /* M3 提供 ANonce, M2 提供 MIC + EAPOL 原文 */
            memcpy(h->peo[0], h->eo[2], h->eo_len[2]); h->plen[0] = h->eo_len[2];
            memcpy(h->peo[1], h->eo[1], h->eo_len[1]); h->plen[1] = h->eo_len[1];
            h->pair_kind = 2;
        }
        if (h->pair_kind) {
            char b[13], s2[13];
            hex_into(b, h->bssid, 6);
            hex_into(s2, h->sta, 6);
            notify("META,HS,COMPLETE,bssid,%s,sta,%s,pair,%s,keyver,%u,chan,%u,rssi,%d",
                   b, s2, pair_name(h), (unsigned)h->keyver, (unsigned)chan, (int)rssi);
        }
    }
}


void hs_clear(void)
{
    s_used = 0;
    memset((void *)s_seen, 0, sizeof(s_seen));
}
int hs_count(void) { return s_used; }

/* 带 PMKID 的记录数 (无客户端 PMKID 攻击的结果查询) */
int hs_pmkid_count(void)
{
    int n = 0;
    for (int i = 0; i < s_used; i++) if (s_tab[i].present & P_PMKID) n++;
    return n;
}

int hs_complete_count(void)
{
    int n = 0;
    for (int i = 0; i < s_used; i++) if (is_complete(&s_tab[i])) n++;
    return n;
}

int hs_dump(bool only_complete)
{
    /* 各消息累计见到次数: 若 M1 恒为 0, 说明该 AP 的 M1 压根抓不到
     * (5GHz / 11ax 上常见), 那就只能靠 M2+M3 配对 */
    printf("META,HS,STATS,seen_m1,%u,seen_m2,%u,seen_m3,%u,seen_m4,%u\n",
           (unsigned)s_seen[1], (unsigned)s_seen[2],
           (unsigned)s_seen[3], (unsigned)s_seen[4]);
    int n = 0;
    for (int i = 0; i < s_used; i++) {
        const hs_t *h = &s_tab[i];
        if (only_complete && !is_complete(h)) continue;
        char b[13], s[13], essid[33];
        hex_into(b, h->bssid, 6);
        hex_into(s, h->sta, 6);
        essid_of(h, essid, sizeof(essid), NULL);
        printf("META,HS,ENTRY,i,%d,bssid,%s,sta,%s,essid,%s,msgs,%u,pair,%s,"
               "chan,%u,rssi,%d,keyver,%u,ts,%u\n",
               i, b, s, essid[0] ? essid : "-", (unsigned)h->present,
               pair_name(h), (unsigned)h->chan, (int)h->rssi,
               (unsigned)h->keyver, (unsigned)h->ts_ms);
        n++;
    }
    fflush(stdout);
    return n;
}

int hs_export_22000(void (*sink)(const char *line, void *ctx), void *ctx)
{
    int written = 0;
    for (int i = 0; i < s_used; i++) {
        const hs_t *h = &s_tab[i];
        char ap[13], sta[13], essid[33], essid_hex[67];
        hex_into(ap, h->bssid, 6);
        hex_into(sta, h->sta, 6);
        int elen = 0;
        essid_of(h, essid, sizeof(essid), &elen);
        if (elen > 0) hex_into(essid_hex, (const uint8_t *)essid, elen);
        else          essid_hex[0] = '\0';
        /* 1024 足够: EAPOL 510 hex + ESSID 64 + ANonce 64 + MIC 32 + MAC 24 + 固定字段 */
        char line[1024];

        /* 类型 01: PMKID (无需客户端) */
        if (h->present & P_PMKID) {
            char pm[33];
            hex_into(pm, h->pmkid, 16);
            int k = snprintf(line, sizeof(line), "WPA*01*%s*%s*%s*%s***",
                             pm, ap, sta, essid_hex);
            if (k > 0 && k < (int)sizeof(line)) { sink(line, ctx); written++; }
        }

        /* 类型 02: EAPOL (配对已在到达当刻固化) */
        if (h->pair_kind && h->plen[1] >= 97) {
            /* mp: 0 = M1+M2 取 M2 的 EAPOL; 2 = M2+M3 取 M2 的 EAPOL */
            int mp = (h->pair_kind == 1) ? 0 : 2;
            char mic[33], anonce[65], eapol_hex[HS_EAPOL_MAX * 2 + 1];
            hex_into(mic, h->peo[1] + 81, 16);        /* Key MIC 在固定部分尾部 */
            hex_into(anonce, h->peo[0] + 17, 32);     /* Key Nonce */
            hex_into(eapol_hex, h->peo[1], h->plen[1]);
            int k = snprintf(line, sizeof(line), "WPA*02*%s*%s*%s*%s*%s*%s*%d",
                             mic, ap, sta, essid_hex, anonce, eapol_hex, mp);
            if (k > 0 && k < (int)sizeof(line)) { sink(line, ctx); written++; }
        }
    }
    return written;
}

/* 自检
 * 真实环境里握手很稀疏 (一次可能只碰到单个 M3), 靠天吃饭没法验证格式.
 * 这里构造已知内容的一对 M1/M2 走完整链路, 确定性地校验:
 *   分类 -> 方向映射 -> RC 配对 -> 快照 -> MIC/ANonce 偏移 -> 22000 字段顺序与长度
 */

static int build_eapol_frame(uint8_t *out, bool ap_to_sta, int msg,
                             const uint8_t rc[8], const uint8_t nonce[32],
                             const uint8_t mic[16], const uint8_t *pmkid)
{
    /* 本机管理地址, 不可能命中 wifi_db, 这样 ESSID 字段应为空, 便于核对字段序 */
    static const uint8_t ap[6]  = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t sta[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t snap[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};

    uint8_t *p = out;
    *p++ = 0x08;                                  /* data */
    *p++ = ap_to_sta ? 0x02 : 0x01;               /* fromDS / toDS */
    *p++ = 0x00; *p++ = 0x00;                     /* duration */
    if (ap_to_sta) { memcpy(p, sta, 6); p += 6; memcpy(p, ap, 6); p += 6; memcpy(p, ap, 6); p += 6; }
    else           { memcpy(p, ap,  6); p += 6; memcpy(p, sta, 6); p += 6; memcpy(p, ap, 6); p += 6; }
    *p++ = 0x00; *p++ = 0x00;                     /* seq */
    memcpy(p, snap, sizeof(snap)); p += sizeof(snap);

    int kd = pmkid ? 22 : 0;                      /* DD len OUI(3) type + 16B PMKID */
    uint16_t eapol_len = (uint16_t)(95 + kd);
    *p++ = 0x02;                                  /* EAPOL version */
    *p++ = 0x03;                                  /* EAPOL-Key */
    *p++ = (uint8_t)(eapol_len >> 8); *p++ = (uint8_t)(eapol_len & 0xFF);
    *p++ = 0x02;                                  /* RSN descriptor */
    uint16_t ki;
    /* 用真实 AP 的取值: M1 一定置 key type (pairwise), 所以是 0x008a 而不是
     * 0x0082. 这两位的差别正是当初漏掉 MIC 位的原因, 自检必须跟线上一致. */
    if (msg == 1)      ki = 0x008A;               /* ACK + keytype + keyver2 */
    else if (msg == 2) ki = 0x010A;               /* MIC + keytype + keyver2 */
    else if (msg == 3) ki = 0x13CA;               /* ACK|MIC|INSTALL|SECURE */
    else               ki = 0x030A;               /* MIC|SECURE */
    *p++ = (uint8_t)(ki >> 8); *p++ = (uint8_t)(ki & 0xFF);
    *p++ = 0x00; *p++ = 0x10;                     /* key length */
    memcpy(p, rc, 8);    p += 8;
    memcpy(p, nonce, 32); p += 32;
    memset(p, 0, 16);    p += 16;                 /* IV */
    memset(p, 0, 8);     p += 8;                  /* RSC */
    memset(p, 0, 8);     p += 8;                  /* ID */
    memcpy(p, mic, 16);  p += 16;                 /* MIC: EAPOL 内偏移 81 */
    *p++ = (uint8_t)(kd >> 8); *p++ = (uint8_t)(kd & 0xFF);
    if (pmkid) {
        *p++ = 0xDD; *p++ = 0x14;
        *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x04;
        memcpy(p, pmkid, 16); p += 16;
    }
    return (int)(p - out);
}

static void selftest_sink(const char *line, void *ctx)
{
    (void)ctx;
    printf("%s\n", line);
}

int hs_selftest(void)
{
    uint8_t rc[8]     = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t anonce[32], snonce[32], mic[16], pmkid[16];
    for (int i = 0; i < 32; i++) { anonce[i] = 0xAA; snonce[i] = 0xBB; }
    for (int i = 0; i < 16; i++) { mic[i] = 0xCC; pmkid[i] = 0xDD; }

    hs_clear();
    uint8_t f[512];
    int n;
    /* 1) M1 + M2 同 RC -> 应生成一条 WPA*02, mp=0 */
    n = build_eapol_frame(f, true, 1, rc, anonce, mic, NULL);
    hs_feed(f, (uint16_t)n, -40, 36);
    n = build_eapol_frame(f, false, 2, rc, snonce, mic, NULL);
    hs_feed(f, (uint16_t)n, -40, 36);

    printf("---- selftest: M1+M2 (期望 pair=m1m2, 一条 WPA*02 且末位 mp=0) ----\n");
    hs_dump(false);
    int got = hs_export_22000(selftest_sink, NULL);
    printf("---- selftest: lines=%d ----\n", got);

    /* 2) 只带 PMKID 的 M1 -> 应生成一条 WPA*01 */
    hs_clear();
    n = build_eapol_frame(f, true, 1, rc, anonce, mic, pmkid);
    hs_feed(f, (uint16_t)n, -40, 36);
    printf("---- selftest: 仅 PMKID (期望一条 WPA*01) ----\n");
    hs_dump(false);
    int got2 = hs_export_22000(selftest_sink, NULL);
    printf("---- selftest: lines=%d ----\n", got2);

    /* 3) RC 不一致 -> 必须判为无效 (这是「废握手」的核心防线) */
    hs_clear();
    uint8_t rc2[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x99};
    n = build_eapol_frame(f, true, 1, rc,  anonce, mic, NULL); hs_feed(f, (uint16_t)n, -40, 36);
    n = build_eapol_frame(f, false, 2, rc2, snonce, mic, NULL); hs_feed(f, (uint16_t)n, -40, 36);
    int got3 = hs_export_22000(selftest_sink, NULL);
    printf("---- selftest: RC 不一致 -> lines=%d (期望 0) ----\n", got3);

    hs_clear();
    return (got == 1 && got2 == 1 && got3 == 0) ? 0 : 1;
}


esp_err_t hs_init(void)
{
    if (s_tab) return ESP_OK;
    s_tab = heap_caps_calloc(HS_SLOTS, sizeof(hs_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_tab) s_tab = calloc(HS_SLOTS, sizeof(hs_t));
    if (!s_tab) {
        ESP_LOGW(TAG, "alloc failed, handshake tracking disabled");
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "ready: %d slots (%u B each)",
             HS_SLOTS, (unsigned)sizeof(hs_t));
    return ESP_OK;
}
