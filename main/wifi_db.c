/*
 * wifi_db.c - Wi-Fi sniff database implementation
 *
 * AP/Client/EAPOL tracking with OUI vendor lookup.
 * All storage in PSRAM via heap_caps_calloc.
 */
#include "wifi_db.h"
#include "ie_parse.h"
#include "wifi_names.h"
#include "wifi_export.h"
#include "radio_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"

/* OUI table (top vendors, compressed) */
/* Format: {oui[3], name}. Sorted for binary search. */
typedef struct { uint8_t oui[3]; const char *name; } oui_entry_t;

static const char *DB_TAG = "WDB";

static const oui_entry_t s_oui_table[] = {
    {{0x00,0x0C,0xE7}, "Espressif"},
    {{0x00,0x11,0x22}, "Custom"},
    {{0x00,0x1A,0x11}, "Google"},
    {{0x00,0x50,0x56}, "VMware"},
    {{0x00,0x50,0xF2}, "Microsoft"},
    {{0x00,0x60,0x2F}, "Cisco"},
    {{0x00,0xA0,0xF8}, "Symbol"},
    {{0x04,0x0E,0x0E}, "Tp-link"},
    {{0x04,0xC0,0x07}, "Tp-link"},
    {{0x0C,0x82,0x8C}, "Tp-link"},
    {{0x10,0x27,0xBE}, "Apple"},
    {{0x14,0x8F,0xB6}, "Tp-link"},
    {{0x18,0xA6,0xF0}, "Tp-link"},
    {{0x1C,0xBF,0xCE}, "Tp-link"},
    {{0x24,0x0A,0x64}, "Tp-link"},
    {{0x28,0x15,0xA4}, "Unknown"},
    {{0x30,0xB5,0xC2}, "Espressif"},
    {{0x3C,0xDC,0x75}, "Espressif"},
    {{0x40,0x83,0x3F}, "Tp-link"},
    {{0x48,0x57,0x02}, "Unknown"},
    {{0x50,0xC7,0xBF}, "Tp-link"},
    {{0x54,0xA6,0x51}, "Unknown"},
    {{0x58,0xD5,0x6E}, "Tp-link"},
    {{0x60,0x32,0xB1}, "Tp-link"},
    {{0x64,0x16,0x66}, "Tp-link"},
    {{0x68,0x77,0x24}, "Waveshare"},
    {{0x7C,0xDD,0x90}, "Unknown"},
    {{0x7E,0x77,0x24}, "Waveshare"},
    {{0x80,0xEA,0x96}, "Tp-link"},
    {{0x8C,0xE1,0x17}, "Tp-link"},
    {{0x90,0x4C,0xE0}, "Unknown"},
    {{0x9C,0xF6,0xDD}, "Tp-link"},
    {{0xA0,0xF3,0xC1}, "Tp-link"},
    {{0xAC,0x84,0xC6}, "Tp-link"},
    {{0xB0,0x4E,0x60}, "Unknown"},
    {{0xC0,0x4A,0x00}, "Tp-link"},
    {{0xD4,0x6A,0x8A}, "Unknown"},
    {{0xE0,0x4D,0x84}, "Unknown"},
    {{0xE4,0xFE,0x43}, "Unknown"},
    {{0xEC,0x08,0x6B}, "Tp-link"},
    {{0xF0,0x99,0xB6}, "Tp-link"},
    {{0xF4,0xEC,0x38}, "Unknown"},
};
#define OUI_COUNT (sizeof(s_oui_table)/sizeof(s_oui_table[0]))

const char *oui_lookup(const uint8_t mac[3])
{
    /* Linear search (table is small, ~40 entries) */
    for (int i = 0; i < (int)OUI_COUNT; i++) {
        if (s_oui_table[i].oui[0] == mac[0] &&
            s_oui_table[i].oui[1] == mac[1] &&
            s_oui_table[i].oui[2] == mac[2])
            return s_oui_table[i].name;
    }
    return "Unknown";
}

const char *enc_str(uint8_t enc) { return wifi_enc_str(enc); }

/* Storage (PSRAM) */
static ap_entry_t     *s_aps     = NULL;
static client_entry_t *s_clients = NULL;
static eapol_entry_t  *s_eapols  = NULL;
static int s_ap_cnt = 0, s_cli_cnt = 0, s_eap_cnt = 0;

/* 哈希索引: 256 桶 + 单链分离链地址法.
 * 原为全表线性扫描, 满表时每包 memcmp 至多 256 次; 此路径跑在 promiscuous 回调
 * (Wi-Fi 驱动任务), 直接吃掉驱动时间片, 高密度下丢包. 改后平均查找长度 ~ n/256,
 * 满表近 O(1). s_ap_bucket[b] = 桶内首条目下标 (-1 空), s_ap_next[i] = 同桶下一个.
 * 桶表与条目同在 PSRAM: 四张表占 2KB 内部 RAM, 而 NimBLE 初始化要一块 >=32KB 的
 * 连续内部块, 少 2KB 就 ESP_ERR_NO_MEM. */
#define DB_BUCKETS 256

static int16_t *s_ap_bucket  = NULL;
static int16_t *s_ap_next    = NULL;
static int16_t *s_cli_bucket = NULL;
static int16_t *s_cli_next   = NULL;

/* Simple hash: 6-byte MAC -> 0..255 */
static inline uint8_t mac_hash(const uint8_t mac[6])
{
    /* FNV-ish 混合: 只用异或会让真实 MAC 的 OUI 前缀分布很差
     * (同厂商设备前 3 字节相同), 乘一个奇数打散. */
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return (uint8_t)(h >> 16);
}

static bool db_index_alloc(void)
{
    if (s_ap_bucket) return true;
    s_ap_bucket  = heap_caps_calloc(DB_BUCKETS, sizeof(int16_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_ap_next    = heap_caps_calloc(WIFI_DB_MAX_APS, sizeof(int16_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_cli_bucket = heap_caps_calloc(DB_BUCKETS, sizeof(int16_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_cli_next   = heap_caps_calloc(WIFI_DB_MAX_CLIENTS, sizeof(int16_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return s_ap_bucket && s_ap_next && s_cli_bucket && s_cli_next;
}

static void db_index_reset(void)
{
    if (!db_index_alloc()) return;
    for (int i = 0; i < DB_BUCKETS; i++) {
        s_ap_bucket[i]  = -1;
        s_cli_bucket[i] = -1;
    }
    for (int i = 0; i < WIFI_DB_MAX_APS; i++)     s_ap_next[i]  = -1;
    for (int i = 0; i < WIFI_DB_MAX_CLIENTS; i++) s_cli_next[i] = -1;
}

/* Find or create AP entry by BSSID */
static ap_entry_t *find_ap(const uint8_t bssid[6])
{
    if (!s_aps || !s_ap_bucket) return NULL;
    uint8_t b = mac_hash(bssid);
    for (int16_t i = s_ap_bucket[b]; i >= 0; i = s_ap_next[i]) {
        if (memcmp(s_aps[i].bssid, bssid, 6) == 0)
            return &s_aps[i];
    }
    if (s_ap_cnt < WIFI_DB_MAX_APS) {
        int16_t idx = (int16_t)s_ap_cnt++;
        ap_entry_t *e = &s_aps[idx];
        memset(e, 0, sizeof(*e));
        memcpy(e->bssid, bssid, 6);
        const char *v = oui_lookup(bssid);
        strncpy(e->vendor, v, sizeof(e->vendor) - 1);
        e->hidden = true;
        /* 头插: 新条目进桶首, 最近活跃的 AP 查找更快 */
        s_ap_next[idx]   = s_ap_bucket[b];
        s_ap_bucket[b]   = idx;
        return e;
    }
    return NULL;
}

static client_entry_t *find_client(const uint8_t mac[6])
{
    if (!s_clients || !s_cli_bucket) return NULL;
    uint8_t b = mac_hash(mac);
    for (int16_t i = s_cli_bucket[b]; i >= 0; i = s_cli_next[i]) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0)
            return &s_clients[i];
    }
    if (s_cli_cnt < WIFI_DB_MAX_CLIENTS) {
        int16_t idx = (int16_t)s_cli_cnt++;
        client_entry_t *e = &s_clients[idx];
        memset(e, 0, sizeof(*e));
        memcpy(e->mac, mac, 6);
        const char *v = oui_lookup(mac);
        strncpy(e->vendor, v, sizeof(e->vendor) - 1);
        s_cli_next[idx]   = s_cli_bucket[b];
        s_cli_bucket[b]   = idx;
        return e;
    }
    return NULL;
}


/* IE 解析已移到 ie_parse.c, 原来的 parse_rsn() 有 bug:
 * AKM 套件是 4 字节 (OUI 00-0F-AC + type), 它却只取前 2 字节当 uint16 与
 * 0x0008 比较, 而前两字节恒为 00 0F, 所以 SAE (WPA3) 永远识别不出来. */

/* Extract SSID from IE, sanitize non-printable */
static int safe_extract_ssid(const uint8_t *frame, int len, char *dst, int cap)
{
    int off = 24 + 12; /* mac header + beacon fixed fields */
    while (off + 2 <= len) {
        uint8_t id = frame[off];
        uint8_t slen = frame[off + 1];
        if (off + 2 + slen > len) break;
        if (id == 0) {
            int n = slen < cap - 1 ? slen : cap - 1;
            memcpy(dst, frame + off + 2, n);
            dst[n] = '\0';
            /* 只清理控制字符, 保留 UTF-8 多字节.
             * 原来把 >= 0x80 的字节全换成 '?', 于是中文 SSID 全成了乱码
             * (实测 "6G网" 显示为 "6G???"), 而中文 SSID 在国内极常见.
             * 下游 App / JSON / CSV 都是 UTF-8, 直接透传即可. */
            for (int i = 0; i < n; i++) {
                unsigned char c = (unsigned char)dst[i];
                if (c < 0x20 || c == 0x7f) dst[i] = '?';
            }
            return n;
        }
        off += 2 + slen;
    }
    dst[0] = '\0';
    return 0;
}


esp_err_t wifi_db_init(void)
{
    if (!s_aps) {
        s_aps = heap_caps_calloc(WIFI_DB_MAX_APS, sizeof(ap_entry_t), MALLOC_CAP_SPIRAM);
        if (!s_aps) return ESP_ERR_NO_MEM;
    }
    if (!s_clients) {
        s_clients = heap_caps_calloc(WIFI_DB_MAX_CLIENTS, sizeof(client_entry_t), MALLOC_CAP_SPIRAM);
        if (!s_clients) return ESP_ERR_NO_MEM;
    }
    if (!s_eapols) {
        s_eapols = heap_caps_calloc(WIFI_DB_MAX_EAPOLS, sizeof(eapol_entry_t), MALLOC_CAP_SPIRAM);
        if (!s_eapols) return ESP_ERR_NO_MEM;
    }
    s_ap_cnt = s_cli_cnt = s_eap_cnt = 0;
    db_index_reset();
    ESP_LOGI(DB_TAG, "db init: aps=%p clients=%p eapols=%p", s_aps, s_clients, s_eapols);
    return ESP_OK;
}

void wifi_db_clear(void)
{
    s_ap_cnt = s_cli_cnt = s_eap_cnt = 0;
    if (s_aps) memset(s_aps, 0, WIFI_DB_MAX_APS * sizeof(ap_entry_t));
    if (s_clients) memset(s_clients, 0, WIFI_DB_MAX_CLIENTS * sizeof(client_entry_t));
    if (s_eapols) memset(s_eapols, 0, WIFI_DB_MAX_EAPOLS * sizeof(eapol_entry_t));
    db_index_reset();
}

bool wifi_db_update_ap(const uint8_t *frame, int len, uint8_t channel, int8_t rssi)
{
    if (!s_aps) { ESP_LOGE(DB_TAG, "update_ap: s_aps is NULL!"); return false; }
    if (len < 24) return false;
    const uint8_t *bssid = frame + 16; /* addr3 */
    ap_entry_t *e = find_ap(bssid);
    if (!e) return false;
    /* find_ap 未命中时会新建条目, 新条目的 beacon_count 为 0.
     * 在自增之前取这个标志, 就是"这台 AP 是不是刚被发现". */
    bool is_new = (e->beacon_count == 0);
    e->rssi = rssi;
    e->channel = channel;
    e->last_seen_tick = (uint32_t)esp_timer_get_time();
    e->beacon_count++;
    /* Extract SSID */
    char ssid[34];
    int slen = safe_extract_ssid(frame, len, ssid, sizeof(ssid));
    if (slen > 0) {
        /* Real SSID (not hidden) - update */
        strncpy(e->ssid, ssid, sizeof(e->ssid) - 1);
        e->ssid[sizeof(e->ssid)-1] = '\0';
        e->hidden = false;
    } else {
        e->hidden = true;
        if (e->ssid[0] == '\0') strncpy(e->ssid, "<hidden>", sizeof(e->ssid)-1);
    }
    /* 一次解析出安全套件 / PMF / WPS / 11n-ax / 带宽 */
    ap_caps_t caps;
    ie_parse_ap(frame, len, &caps);
    e->encryption = caps.enc;
    e->pmf        = (caps.pmf & CAP_PMF_REQUIRED) != 0;
    e->pmf_cap    = (caps.pmf & CAP_PMF_CAPABLE) != 0;
    e->akm        = caps.akm;
    /* 过渡模式 = 同时宣告 PSK 与 SAE, 且没有强制 PMF. 只要 MFP 必需, 客户端
     * 就会验 RSN IE, 伪造一个只宣告 WPA2 的孪生会被识破. */
    e->transition = ((caps.akm & CAP_AKM_PSK) != 0) &&
                    ((caps.akm & CAP_AKM_SAE) != 0) && !e->pmf;
    e->bss_color  = caps.bss_color;
    e->twt        = caps.twt;
    e->twt_req    = caps.twt_req;
    e->rnr_count  = caps.rnr_count;
    e->rnr_ch     = caps.rnr_ch;
    e->rnr_6g     = caps.rnr_6g;
    e->cipher     = caps.cipher;
    e->bw         = caps.bw;
    e->ht         = caps.ht;
    e->vht        = caps.vht;
    e->he         = caps.he;
    e->wps        = caps.wps;
    e->crackable  = caps.crackable;
    return is_new;
}

void wifi_db_update_client(const uint8_t *frame, int len, int8_t rssi)
{
    if (!s_clients || len < 24) return;
    uint8_t ftype = frame_type(frame);
    if (ftype != FC_TYPE_DATA) return;
    /* Determine station MAC based on ToDS/FromDS */
    uint8_t tods = frame[1] & 0x01;
    uint8_t fromds = (frame[1] >> 1) & 0x01;
    const uint8_t *sta = NULL;
    const uint8_t *bssid = NULL;
    if (fromds && !tods) {
        /* AP -> STA: addr1=STA, addr2=BSSID */
        sta = frame + 4;
        bssid = frame + 10;
    } else if (tods && !fromds) {
        /* STA -> AP: addr2=STA, addr3=BSSID */
        sta = frame + 10;
        bssid = frame + 16;
    } else {
        return; /* WDS or ad-hoc, skip */
    }
    /* Skip broadcast/multicast */
    if (sta[0] & 0x01) return;
    client_entry_t *c = find_client(sta);
    if (!c) return;
    c->rssi = rssi;
    /* RSSI 趋势采样 (环形, 保留最近 WIFI_DB_RSSI_HIST 次) */
    c->rssi_hist[c->rssi_i] = rssi;
    c->rssi_i = (uint8_t)((c->rssi_i + 1) % WIFI_DB_RSSI_HIST);
    if (c->rssi_n < WIFI_DB_RSSI_HIST) c->rssi_n++;
    c->pkt_count++;
    c->last_seen_tick = (uint32_t)esp_timer_get_time();
    if (bssid) memcpy(c->bssid, bssid, 6);
}

bool wifi_db_check_eapol(const uint8_t *frame, int len, int8_t rssi)
{
    (void)rssi;
    if (!s_eapols || len < 30) return false;
    uint8_t ftype = frame_type(frame);
    if (ftype != FC_TYPE_DATA) return false;
    /* Data frame: skip mac header (24) + LLC/SNAP (6) -> ethertype (2) */
    int off = 24;
    /* QoS data has 2 extra bytes */
    uint8_t fsub = frame_subtype(frame);
    if (fsub & 0x08) off += 2; /* QoS */
    if (off + 8 > len) return false;
    /* LLC/SNAP: AA AA 03 00 00 00 + ethertype */
    if (frame[off] == 0xAA && frame[off+1] == 0xAA && frame[off+2] == 0x03) {
        uint16_t ether_type = frame[off+6] | (frame[off+7] << 8);
        if (ether_type == 0x888E) {
            /* EAPOL! Record it */
            if (s_eap_cnt < WIFI_DB_MAX_EAPOLS) {
                eapol_entry_t *e = &s_eapols[s_eap_cnt++];
                memset(e, 0, sizeof(*e));
                memcpy(e->src, frame + 10, 6); /* addr2 = SA */
                memcpy(e->dst, frame + 4, 6);  /* addr1 = DA */
                e->tick = (uint32_t)esp_timer_get_time();
                /* Parse EAPOL type and key info */
                int eapol_off = off + 8;
                if (eapol_off + 4 <= len) {
                    e->eapol_type = frame[eapol_off]; /* 3 = EAPOL-Key */
                    if (e->eapol_type == 3 && eapol_off + 99 <= len) {
                        /* Key Information field at offset +5 from EAPOL */
                        uint16_t key_info = frame[eapol_off + 5] | (frame[eapol_off + 6] << 8);
                        uint8_t ack = (key_info >> 7) & 1;
                        uint8_t mic = (key_info >> 8) & 1;
                        uint8_t install = (key_info >> 6) & 1;
                        if (ack && !mic && !install) e->handshake_step = 1; /* M1 */
                        else if (!ack && mic && !install) e->handshake_step = 2; /* M2 */
                        else if (ack && mic && install) e->handshake_step = 3; /* M3 */
                        else if (!ack && mic && !install) e->handshake_step = 4; /* M4 */
                        else e->handshake_step = 0;
                    }
                }
            }
            return true;
        }
    }
    return false;
}

/* Dump / Export */

/* 由 ap_entry_t 还原出 ap_caps_t, 好复用 ie_parse 的字符串化函数 */
static void caps_from_entry(const ap_entry_t *e, ap_caps_t *c)
{
    wifi_caps_from_entry(e, c);
}

static const char *cipher_str(uint8_t m) { return wifi_cipher_str(m); }

void wifi_db_dump_aps(void)
{
    ESP_LOGI(DB_TAG, "dump_aps: count=%d, s_aps=%p", s_ap_cnt, s_aps);
    printf("META,WIFI,APS,count,%d\n", s_ap_cnt);
    for (int i = 0; i < s_ap_cnt; i++) {
        ap_entry_t *e = &s_aps[i];
        char bssid[18], akm[32];
        ap_caps_t c;
        caps_from_entry(e, &c);
        caps_akm_str(&c, akm, sizeof(akm));
        mac_to_str(e->bssid, bssid);
        /* 前 11 个字段保持原样 (App 既有的位置解析不受影响), 新字段追加在后面 */
        printf("AP,%s,%s,ch%d,rssi%d,%s,%s,pmf%d,bcn%u,data%u,%s,"
               "akm,%s,cip,%s,bw,%u,std,%s,wps,%d,pmfc,%d,crk,%d,trans,%d\n",
               bssid, e->ssid, e->channel, e->rssi,
               enc_str(e->encryption), e->hidden ? "HIDDEN" : "VISIBLE",
               e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count,
               e->vendor, akm, cipher_str(e->cipher), (unsigned)e->bw,
               caps_std_str(&c), e->wps ? 1 : 0, e->pmf_cap ? 1 : 0,
               e->crackable ? 1 : 0, e->transition ? 1 : 0);
    }
    fflush(stdout);
}

/* 按时间序打印 RSSI 采样 (最旧 -> 最新) */
static void print_rssi_hist(const client_entry_t *c)
{
    int n = c->rssi_n;
    if (n <= 0) { printf("-"); return; }
    int start = wifi_hist_start(c->rssi_i, (uint8_t)n);
    for (int k = 0; k < n; k++) {
        printf("%s%d", k ? "|" : "", c->rssi_hist[(start + k) % WIFI_DB_RSSI_HIST]);
    }
}

void wifi_db_dump_clients(void)
{
    printf("META,WIFI,CLIENTS,count,%d\n", s_cli_cnt);
    for (int i = 0; i < s_cli_cnt; i++) {
        client_entry_t *c = &s_clients[i];
        char mac[18], bssid[18];
        mac_to_str(c->mac, mac);
        mac_to_str(c->bssid, bssid);
        printf("CLIENT,%s,%s,rssi%d,pkts%u,%s,hist,",
               mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor);
        print_rssi_hist(c);
        printf("\n");
    }
    fflush(stdout);
}

void wifi_db_dump_eapols(void)
{
    printf("META,WIFI,EAPOL,count,%d\n", s_eap_cnt);
    for (int i = 0; i < s_eap_cnt; i++) {
        eapol_entry_t *e = &s_eapols[i];
        char src[18], dst[18];
        mac_to_str(e->src, src);
        mac_to_str(e->dst, dst);
        printf("EAPOL,%s,%s,type%d,step%d\n",
               src, dst, e->eapol_type, e->handshake_step);
    }
    fflush(stdout);
}

void wifi_db_export_csv(void)
{
    char line[WIFI_EXPORT_LINE_MAX];
    printf("META,WIFI,EXPORT,csv,start\n");
    printf("type,bssid_or_mac,ssid,channel,rssi,encryption,hidden,pmf,beacon_count,"
           "data_count,vendor,akm,cipher,bw,std,wps,pmf_cap,crackable\n");
    for (int i = 0; i < s_ap_cnt; i++) {
        wifi_export_csv_ap(&s_aps[i], line, sizeof(line));
        printf("%s\n", line);
    }
    printf("\ntype,mac,bssid,rssi,pkt_count,vendor,rssi_hist\n");
    for (int i = 0; i < s_cli_cnt; i++) {
        wifi_export_csv_client(&s_clients[i], line, sizeof(line));
        printf("%s\n", line);
    }
    printf("\ntype,src,dst,eapol_type,handshake_step\n");
    for (int i = 0; i < s_eap_cnt; i++) {
        wifi_export_csv_eapol(&s_eapols[i], line, sizeof(line));
        printf("%s\n", line);
    }
    printf("META,WIFI,EXPORT,csv,done,aps,%d,clients,%d,eapols,%d\n",
           s_ap_cnt, s_cli_cnt, s_eap_cnt);
    fflush(stdout);
}

void wifi_db_export_json(void)
{
    char line[WIFI_EXPORT_LINE_MAX];
    printf("META,WIFI,EXPORT,json,start\n");
    printf("{\"aps\":[");
    for (int i = 0; i < s_ap_cnt; i++) {
        if (i > 0) printf(",");
        wifi_export_json_ap(&s_aps[i], line, sizeof(line));
        printf("%s", line);
    }
    printf("],\"clients\":[");
    for (int i = 0; i < s_cli_cnt; i++) {
        if (i > 0) printf(",");
        wifi_export_json_client(&s_clients[i], line, sizeof(line));
        printf("%s", line);
    }
    printf("],\"eapols\":[");
    for (int i = 0; i < s_eap_cnt; i++) {
        if (i > 0) printf(",");
        wifi_export_json_eapol(&s_eapols[i], line, sizeof(line));
        printf("%s", line);
    }
    printf("]}\n");
    printf("META,WIFI,EXPORT,json,done,aps,%d,clients,%d,eapols,%d\n",
           s_ap_cnt, s_cli_cnt, s_eap_cnt);
    fflush(stdout);
}

int wifi_db_ap_count(void)     { return s_ap_cnt; }
int wifi_db_client_count(void) { return s_cli_cnt; }
int wifi_db_eapol_count(void)   { return s_eap_cnt; }

const ap_entry_t *wifi_db_get_aps(int *out_cnt)
{
    if (out_cnt) *out_cnt = s_ap_cnt;
    return s_aps;
}
const client_entry_t *wifi_db_get_clients(int *out_cnt)
{
    if (out_cnt) *out_cnt = s_cli_cnt;
    return s_clients;
}
const eapol_entry_t *wifi_db_get_eapols(int *out_cnt)
{
    if (out_cnt) *out_cnt = s_eap_cnt;
    return s_eapols;
}

/* 精确查找 (不创建). 复用桶索引, 未命中立即返回. */
const ap_entry_t *wifi_db_find_ap(const uint8_t bssid[6])
{
    if (!s_aps || !bssid || !s_ap_bucket) return NULL;
    uint8_t b = mac_hash(bssid);
    for (int16_t i = s_ap_bucket[b]; i >= 0; i = s_ap_next[i]) {
        if (memcmp(s_aps[i].bssid, bssid, 6) == 0) return &s_aps[i];
    }
    return NULL;
}

const client_entry_t *wifi_db_find_client(const uint8_t mac[6])
{
    if (!s_clients || !mac || !s_cli_bucket) return NULL;
    uint8_t b = mac_hash(mac);
    for (int16_t i = s_cli_bucket[b]; i >= 0; i = s_cli_next[i]) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) return &s_clients[i];
    }
    return NULL;
}
