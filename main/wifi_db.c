/*
 * wifi_db.c - Wi-Fi sniff database implementation
 *
 * AP/Client/EAPOL tracking with OUI vendor lookup.
 * All storage in PSRAM via heap_caps_calloc.
 */
#include "wifi_db.h"
#include "radio_common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"

/* ===================== OUI table (top vendors, compressed) ===================== */
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

const char *enc_str(uint8_t enc)
{
    switch (enc) {
    case 0: return "OPEN";
    case 1: return "WEP";
    case 2: return "WPA";
    case 3: return "WPA2";
    case 4: return "WPA3";
    case 5: return "WPA/W2";
    default: return "?";
    }
}

/* ===================== Storage (PSRAM) ===================== */
static ap_entry_t     *s_aps     = NULL;
static client_entry_t *s_clients = NULL;
static eapol_entry_t  *s_eapols  = NULL;
static int s_ap_cnt = 0, s_cli_cnt = 0, s_eap_cnt = 0;

/* Simple hash: 6-byte MAC -> 0..255 */
static inline uint8_t mac_hash(const uint8_t mac[6])
{
    return (mac[0] ^ mac[1] ^ mac[2] ^ mac[3] ^ mac[4] ^ mac[5]) & 0xFF;
}

/* Find or create AP entry by BSSID */
static ap_entry_t *find_ap(const uint8_t bssid[6])
{
    /* Linear search (256 max, acceptable in callback) */
    for (int i = 0; i < s_ap_cnt; i++) {
        if (memcmp(s_aps[i].bssid, bssid, 6) == 0)
            return &s_aps[i];
    }
    if (s_ap_cnt < WIFI_DB_MAX_APS) {
        ap_entry_t *e = &s_aps[s_ap_cnt++];
        memset(e, 0, sizeof(*e));
        memcpy(e->bssid, bssid, 6);
        const char *v = oui_lookup(bssid);
        strncpy(e->vendor, v, sizeof(e->vendor) - 1);
        e->hidden = true;
        return e;
    }
    return NULL;
}

static client_entry_t *find_client(const uint8_t mac[6])
{
    for (int i = 0; i < s_cli_cnt; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0)
            return &s_clients[i];
    }
    if (s_cli_cnt < WIFI_DB_MAX_CLIENTS) {
        client_entry_t *e = &s_clients[s_cli_cnt++];
        memset(e, 0, sizeof(*e));
        memcpy(e->mac, mac, 6);
        const char *v = oui_lookup(mac);
        strncpy(e->vendor, v, sizeof(e->vendor) - 1);
        return e;
    }
    return NULL;
}

/* ===================== IE parsing ===================== */

/* Parse RSN IE (id=48) for WPA2/WPA3 + PMF */
static void parse_rsn(const uint8_t *ie, int ie_len, uint8_t *enc, bool *pmf)
{
    *enc = 3; /* WPA2 default */
    *pmf = false;
    if (ie_len < 2) return;
    int off = 2; /* skip version */
    /* Group cipher: 4 bytes */
    if (off + 4 > ie_len) return;
    off += 4;
    /* Pairwise cipher count */
    if (off + 2 > ie_len) return;
    int count = ie[off] | (ie[off+1] << 8);
    off += 2;
    /* Skip pairwise ciphers */
    off += count * 4;
    /* AKM count */
    if (off + 2 > ie_len) return;
    int akm_count = ie[off] | (ie[off+1] << 8);
    off += 2;
    /* Check AKM types for WPA3 (SAE = 0x000F00) */
    for (int i = 0; i < akm_count && off + 4 <= ie_len; i++) {
        uint16_t akm = ie[off] | (ie[off+1] << 8);
        if (akm == 0x0008 || akm == 0x0009) *enc = 4; /* SAE = WPA3 */
        off += 4;
    }
    /* RSN capabilities (2 bytes) */
    if (off + 2 <= ie_len) {
        uint16_t caps = ie[off] | (ie[off+1] << 8);
        if (caps & 0x0080) *pmf = true; /* MFPR or MFCR */
    }
}

/* Parse WPA IE (id=221, vendor specific) */
static bool parse_wpa_vendor(const uint8_t *ie, int ie_len, uint8_t *enc)
{
    if (ie_len < 6) return false;
    /* Check for Microsoft OUI 00:50:F2 */
    if (ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xF2 && ie[3] == 0x01) {
        *enc = 2; /* WPA */
        return true;
    }
    return false;
}

/* Iterate IEs in frame body, extract encryption info */
static void extract_encryption(const uint8_t *frame, int len, uint8_t *enc, bool *pmf)
{
    *enc = 0; /* OPEN default */
    *pmf = false;
    int off = 24; /* skip mac header (24 bytes mgmt) */
    /* For beacon: skip fixed fields (8+2+2=12) */
    off += 12;
    bool found_wpa = false, found_rsn = false;
    while (off + 2 <= len) {
        uint8_t id = frame[off];
        int slen = frame[off + 1];
        if (off + 2 + slen > len) break;
        if (id == 48) { /* RSN IE */
            found_rsn = true;
            parse_rsn(frame + off + 2, slen, enc, pmf);
        } else if (id == 221) { /* Vendor specific */
            uint8_t e2;
            if (parse_wpa_vendor(frame + off + 2, slen, &e2)) {
                found_wpa = true;
            }
        }
        off += 2 + slen;
    }
    if (!found_rsn && found_wpa) *enc = 2;
    if (!found_rsn && !found_wpa) *enc = 0;
}

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
            for (int i = 0; i < n; i++) {
                if ((unsigned char)dst[i] < 0x20 || (unsigned char)dst[i] > 0x7e)
                    dst[i] = '?';
            }
            return n;
        }
        off += 2 + slen;
    }
    dst[0] = '\0';
    return 0;
}

/* ===================== Public API ===================== */

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
    ESP_LOGI(DB_TAG, "db init: aps=%p clients=%p eapols=%p", s_aps, s_clients, s_eapols);
    return ESP_OK;
}

void wifi_db_clear(void)
{
    s_ap_cnt = s_cli_cnt = s_eap_cnt = 0;
    if (s_aps) memset(s_aps, 0, WIFI_DB_MAX_APS * sizeof(ap_entry_t));
    if (s_clients) memset(s_clients, 0, WIFI_DB_MAX_CLIENTS * sizeof(client_entry_t));
    if (s_eapols) memset(s_eapols, 0, WIFI_DB_MAX_EAPOLS * sizeof(eapol_entry_t));
}

void wifi_db_update_ap(const uint8_t *frame, int len, uint8_t channel, int8_t rssi)
{
    if (!s_aps) { ESP_LOGE(DB_TAG, "update_ap: s_aps is NULL!"); return; }
    if (len < 24) return;
    const uint8_t *bssid = frame + 16; /* addr3 */
    ap_entry_t *e = find_ap(bssid);
    if (!e) return;
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
    /* Parse encryption */
    uint8_t enc; bool pmf;
    extract_encryption(frame, len, &enc, &pmf);
    e->encryption = enc;
    e->pmf = pmf;
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

/* ===================== Dump / Export ===================== */

void wifi_db_dump_aps(void)
{
    ESP_LOGI(DB_TAG, "dump_aps: count=%d, s_aps=%p", s_ap_cnt, s_aps);
    printf("META,WIFI,APS,count,%d\n", s_ap_cnt);
    for (int i = 0; i < s_ap_cnt; i++) {
        ap_entry_t *e = &s_aps[i];
        char bssid[18];
        mac_to_str(e->bssid, bssid);
        printf("AP,%s,%s,ch%d,rssi%d,%s,%s,pmf%d,bcn%u,data%u,%s\n",
               bssid, e->ssid, e->channel, e->rssi,
               enc_str(e->encryption), e->hidden ? "HIDDEN" : "VISIBLE",
               e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count,
               e->vendor);
    }
    fflush(stdout);
}

void wifi_db_dump_clients(void)
{
    printf("META,WIFI,CLIENTS,count,%d\n", s_cli_cnt);
    for (int i = 0; i < s_cli_cnt; i++) {
        client_entry_t *c = &s_clients[i];
        char mac[18], bssid[18];
        mac_to_str(c->mac, mac);
        mac_to_str(c->bssid, bssid);
        printf("CLIENT,%s,%s,rssi%d,pkts%u,%s\n",
               mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor);
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
    printf("META,WIFI,EXPORT,csv,start\n");
    printf("type,bssid_or_mac,ssid,channel,rssi,encryption,hidden,pmf,beacon_count,data_count,vendor\n");
    for (int i = 0; i < s_ap_cnt; i++) {
        ap_entry_t *e = &s_aps[i];
        char bssid[18];
        mac_to_str(e->bssid, bssid);
        printf("AP,%s,\"%s\",%d,%d,%s,%s,%d,%u,%u,%s\n",
               bssid, e->ssid, e->channel, e->rssi,
               enc_str(e->encryption), e->hidden ? "Y" : "N",
               e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count, e->vendor);
    }
    printf("\ntype,mac,bssid,rssi,pkt_count,vendor\n");
    for (int i = 0; i < s_cli_cnt; i++) {
        client_entry_t *c = &s_clients[i];
        char mac[18], bssid[18];
        mac_to_str(c->mac, mac);
        mac_to_str(c->bssid, bssid);
        printf("CLIENT,%s,%s,%d,%u,%s\n",
               mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor);
    }
    printf("\ntype,src,dst,eapol_type,handshake_step\n");
    for (int i = 0; i < s_eap_cnt; i++) {
        eapol_entry_t *e = &s_eapols[i];
        char src[18], dst[18];
        mac_to_str(e->src, src);
        mac_to_str(e->dst, dst);
        printf("EAPOL,%s,%s,%d,%d\n", src, dst, e->eapol_type, e->handshake_step);
    }
    printf("META,WIFI,EXPORT,csv,done,aps,%d,clients,%d,eapols,%d\n",
           s_ap_cnt, s_cli_cnt, s_eap_cnt);
    fflush(stdout);
}

void wifi_db_export_json(void)
{
    printf("META,WIFI,EXPORT,json,start\n");
    printf("{\"aps\":[");
    for (int i = 0; i < s_ap_cnt; i++) {
        ap_entry_t *e = &s_aps[i];
        char bssid[18];
        mac_to_str(e->bssid, bssid);
        if (i > 0) printf(",");
        printf("{\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%d,\"rssi\":%d,"
               "\"encryption\":\"%s\",\"hidden\":%s,\"pmf\":%d,"
               "\"beacons\":%u,\"data\":%u,\"vendor\":\"%s\"}",
               bssid, e->ssid, e->channel, e->rssi,
               enc_str(e->encryption), e->hidden ? "true" : "false",
               e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count, e->vendor);
    }
    printf("],\"clients\":[");
    for (int i = 0; i < s_cli_cnt; i++) {
        client_entry_t *c = &s_clients[i];
        char mac[18], bssid[18];
        mac_to_str(c->mac, mac);
        mac_to_str(c->bssid, bssid);
        if (i > 0) printf(",");
        printf("{\"mac\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"pkts\":%u,\"vendor\":\"%s\"}",
               mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor);
    }
    printf("],\"eapols\":[");
    for (int i = 0; i < s_eap_cnt; i++) {
        eapol_entry_t *e = &s_eapols[i];
        char src[18], dst[18];
        mac_to_str(e->src, src);
        mac_to_str(e->dst, dst);
        if (i > 0) printf(",");
        printf("{\"src\":\"%s\",\"dst\":\"%s\",\"type\":%d,\"step\":%d}",
               src, dst, e->eapol_type, e->handshake_step);
    }
    printf("]}\n");
    printf("META,WIFI,EXPORT,json,done,aps,%d,clients,%d,eapols,%d\n",
           s_ap_cnt, s_cli_cnt, s_eap_cnt);
    fflush(stdout);
}

int wifi_db_ap_count(void)     { return s_ap_cnt; }
int wifi_db_client_count(void) { return s_cli_cnt; }
int wifi_db_eapol_count(void)   { return s_eap_cnt; }

/* ===================== 只读遍历 getter ===================== */
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
