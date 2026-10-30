#include "wifi_export.h"

#include <stdio.h>

#include "ie_parse.h"
#include "wifi_names.h"

/* RSSI 趋势: CSV 用 | 分隔, JSON 用逗号. 空 hist 时 CSV 写 "-", JSON 写空数组. */
static void hist_join(const client_entry_t *c, char sep, char *out, size_t cap)
{
    int n = c->rssi_n;
    if (n > WIFI_DB_RSSI_HIST) n = WIFI_DB_RSSI_HIST;
    if (n <= 0) { out[0] = '\0'; return; }

    int start = wifi_hist_start(c->rssi_i, (uint8_t)n);
    size_t used = 0;
    for (int k = 0; k < n; k++) {
        int v = c->rssi_hist[(start + k) % WIFI_DB_RSSI_HIST];
        int w = snprintf(out + used, cap - used, "%s%d", k ? (char[2]){sep, 0} : "", v);
        if (w < 0 || (size_t)w >= cap - used) break;
        used += (size_t)w;
    }
}

void wifi_export_csv_ap(const ap_entry_t *e, char *out, size_t cap)
{
    char bssid[18], akm[32];
    ap_caps_t cc;
    wifi_mac_str(e->bssid, bssid);
    wifi_caps_from_entry(e, &cc);
    caps_akm_str(&cc, akm, sizeof(akm));

    snprintf(out, cap,
             "AP,%s,\"%s\",%d,%d,%s,%s,%d,%u,%u,%s,%s,%s,%u,%s,%d,%d,%d",
             bssid, e->ssid, e->channel, e->rssi,
             wifi_enc_str(e->encryption), e->hidden ? "Y" : "N",
             e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count,
             e->vendor, akm, wifi_cipher_str(e->cipher), (unsigned)e->bw,
             caps_std_str(&cc), e->wps ? 1 : 0, e->pmf_cap ? 1 : 0,
             e->crackable ? 1 : 0);
}

void wifi_export_csv_client(const client_entry_t *c, char *out, size_t cap)
{
    char mac[18], bssid[18], h[WIFI_DB_RSSI_HIST * 5];
    wifi_mac_str(c->mac, mac);
    wifi_mac_str(c->bssid, bssid);
    hist_join(c, '|', h, sizeof(h));
    snprintf(out, cap, "CLIENT,%s,%s,%d,%u,%s,\"%s\"",
             mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor,
             h[0] ? h : "-");
}

void wifi_export_csv_eapol(const eapol_entry_t *e, char *out, size_t cap)
{
    char src[18], dst[18];
    wifi_mac_str(e->src, src);
    wifi_mac_str(e->dst, dst);
    snprintf(out, cap, "EAPOL,%s,%s,%d,%d", src, dst, e->eapol_type, e->handshake_step);
}

void wifi_export_json_ap(const ap_entry_t *e, char *out, size_t cap)
{
    char bssid[18], akm[32];
    ap_caps_t cc;
    wifi_mac_str(e->bssid, bssid);
    wifi_caps_from_entry(e, &cc);
    caps_akm_str(&cc, akm, sizeof(akm));

    snprintf(out, cap,
             "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%d,\"rssi\":%d,"
             "\"encryption\":\"%s\",\"hidden\":%s,\"pmf\":%d,"
             "\"beacons\":%u,\"data\":%u,\"vendor\":\"%s\","
             "\"akm\":\"%s\",\"cipher\":\"%s\",\"bw\":%u,\"std\":\"%s\","
             "\"wps\":%s,\"pmf_cap\":%s,\"crackable\":%s}",
             bssid, e->ssid, e->channel, e->rssi,
             wifi_enc_str(e->encryption), e->hidden ? "true" : "false",
             e->pmf ? 1 : 0, (unsigned)e->beacon_count, (unsigned)e->data_count,
             e->vendor, akm, wifi_cipher_str(e->cipher), (unsigned)e->bw,
             caps_std_str(&cc), e->wps ? "true" : "false",
             e->pmf_cap ? "true" : "false", e->crackable ? "true" : "false");
}

void wifi_export_json_client(const client_entry_t *c, char *out, size_t cap)
{
    char mac[18], bssid[18], h[WIFI_DB_RSSI_HIST * 5];
    wifi_mac_str(c->mac, mac);
    wifi_mac_str(c->bssid, bssid);
    hist_join(c, ',', h, sizeof(h));
    snprintf(out, cap,
             "{\"mac\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"pkts\":%u,"
             "\"vendor\":\"%s\",\"rssi_hist\":[%s]}",
             mac, bssid, c->rssi, (unsigned)c->pkt_count, c->vendor, h);
}

void wifi_export_json_eapol(const eapol_entry_t *e, char *out, size_t cap)
{
    char src[18], dst[18];
    wifi_mac_str(e->src, src);
    wifi_mac_str(e->dst, dst);
    snprintf(out, cap, "{\"src\":\"%s\",\"dst\":\"%s\",\"type\":%d,\"step\":%d}",
             src, dst, e->eapol_type, e->handshake_step);
}
