#include "wifi_names.h"

#include <string.h>

const char *wifi_enc_str(uint8_t enc)
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

const char *wifi_cipher_str(uint8_t mask)
{
    if (mask & CAP_CIPHER_GCMP) return "GCMP";
    if (mask & CAP_CIPHER_CCMP) return "CCMP";
    if (mask & CAP_CIPHER_TKIP) return "TKIP";
    return "-";
}

void wifi_caps_from_entry(const ap_entry_t *e, ap_caps_t *c)
{
    memset(c, 0, sizeof(*c));
    c->akm    = e->akm;
    c->cipher = e->cipher;
    c->ht = e->ht;
    c->vht = e->vht;
    c->he = e->he;
    c->bw  = e->bw;
    c->pmf = (e->pmf_cap ? CAP_PMF_CAPABLE : 0) | (e->pmf ? CAP_PMF_REQUIRED : 0);
}

int wifi_hist_start(uint8_t rssi_i, uint8_t rssi_n)
{
    if (rssi_n == 0) return 0;
    if (rssi_n > WIFI_DB_RSSI_HIST) rssi_n = WIFI_DB_RSSI_HIST;
    /* +2*HIST 是为了抵消 uint8 相减的下溢, 等价于取模后再归一 */
    int start = (int)(rssi_i - rssi_n + WIFI_DB_RSSI_HIST * 2) % WIFI_DB_RSSI_HIST;
    return start < 0 ? start + WIFI_DB_RSSI_HIST : start;
}
