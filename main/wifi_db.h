/*
 * wifi_db.h - Wi-Fi sniff database (AP / Client / EAPOL tracking)
 *
 * Uses PSRAM for fixed-capacity hash tables, updated in promiscuous callback.
 * Supports export csv/json for host-side processing.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_DB_MAX_APS     256
#define WIFI_DB_MAX_CLIENTS 256
#define WIFI_DB_MAX_EAPOLS  32

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  encryption;
    bool     hidden;
    bool     pmf;
    uint32_t beacon_count;
    uint32_t data_count;
    uint32_t last_seen_tick;
    char     vendor[16];
} ap_entry_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint32_t pkt_count;
    uint32_t last_seen_tick;
    char     vendor[16];
} client_entry_t;

typedef struct {
    uint8_t  src[6];
    uint8_t  dst[6];
    uint8_t  eapol_type;
    uint8_t  handshake_step;
    uint32_t tick;
} eapol_entry_t;

const char *enc_str(uint8_t enc);

esp_err_t wifi_db_init(void);
void wifi_db_clear(void);

void wifi_db_update_ap(const uint8_t *frame, int len, uint8_t channel, int8_t rssi);
void wifi_db_update_client(const uint8_t *frame, int len, int8_t rssi);
bool wifi_db_check_eapol(const uint8_t *frame, int len, int8_t rssi);

void wifi_db_dump_aps(void);
void wifi_db_dump_clients(void);
void wifi_db_dump_eapols(void);
void wifi_db_export_csv(void);
void wifi_db_export_json(void);

int wifi_db_ap_count(void);
int wifi_db_client_count(void);
int wifi_db_eapol_count(void);

const char *oui_lookup(const uint8_t mac[3]);

/* 只读遍历 (HTTP 导出用, 返回内部指针, 调用期间请勿修改 DB). */
const ap_entry_t     *wifi_db_get_aps(int *out_cnt);
const client_entry_t *wifi_db_get_clients(int *out_cnt);
const eapol_entry_t  *wifi_db_get_eapols(int *out_cnt);

#ifdef __cplusplus
}
#endif