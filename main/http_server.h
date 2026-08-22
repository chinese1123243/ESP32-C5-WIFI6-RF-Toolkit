/*
 * http_server.h — HTTP REST API + SoftAP 接入点
 *
 * 远程控制接口 (JSON):
 *   GET  /api/status            -> {state, channel, auto_ch, sniff_total, inject_total, aps, clients, eapols}
 *   GET  /api/db/aps            -> [{bssid, ssid, channel, rssi, encryption, hidden, pmf, vendor, ...}, ...]
 *   GET  /api/db/clients        -> [{mac, bssid, rssi, pkt_count, vendor}, ...]
 *   GET  /api/db/eapols         -> [{src, dst, eapol_type, handshake_step, tick}, ...]
 *   POST /api/sniff/start       -> {"channel":6, "count":0}
 *   POST /api/sniff/auto        -> {"dwell_ms":1000}
 *   POST /api/deauth/start      -> {"bssid":"aa:bb:..","station":"cc:dd:..","count":0,"reason":7,"interval_ms":0}
 *   POST /api/beaconflood/start -> {"prefix":"TESTAP","count":0,"interval_ms":0}
 *   POST /api/probeflood/start  -> {"count":0,"interval_ms":0}
 *   POST /api/stop              -> {}
 *   GET  /                      -> 简易 HTML 控制面板
 *
 * SoftAP 默认:
 *   SSID: rftool-<chipid>  密码: rftool1234  IP: 192.168.71.1
 *   CLI 命令: http start [ssid] [pass]  /  http stop  /  http status
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 启动 SoftAP + HTTP server. ssid=NULL 用默认 "rftool-XXXX". pass=NULL 默认 "rftool1234".
 * 端口 TCP 80. */
esp_err_t http_server_start(const char *ssid, const char *pass);

/* 停止 HTTP server + 关闭 SoftAP. */
esp_err_t http_server_stop(void);

/* 是否已运行. */
bool http_server_is_running(void);

/* 打印运行状态 (IP / SSID / 连接数). */
void http_server_status(void);

#ifdef __cplusplus
}
#endif
