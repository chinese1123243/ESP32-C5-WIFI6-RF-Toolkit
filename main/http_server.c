/*
 * http_server.c — HTTP REST API 远程控制 + SoftAP 接入点实现
 *
 * 设计要点:
 *   1. 模式切换: 启动时 STA -> APSTA (保持 STA 能嗅探/注入, 同时 AP 给人连)
 *   2. SoftAP 默认 192.168.71.1, DHCP 192.168.71.2 ~ 192.168.71.10
 *   3. HTTP server (httpd) 监听 *:80, 所有 URI 注册为 GET/POST
 *   4. POST body 解析使用极简 JSON parser (无外部依赖), 只解析字符串/整数
 *   5. 响应格式统一为 JSON {"ok":true, ...} / {"ok":false,"err":"msg"}
 */
#include "http_server.h"
#include "wifi_attack.h"
#include "wifi_db.h"
#include "radio_common.h"
#include "rgb_led.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_event.h"
#include "lwip/err.h"
#include "lwip/sys.h"

static const char *TAG = "HTTP";

/* ======== 状态 ======== */
static httpd_handle_t s_server = NULL;
static esp_netif_t   *s_ap_netif = NULL;
static bool           s_running = false;
static char           s_ssid[33] = {0};
static uint16_t       s_sta_num = 0;

/* ======== SoftAP 事件回调 ======== */
static void ap_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)event_data;
        s_sta_num++;
        rgb_led_event(RGB_EV_STA_JOIN, 0);
        ESP_LOGI(TAG, "station join: AID=%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x, total=%d",
                 e->aid, e->mac[0],e->mac[1],e->mac[2],e->mac[3],e->mac[4],e->mac[5], s_sta_num);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = (wifi_event_ap_stadisconnected_t *)event_data;
        if (s_sta_num > 0) s_sta_num--;
        ESP_LOGI(TAG, "station leave: AID=%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x, total=%d",
                 e->aid, e->mac[0],e->mac[1],e->mac[2],e->mac[3],e->mac[4],e->mac[5], s_sta_num);
    }
}

/* ======== JSON 辅助 ======== */
static void send_json(httpd_req_t *r, const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    httpd_resp_send(r, buf, HTTPD_RESP_USE_STRLEN);
}

static void send_ok(httpd_req_t *r, const char *extra_json)
{
    if (extra_json && *extra_json) {
        send_json(r, "{\"ok\":true,%s}", extra_json);
    } else {
        send_json(r, "{\"ok\":true}");
    }
}

static void send_err(httpd_req_t *r, const char *msg)
{
    send_json(r, "{\"ok\":false,\"err\":\"%s\"}", msg);
}

/* 极简 JSON 取值: 在 body 中查 "key":value, 返回字符串指针 (需后续解析) */
static const char *json_find(const char *body, const char *key)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != ':') return NULL;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static bool json_get_str(const char *body, const char *key, char *dst, int dst_cap)
{
    const char *p = json_find(body, key);
    if (!p || *p != '"') return false;
    p++;
    int n = 0;
    while (*p && *p != '"' && n < dst_cap - 1) {
        if (*p == '\\' && p[1]) { p++; }
        dst[n++] = *p++;
    }
    dst[n] = '\0';
    return n > 0 || *p == '"';
}

static bool json_get_int(const char *body, const char *key, int *out)
{
    const char *p = json_find(body, key);
    if (!p) return false;
    if (!isdigit((unsigned char)*p) && *p != '-') return false;
    char *endp;
    long v = strtol(p, &endp, 10);
    if (endp == p) return false;
    *out = (int)v;
    return true;
}

static char *read_body(httpd_req_t *r)
{
    int total = r->content_len;
    if (total <= 0 || total > 4096) total = 4096;
    char *buf = calloc(1, total + 1);
    if (!buf) return NULL;
    int got = 0;
    while (got < total) {
        int n = httpd_req_recv(r, buf + got, total - got);
        if (n <= 0) break;
        got += n;
    }
    buf[got] = '\0';
    return buf;
}


/* ======== REST Handlers ======== */

static esp_err_t h_root_get(httpd_req_t *r)
{
    httpd_resp_set_type(r, "text/html; charset=ascii");
    httpd_resp_sendstr_chunk(r,
        "<!DOCTYPE html><html><head><meta charset='ascii'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,user-scalable=yes'>"
        "<title>rftool</title><style>"
        "*{box-sizing:border-box}"
        "body{font-family:monospace;max-width:680px;margin:0 auto;padding:6px;"
        "color:#111;background:#fff;-webkit-overflow-scrolling:touch}"
        "h1{font-size:1.2em;margin:4px 0;border-bottom:2px solid #000;padding-bottom:2px}"
        "button{padding:8px 14px;margin:3px 1px;background:#000;color:#fff;border:1px solid #000;"
        "border-radius:3px;cursor:pointer;font-size:13px;font-family:monospace;"
        "min-height:34px;touch-action:manipulation}"
        "button:active{background:#fff;color:#000}"
        "input{padding:5px;margin:1px;border:1px solid #999;border-radius:3px;font-size:13px;font-family:monospace}"
        "label{display:inline-block;margin:2px 3px;font-size:12px}"
        ".sec{margin:6px 0;padding:8px;border:1px solid #ccc;border-radius:4px}"
        ".sec b{font-size:13px}"
        "#st{background:#f5f5f5;padding:6px;border-radius:3px;font-size:11px;"
        "white-space:pre-wrap;word-break:break-all;margin:4px 0}"
        "table{border-collapse:collapse;width:100%;margin:4px 0}"
        "th,td{border:1px solid #ccc;padding:3px 5px;text-align:left;font-size:11px}"
        "th{background:#000;color:#fff}"
        "tr:nth-child(even){background:#f9f9f9}"
        "#msg{color:#000;font-weight:bold;min-height:18px}"
        "</style></head><body>"
        "<h1>ESP32-C5 rftool</h1>"
        "<div id='st'>loading...</div>"
        "<div id='msg'></div>"
        "<div class='sec'><b>Sniff</b><br>"
        "<label>ch<input id='ch' type='number' min='1' max='14' value='6' style='width:36px'></label>"
        "<label>n<input id='cnt' type='number' min='0' value='0' style='width:44px'></label>"
        "<button onclick='doSniff()'>Sniff</button> "
        "<label>dwell<input id='dwell' type='number' min='100' value='1000' style='width:50px'></label>"
        "<button onclick='doSniffAuto()'>Auto</button> "
        "<button onclick='doStop()'>STOP</button>"
        "</div>"
        "<div class='sec'><b>Deauth</b> (auth only)<br>"
        "<label>BSSID<input id='bssid' placeholder='aa:bb:cc:dd:ee:ff' style='width:130px'></label>"
        "<label>STA<input id='sta' placeholder='empty=bcast' style='width:110px'></label><br>"
        "<label>n<input id='dcnt' type='number' min='0' value='20' style='width:44px'></label>"
        "<label>ms<input id='dint' type='number' min='0' value='0' style='width:44px'></label>"
        "<button onclick='doDeauth()'>Start</button>"
        "</div>"
        "<div class='sec'><b>Flood</b> (auth only)<br>"
        "<label>prefix<input id='prefix' value='FREE-WIFI-' style='width:90px'></label>"
        "<label>n<input id='bcnt' type='number' min='0' value='100' style='width:44px'></label>"
        "<button onclick='doBeacon()'>Beacon</button> "
        "<label>n<input id='pcnt' type='number' min='0' value='200' style='width:44px'></label>"
        "<button onclick='doProbe()'>Probe</button> "
        "<button onclick='doStop()'>STOP</button>"
        "</div>"
        "<div class='sec'><b>Database</b> <button onclick='loadAll()'>Refresh</button>"
        "<div id='aps'></div><div id='cls'></div></div>"
        "<div class='sec'><b>Export</b> "
        "<a href='/api/export/json' target='_blank'><button type='button'>JSON</button></a>"
        "<a href='/api/export/csv' target='_blank'><button type='button'>CSV</button></a>"
        "</div>");
    httpd_resp_sendstr_chunk(r,
        "<script>"
        "function $(i){return document.getElementById(i)}"
        "function val(i){return $(i).value}"
        "function num(i,d){var v=parseInt(val(i));return isNaN(v)?d:v}"
        "function msg(s){$('msg').textContent=s;setTimeout(function(){$('msg').textContent=''},3000)}"
        "async function api(u,b){"
        "var o={headers:{'Content-Type':'application/json'}};"
        "if(b){o.method='POST';o.body=JSON.stringify(b)}"
        "try{var r=await fetch(u,o);var j=await r.json();"
        "if(!j.ok){msg('ERR: '+(j.err||'unknown'))}else{msg('OK')}"
        "return j}catch(e){msg('NET ERR: '+e);return null}}"
        "async function refresh(){"
        "try{var s=await(await fetch('/api/status')).json();"
        "$('st').textContent=JSON.stringify(s,null,1)}catch(e){}}"
        "async function loadAll(){await refresh();"
        "try{var d=await(await fetch('/api/export/json')).json();"
        "var h='<table><tr><th>BSSID</th><th>SSID</th><th>Ch</th><th>RSSI</th><th>Enc</th><th>Vendor</th></tr>';"
        "if(d.aps&&d.aps.length)for(var i=0;i<d.aps.length;i++){var a=d.aps[i];"
        "h+='<tr><td>'+a.bssid+'</td><td>'+a.ssid+'</td><td>'+a.channel+'</td><td>'+a.rssi+'</td><td>'+a.encryption+'</td><td>'+a.vendor+'</td></tr>'}"
        "else{h+='<tr><td colspan=6>(empty)</td></tr>'}"
        "h+='</table>';$('aps').innerHTML=h;"
        "h='<table><tr><th>MAC</th><th>BSSID</th><th>RSSI</th><th>Pkts</th><th>Vendor</th></tr>';"
        "if(d.clients&&d.clients.length)for(var i=0;i<d.clients.length;i++){var c=d.clients[i];"
        "h+='<tr><td>'+c.mac+'</td><td>'+c.bssid+'</td><td>'+c.rssi+'</td><td>'+c.pkt_count+'</td><td>'+c.vendor+'</td></tr>'}"
        "else{h+='<tr><td colspan=5>(empty)</td></tr>'}"
        "h+='</table>';$('cls').innerHTML=h}"
        "catch(e){$('aps').textContent='load err: '+e}}"
        "function doSniff(){api('/api/sniff/start',{channel:num('ch',6),count:num('cnt',0)}).then(refresh)}"
        "function doSniffAuto(){api('/api/sniff/auto',{dwell_ms:num('dwell',1000)}).then(refresh)}"
        "function doStop(){api('/api/stop',{}).then(refresh)}"
        "function doDeauth(){api('/api/deauth/start',{bssid:val('bssid'),station:val('sta'),count:num('dcnt',20),interval_ms:num('dint',0),reason:7}).then(refresh)}"
        "function doBeacon(){api('/api/beaconflood/start',{prefix:val('prefix'),count:num('bcnt',100),interval_ms:0}).then(refresh)}"
        "function doProbe(){api('/api/probeflood/start',{count:num('pcnt',200),interval_ms:0}).then(refresh)}"
        "setInterval(refresh,3000);refresh();loadAll();"
        "</script></body></html>");
    httpd_resp_sendstr_chunk(r, NULL);
    return ESP_OK;
}

/* GET /api/status */
static esp_err_t h_status_get(httpd_req_t *r)
{
    int ap_cnt = wifi_db_ap_count();
    int cl_cnt = wifi_db_client_count();
    int ep_cnt = wifi_db_eapol_count();
    int st_raw = wifi_atk_state_val();
    const char *stname = (st_raw == 1) ? "SNIFF" : (st_raw == 2 ? "INJECT" : "IDLE");
    unsigned ch   = (unsigned)wifi_atk_channel();
    unsigned auto_ch = wifi_atk_auto_ch() ? 1u : 0u;
    unsigned sniff_t = (unsigned)wifi_atk_sniff_total();
    unsigned inj_t   = (unsigned)wifi_atk_inject_total();
    send_json(r,
        "{\"ok\":true,\"state\":\"%s\",\"channel\":%u,\"auto_ch\":%u,"
        "\"sniff_total\":%u,\"inject_total\":%u,\"aps\":%d,\"clients\":%d,\"eapols\":%d,"
        "\"http\":{\"ssid\":\"%s\",\"sta\":%u}}",
        stname, ch, auto_ch, sniff_t, inj_t,
        ap_cnt, cl_cnt, ep_cnt,
        s_ssid, (unsigned)s_sta_num);
    return ESP_OK;
}


/* POST /api/sniff/start */
static esp_err_t h_sniff_start_post(httpd_req_t *r)
{
    char *body = read_body(r);
    if (!body) { send_err(r, "oom"); return ESP_OK; }
    int ch = 0, cnt = 0;
    bool ok1 = json_get_int(body, "channel", &ch);
    json_get_int(body, "count", &cnt);
    free(body);
    if (!ok1 || ch < 1 || ch > 14) { send_err(r, "bad_channel (1-14)"); return ESP_OK; }
    esp_err_t e = wifi_attack_sniff_start((uint8_t)ch, (uint32_t)(cnt < 0 ? 0 : cnt));
    if (e != ESP_OK) { send_err(r, "sniff_start_failed"); } else { send_ok(r, NULL); }
    return ESP_OK;
}

/* POST /api/sniff/auto */
static esp_err_t h_sniff_auto_post(httpd_req_t *r)
{
    char *body = read_body(r);
    if (!body) { send_err(r, "oom"); return ESP_OK; }
    int dwell = 1000;
    json_get_int(body, "dwell_ms", &dwell);
    free(body);
    if (dwell < 100) dwell = 100;
    esp_err_t e = wifi_attack_sniff_auto_start((uint32_t)dwell);
    if (e != ESP_OK) { send_err(r, "sniff_auto_start_failed"); } else { send_ok(r, NULL); }
    return ESP_OK;
}

/* POST /api/stop */
static esp_err_t h_stop_post(httpd_req_t *r)
{
    (void)r;
    esp_err_t e1 = wifi_attack_inject_stop();
    esp_err_t e2 = wifi_attack_sniff_stop();
    if (e1 != ESP_OK && e2 != ESP_OK) { send_err(r, "nothing_running"); } else { send_ok(r, NULL); }
    return ESP_OK;
}

/* POST /api/deauth/start */
static esp_err_t h_deauth_start_post(httpd_req_t *r)
{
    char *body = read_body(r);
    if (!body) { send_err(r, "oom"); return ESP_OK; }
    char bssid[64] = {0}, sta[64] = {0};
    int count = 0, reason = 7, interval = 0;
    bool ok = json_get_str(body, "bssid", bssid, sizeof(bssid));
    json_get_str(body, "station", sta, sizeof(sta));
    json_get_int(body, "count", &count);
    json_get_int(body, "reason", &reason);
    json_get_int(body, "interval_ms", &interval);
    free(body);
    if (!ok) { send_err(r, "missing_bssid"); return ESP_OK; }
    uint8_t b[6], s[6] = {0};
    if (!parse_mac(bssid, b)) { send_err(r, "bad_bssid"); return ESP_OK; }
    if (sta[0] && !parse_mac(sta, s)) { send_err(r, "bad_station"); return ESP_OK; }
    esp_err_t e = wifi_attack_deauth_start(b, s,
        count < 0 ? 0 : (uint32_t)count,
        (uint16_t)(reason < 0 ? 7 : reason),
        interval < 0 ? 0 : (uint32_t)interval);
    if (e != ESP_OK) { send_err(r, "deauth_start_failed"); } else { send_ok(r, NULL); }
    return ESP_OK;
}

/* POST /api/beaconflood/start */
static esp_err_t h_beacon_start_post(httpd_req_t *r)
{
    char *body = read_body(r);
    if (!body) { send_err(r, "oom"); return ESP_OK; }
    char prefix[128] = {0};
    int count = 0, interval = 0;
    bool ok = json_get_str(body, "prefix", prefix, sizeof(prefix));
    json_get_int(body, "count", &count);
    json_get_int(body, "interval_ms", &interval);
    free(body);
    if (!ok || !prefix[0]) { send_err(r, "missing_prefix"); return ESP_OK; }
    esp_err_t e = wifi_attack_beacon_flood_start(prefix,
        count < 0 ? 0 : (uint32_t)count,
        interval < 0 ? 0 : (uint32_t)interval);
    if (e != ESP_OK) { send_err(r, "beacon_start_failed"); } else { send_ok(r, NULL); }
    return ESP_OK;
}

/* POST /api/probeflood/start */
static esp_err_t h_probe_start_post(httpd_req_t *r)
{
    char *body = read_body(r);
    if (!body) { send_err(r, "oom"); return ESP_OK; }
    int count = 0, interval = 0;
    json_get_int(body, "count", &count);
    json_get_int(body, "interval_ms", &interval);
    free(body);
    esp_err_t e = wifi_attack_probe_flood_start(
        count < 0 ? 0 : (uint32_t)count,
        interval < 0 ? 0 : (uint32_t)interval);
    if (e != ESP_OK) { send_err(r, "probe_start_failed"); } else { send_ok(r, NULL); }
    return ESP_OK;
}


/* ======== DB export handlers ======== */

/* GET /api/db/aps */
static esp_err_t h_db_aps_get(httpd_req_t *r)
{
    /* 直接调用 wifi_db 的内部结构太复杂, 这里重写一个 JSON 流式输出到临时缓冲区.
     * 由于单连接阻塞模型, 直接用 httpd_resp_sendstr_chunk 分段发送. */
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    char buf[1024];
    /* 为了简洁, 我们通过 "临时禁用 stdout 捕获 wifi_db_export_json 输出" 方法太麻烦.
     * 改为: 让 wifi_db 提供一个额外的 JSON 数组 getter 接口不现实.
     * 所以这里用一个更简单但受限的方法: 从 wifi_db 公共 API 只能取 count, 不能遍历.
     * -> 我们在 wifi_db.h 增加 extern getter (见底部注释). 由于当前没暴露, 这里只输出 count.
     *   用户可通过 /api/export/json 获取完整数据 (会打到串口, 用户侧用 monitor.py 捕获). */
    int n = wifi_db_ap_count();
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"count\":%d,\"note\":\"use /api/export/json for full data\"}", n);
    httpd_resp_send(r, buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t h_db_clients_get(httpd_req_t *r)
{
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    char buf[256];
    int n = wifi_db_client_count();
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"count\":%d,\"note\":\"use /api/export/json for full data\"}", n);
    httpd_resp_send(r, buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t h_db_eapols_get(httpd_req_t *r)
{
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    char buf[256];
    int n = wifi_db_eapol_count();
    snprintf(buf, sizeof(buf), "{\"ok\":true,\"count\":%d,\"note\":\"use /api/export/json for full data\"}", n);
    httpd_resp_send(r, buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* GET /api/export/json — 直接把 wifi_db_export_json 的 stdout 捕获到 HTTP 响应 */
static esp_err_t h_export_json(httpd_req_t *r)
{
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    /* 不幸的是 wifi_db_export_json() 直接 printf 到串口, 所以我们重写一遍.
     * 这避免了修改 wifi_db. 代码虽重复但简洁安全. */
    extern const ap_entry_t     *wifi_db_get_aps(int *out_cnt);
    extern const client_entry_t *wifi_db_get_clients(int *out_cnt);
    extern const eapol_entry_t  *wifi_db_get_eapols(int *out_cnt);

    int ap_cnt = 0, cl_cnt = 0, ep_cnt = 0;
    const ap_entry_t     *aps = wifi_db_get_aps(&ap_cnt);
    const client_entry_t *cls = wifi_db_get_clients(&cl_cnt);
    const eapol_entry_t  *eps = wifi_db_get_eapols(&ep_cnt);

    char chunk[1536];
    int pos = 0;
    /* 头部 */
    pos = snprintf(chunk, sizeof(chunk), "{\"ok\":true,\"aps\":[");
    httpd_resp_send_chunk(r, chunk, pos);

    char macbuf[18];
    for (int i = 0; i < ap_cnt; i++) {
        const ap_entry_t *e = &aps[i];
        pos = snprintf(chunk, sizeof(chunk),
            "%s{\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%u,\"rssi\":%d,"
            "\"encryption\":\"%s\",\"hidden\":%s,\"pmf\":%d,\"beacon_count\":%u,"
            "\"data_count\":%u,\"vendor\":\"%s\"}",
            i ? "," : "",
            mac_to_str(e->bssid, macbuf), e->ssid, (unsigned)e->channel, (int)e->rssi,
            enc_str(e->encryption), e->hidden ? "true" : "false", e->pmf ? 1 : 0,
            (unsigned)e->beacon_count, (unsigned)e->data_count, e->vendor);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    pos = snprintf(chunk, sizeof(chunk), "],\"clients\":[");
    httpd_resp_send_chunk(r, chunk, pos);
    for (int i = 0; i < cl_cnt; i++) {
        const client_entry_t *e = &cls[i];
        pos = snprintf(chunk, sizeof(chunk),
            "%s{\"mac\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"pkt_count\":%u,\"vendor\":\"%s\"}",
            i ? "," : "",
            mac_to_str(e->mac, macbuf), mac_to_str(e->bssid, macbuf),
            (int)e->rssi, (unsigned)e->pkt_count, e->vendor);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    pos = snprintf(chunk, sizeof(chunk), "],\"eapols\":[");
    httpd_resp_send_chunk(r, chunk, pos);
    for (int i = 0; i < ep_cnt; i++) {
        const eapol_entry_t *e = &eps[i];
        pos = snprintf(chunk, sizeof(chunk),
            "%s{\"src\":\"%s\",\"dst\":\"%s\",\"eapol_type\":%u,\"handshake_step\":%u,\"tick\":%u}",
            i ? "," : "",
            mac_to_str(e->src, macbuf), mac_to_str(e->dst, macbuf),
            (unsigned)e->eapol_type, (unsigned)e->handshake_step, (unsigned)e->tick);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    pos = snprintf(chunk, sizeof(chunk), "]}");
    httpd_resp_send_chunk(r, chunk, pos);
    httpd_resp_send_chunk(r, NULL, 0);   /* 结束分块 */
    return ESP_OK;
}

/* GET /api/export/csv */
static esp_err_t h_export_csv(httpd_req_t *r)
{
    httpd_resp_set_type(r, "text/csv; charset=utf-8");
    httpd_resp_set_hdr(r, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(r, "Content-Disposition", "attachment; filename=rftool_export.csv");

    extern const ap_entry_t     *wifi_db_get_aps(int *out_cnt);
    extern const client_entry_t *wifi_db_get_clients(int *out_cnt);
    extern const eapol_entry_t  *wifi_db_get_eapols(int *out_cnt);
    int ap_cnt = 0, cl_cnt = 0, ep_cnt = 0;
    const ap_entry_t     *aps = wifi_db_get_aps(&ap_cnt);
    const client_entry_t *cls = wifi_db_get_clients(&cl_cnt);
    const eapol_entry_t  *eps = wifi_db_get_eapols(&ep_cnt);

    char chunk[1024];
    int pos;
    char m1[18], m2[18];
    pos = snprintf(chunk, sizeof(chunk),
        "type,bssid_or_mac,ssid,channel,rssi,encryption,hidden,pmf,beacon_count,data_count,vendor,pkt_count,eapol_type,handshake_step,tick\n");
    httpd_resp_send_chunk(r, chunk, pos);
    for (int i = 0; i < ap_cnt; i++) {
        const ap_entry_t *e = &aps[i];
        pos = snprintf(chunk, sizeof(chunk),
            "AP,%s,\"%s\",%u,%d,%s,%s,%d,%u,%u,%s,,,,\n",
            mac_to_str(e->bssid, m1), e->ssid, (unsigned)e->channel, (int)e->rssi,
            enc_str(e->encryption), e->hidden ? "yes" : "no", e->pmf ? 1 : 0,
            (unsigned)e->beacon_count, (unsigned)e->data_count, e->vendor);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    for (int i = 0; i < cl_cnt; i++) {
        const client_entry_t *e = &cls[i];
        pos = snprintf(chunk, sizeof(chunk),
            "CLIENT,%s,,,%d,,,,,,%s,%u,,,\n",
            mac_to_str(e->mac, m1), (int)e->rssi, e->vendor, (unsigned)e->pkt_count);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    for (int i = 0; i < ep_cnt; i++) {
        const eapol_entry_t *e = &eps[i];
        pos = snprintf(chunk, sizeof(chunk),
            "EAPOL,%s,,src=%s dst=%s,,,,,,,,,%u,%u,%u\n",
            mac_to_str(e->src, m1), mac_to_str(e->src, m1), mac_to_str(e->dst, m2),
            (unsigned)e->eapol_type, (unsigned)e->handshake_step, (unsigned)e->tick);
        httpd_resp_send_chunk(r, chunk, pos);
    }
    httpd_resp_send_chunk(r, NULL, 0);
    return ESP_OK;
}


/* ======== URI 注册 ======== */

static const httpd_uri_t s_uri_root =       { .uri = "/",                  .method = HTTP_GET,  .handler = h_root_get };
static const httpd_uri_t s_uri_status =     { .uri = "/api/status",        .method = HTTP_GET,  .handler = h_status_get };
static const httpd_uri_t s_uri_sniff =      { .uri = "/api/sniff/start",   .method = HTTP_POST, .handler = h_sniff_start_post };
static const httpd_uri_t s_uri_sniff_auto = { .uri = "/api/sniff/auto",    .method = HTTP_POST, .handler = h_sniff_auto_post };
static const httpd_uri_t s_uri_stop =       { .uri = "/api/stop",          .method = HTTP_POST, .handler = h_stop_post };
static const httpd_uri_t s_uri_deauth =     { .uri = "/api/deauth/start",  .method = HTTP_POST, .handler = h_deauth_start_post };
static const httpd_uri_t s_uri_beacon =     { .uri = "/api/beaconflood/start",.method= HTTP_POST, .handler = h_beacon_start_post };
static const httpd_uri_t s_uri_probe =      { .uri = "/api/probeflood/start", .method= HTTP_POST, .handler = h_probe_start_post };
static const httpd_uri_t s_uri_db_aps =     { .uri = "/api/db/aps",        .method = HTTP_GET,  .handler = h_db_aps_get };
static const httpd_uri_t s_uri_db_clients = { .uri = "/api/db/clients",    .method = HTTP_GET,  .handler = h_db_clients_get };
static const httpd_uri_t s_uri_db_eapols =  { .uri = "/api/db/eapols",     .method = HTTP_GET,  .handler = h_db_eapols_get };
static const httpd_uri_t s_uri_exp_json =   { .uri = "/api/export/json",   .method = HTTP_GET,  .handler = h_export_json };
static const httpd_uri_t s_uri_exp_csv  =   { .uri = "/api/export/csv",    .method = HTTP_GET,  .handler = h_export_csv };

static void register_all_uri(httpd_handle_t srv)
{
    httpd_register_uri_handler(srv, &s_uri_root);
    httpd_register_uri_handler(srv, &s_uri_status);
    httpd_register_uri_handler(srv, &s_uri_sniff);
    httpd_register_uri_handler(srv, &s_uri_sniff_auto);
    httpd_register_uri_handler(srv, &s_uri_stop);
    httpd_register_uri_handler(srv, &s_uri_deauth);
    httpd_register_uri_handler(srv, &s_uri_beacon);
    httpd_register_uri_handler(srv, &s_uri_probe);
    httpd_register_uri_handler(srv, &s_uri_db_aps);
    httpd_register_uri_handler(srv, &s_uri_db_clients);
    httpd_register_uri_handler(srv, &s_uri_db_eapols);
    httpd_register_uri_handler(srv, &s_uri_exp_json);
    httpd_register_uri_handler(srv, &s_uri_exp_csv);
}

/* ======== 公共 API ======== */

bool http_server_is_running(void) { return s_running; }

void http_server_status(void)
{
    if (!s_running) {
        printf("META,HTTP,STATUS,running,0\n");
        fflush(stdout);
        return;
    }
    esp_netif_ip_info_t ip;
    esp_netif_get_ip_info(s_ap_netif, &ip);
    char ipstr[16];
    snprintf(ipstr, sizeof(ipstr), IPSTR, IP2STR(&ip.ip));
    printf("META,HTTP,STATUS,running,1,ssid,%s,ip,%s,sta,%u\n",
           s_ssid, ipstr, (unsigned)s_sta_num);
    fflush(stdout);
}

esp_err_t http_server_start(const char *ssid, const char *pass)
{
    if (s_running) return ESP_ERR_INVALID_STATE;

    /* --- 1. 切换到 APSTA 模式 (保持 STA 以便嗅探/注入) --- */
    wifi_mode_t cur_mode;
    ESP_RETURN_ON_ERROR(esp_wifi_get_mode(&cur_mode), TAG, "get mode");
    if (cur_mode == WIFI_MODE_STA) {
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), TAG, "set APSTA");
    } else if (cur_mode != WIFI_MODE_AP && cur_mode != WIFI_MODE_APSTA) {
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_APSTA), TAG, "force APSTA");
    }

    /* --- 2. 创建 AP netif + 配置静态 IP 192.168.71.1 --- */
    if (!s_ap_netif) {
        esp_netif_inherent_config_t netif_cfg = ESP_NETIF_INHERENT_DEFAULT_WIFI_AP();
        s_ap_netif = esp_netif_create_wifi(WIFI_IF_AP, &netif_cfg);
        esp_netif_dhcps_stop(s_ap_netif);
        esp_netif_ip_info_t ip = {
            .ip =      { .addr = ESP_IP4TOADDR(192,168,71,1) },
            .gw =      { .addr = ESP_IP4TOADDR(192,168,71,1) },
            .netmask = { .addr = ESP_IP4TOADDR(255,255,255,0) },
        };
        esp_netif_set_ip_info(s_ap_netif, &ip);
        esp_netif_dhcps_start(s_ap_netif);

        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
            ESP_EVENT_ANY_ID, &ap_event_handler, NULL, NULL));
    }

    /* --- 3. 配置 SoftAP SSID/密码 --- */
    if (!ssid || !*ssid) {
        uint8_t mac[6];
        esp_wifi_get_mac(WIFI_IF_AP, mac);
        snprintf(s_ssid, sizeof(s_ssid), "rftool-%02X%02X%02X", mac[3], mac[4], mac[5]);
    } else {
        strncpy(s_ssid, ssid, sizeof(s_ssid) - 1);
    }
    const char *p = (pass && *pass) ? pass : "rftool1234";
    wifi_config_t apcfg = {0};
    {
        size_t n = strlen(s_ssid);
        if (n >= sizeof(apcfg.ap.ssid)) n = sizeof(apcfg.ap.ssid) - 1;
        memcpy(apcfg.ap.ssid, s_ssid, n);
        apcfg.ap.ssid[n] = 0;
    }
    apcfg.ap.ssid_len = strlen((const char *)apcfg.ap.ssid);
    {
        size_t n = strlen(p);
        if (n >= sizeof(apcfg.ap.password)) n = sizeof(apcfg.ap.password) - 1;
        memcpy(apcfg.ap.password, p, n);
        apcfg.ap.password[n] = 0;
    }
    apcfg.ap.channel = 6;
    apcfg.ap.max_connection = 4;
    apcfg.ap.authmode = (strlen(p) >= 8) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_AP, &apcfg), TAG, "set ap cfg");

    s_sta_num = 0;

    /* --- 4. 启动 HTTP server --- */
    httpd_config_t hcfg = HTTPD_DEFAULT_CONFIG();
    hcfg.server_port = 80;
    hcfg.max_open_sockets = 7;
    hcfg.lru_purge_enable = true;
    hcfg.stack_size = 6144;
    hcfg.max_uri_handlers = 16;

    ESP_RETURN_ON_ERROR(httpd_start(&s_server, &hcfg), TAG, "httpd_start fail");
    register_all_uri(s_server);

    s_running = true;
    if (rgb_led_get_status() == RGB_IDLE)
        rgb_led_set_status(RGB_HTTP_READY);
    else
        rgb_led_pulse(0, 60, 80, 0);

    esp_netif_ip_info_t ip;
    esp_netif_get_ip_info(s_ap_netif, &ip);
    ESP_LOGI(TAG, "HTTP OK: SSID='%s' pass='%s' IP=" IPSTR, s_ssid, p, IP2STR(&ip.ip));
    printf("META,HTTP,START,ok,1,ssid,%s,ip," IPSTR "\n", s_ssid, IP2STR(&ip.ip));
    fflush(stdout);
    return ESP_OK;
}

esp_err_t http_server_stop(void)
{
    if (!s_running) return ESP_ERR_INVALID_STATE;
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    /* 关闭 SoftAP, 切回纯 STA 模式 (还原嗅探/注入纯净环境) */
    esp_wifi_set_mode(WIFI_MODE_STA);
    s_running = false;
    s_sta_num = 0;
    s_ssid[0] = '\0';
    if (rgb_led_get_status() == RGB_HTTP_READY)
        rgb_led_set_status(RGB_IDLE);
    printf("META,HTTP,STOP,ok,1\n");
    fflush(stdout);
    return ESP_OK;
}
