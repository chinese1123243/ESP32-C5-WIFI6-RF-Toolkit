/*
 * ota.h: 双区 OTA 升级
 *
 * 分区表已改为 ota_0 / ota_1 + otadata, 因此支持:
 *   - 从 HTTP 上传 .bin (手机 App 走 SoftAP, 最实用的一条路)
 *   - 从 URL 拉取 (需要设备能出网, 预留给 STA 场景)
 *   - 启动自检窗口 + 失败自动回滚 (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE)
 *
 * 安全约束:
 *   - 上传/下载都走 esp_ota_end(), 由 IDF 校验镜像 magic / checksum / 段完整性,
 *     损坏或被截断的固件不会被写成可启动镜像.
 *   - 上传路径额外支持 SHA-256 固定值校验 (App 侧传 ?sha256=xxx), 防止
 *     在半开信道里被替换成别的固件.
 *   - HTTP 上传端点必须带 api_token, 见 http_server.c.
 */
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 上电调用: 若当前分区处于 PENDING_VERIFY, 启动 45s 自检窗口,
 * 窗口内未崩溃则自动标记为有效 (取消回滚). */
esp_err_t ota_init(void);

/* META,OTA,STATUS,... : 运行分区 / 下次启动分区 / 镜像状态 / 版本 / 回滚开关 */
void ota_status(void);

/* 标记当前镜像有效 (取消回滚). 返回 0 成功. */
int ota_confirm(void);

/* 回滚到另一个 OTA 分区并重启. 仅在另一分区有可用镜像时生效. */
int ota_rollback(void);

/* 从 URL 拉取固件 (http/https). 成功后设置启动分区, 不自动重启. */
int ota_url(const char *url);

/* HTTP 上传通道 (http_server.c 调用) */
esp_err_t ota_upload_begin(size_t total_len, const char *sha256_hex);
esp_err_t ota_upload_write(const void *data, size_t len);
esp_err_t ota_upload_end(bool commit);
size_t    ota_upload_written(void);
bool      ota_upload_busy(void);
const char *ota_last_error(void);

#ifdef __cplusplus
}
#endif
