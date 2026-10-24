/*
 * config.h: 配置持久化 (NVS 键值存储)
 *
 * 设计:
 *   - 所有配置项以字符串形式存在 NVS "rftool" 命名空间下
 *   - 运行时在内存中维护一份副本 (哈希表/线性表), 读写不阻塞 flash
 *   - set 时同时写 NVS (nvs_set_str 自动 commit), 掉电不丢
 *   - 提供 C API 供其他模块读取配置 (如 http_server 读 api_token)
 *
 * 命令:
 *   config set <key> <value>   设置配置项
 *   config get <key>           读取配置项
 *   config list                列出所有配置项
 *   config reset               清除所有配置项
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化: 从 NVS 加载已有配置到内存表.
 * 在 nvs_flash_init() 之后调用. */
esp_err_t config_init(void);

/* 读取配置项 (返回指向内部缓冲的指针, 无需释放).
 * key 不存在返回 NULL. */
const char *config_get(const char *key);

/* 设置配置项 (同时写 NVS). value 可为 NULL (删除该 key).
 * 返回 0 成功, 非 0 失败. */
int config_set(const char *key, const char *value);

/* 遍历所有配置项, 对每项调用 cb(key, value, ctx). */
typedef void (*config_iter_cb)(const char *key, const char *value, void *ctx);
void config_foreach(config_iter_cb cb, void *ctx);

/* 删除所有配置项. */
void config_reset(void);

#ifdef __cplusplus
}
#endif
