/*
 * logring.h: 日志环形缓冲
 *
 * 始终捕获 stdout/stderr 的最近 N 字节 (默认 16KB), 掉电丢失 (内存).
 * 供 'log dump' 命令和 HTTP /api/log 接口读取, 方便事后排障.
 *
 * 接入: ble_cli.c 的 __wrap__write_r 在每次写 fd=1/2 时调用 logring_push().
 */
#pragma once

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 推入一段日志 (线程安全). data 不需要以 \0 结尾. */
void logring_push(const char *data, size_t len);

/* 把全部缓冲内容写到 out (如 stdout). 返回写入字节数. */
int logring_dump(FILE *out);

/* 清空缓冲. */
void logring_clear(void);

/* 缓冲中当前有效字节数. */
size_t logring_used(void);

#ifdef __cplusplus
}
#endif
