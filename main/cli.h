/*
 * cli.h: 极简 fgets+dispatch REPL
 *
 * 命令 (用 argtable3 解析, '<cmd> --help' 查看详细选项):
 *   help                                 命令列表
 *   status                               显示当前状态与计数
 *   sniff <channel> [--count=<n>]        启动 promiscuous 嗅探 (count=0 永续)
 *   stop                                 停止当前嗅探/注入
 *   deauth -b <bssid> [-s <station>] [opts]
 *   beaconflood -p <prefix> [opts]
 *   probeflood [opts]
 *
 * cli_start() 在调用者任务中直接跑 REPL 循环 (不创建额外任务, 阻塞不返回).
 * 调用前 wifi_attack_init / rgb_led_init 已就绪.
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 启动 REPL 主循环 (阻塞不返回) */
esp_err_t cli_start(void);

/* 执行一行命令 (供 BLE / HTTP 等外部通道调用).
 * line 会被修改 (split_args 加 \0), 调用方传入可写缓冲区.
 * 返回 0 = 成功, 非 0 = 失败. */
int cli_exec_line(char *line);

/* 当前这条命令是否带 --json. 每条命令入口会重置, 所以只能在命令执行期间读.
 * 给拆出去的命令实现 (如 health.c) 用, 免得它们自己再解析一遍参数. */
bool cli_json_mode(void);

#ifdef __cplusplus
}
#endif
