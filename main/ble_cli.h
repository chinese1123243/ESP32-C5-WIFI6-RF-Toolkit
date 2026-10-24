/*
 * ble_cli.h: BLE GATT 服务: 手机直连收发 CLI 命令
 *
 * 设计:
 *   - 暴露 1 个 GATT service, 含 2 个 characteristic:
 *       RX_CHAR (write):  手机写入 CLI 命令 (单行, 以 \n 结尾)
 *       TX_CHAR (notify): 设备返回命令输出 (分帧通知)
 *   - 手机写入命令后, BLE 任务调用 cli_exec_line 执行
 *   - 执行期间 stdout 被捕获到环形缓冲, 执行完后通过 notify 回传
 *   - 不依赖开发板 HTTP 服务器, 纯 BLE 通道
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 启动 BLE GATT 服务 (非阻塞, 创建内部任务).
 * 调用前 wifi_attack_init 已就绪 (cli_exec_line 可用). */
esp_err_t ble_cli_start(void);

/* 停止 BLE 服务. */
esp_err_t ble_cli_stop(void);

/* 异步事件推送: 把一行文本 (自动补 \n) 经 NUS DATA 帧发给手机.
 * 供命令执行之外的模块使用 (门户凭据命中 / EAPOL 命中 / 作业进度).
 * 非阻塞: 内部只拷进队列, 队列满时丢弃最旧一条. 未连接时静默丢弃. */
bool ble_event_post(const char *line);

/* 二进制分片回传: payload = [offset:4 LE][bytes].
 * 用于原始帧落盘的分段拉取, 手机侧按 offset 拼回完整 pcap. */
void ble_send_chunk(uint32_t off, const uint8_t *data, int len);

/* NUS 广播挂起/恢复 (供 bleadv 伪造广播使用)
 * 挂起只停止广播, 不影响已建立的 GATT 连接 (App 仍可收发命令).
 * 恢复时重设 NUS fields 并重新启动可连接广播.
 * 返回 0 成功, 非 0 为 NimBLE 错误码. */
int  ble_cli_adv_suspend(void);
int  ble_cli_adv_resume(void);
/* 首选 ATT MTU. 取 sdkconfig 的 CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU (256);
 * 上层 MSYS_2 的块是 320 字节, 刚好一帧装得下, 不用跨块拼接. */
#ifdef CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU
#define RFTOOL_ATT_MTU CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU
#else
#define RFTOOL_ATT_MTU 256
#endif

bool ble_cli_adv_is_suspended(void);

/* 链路状态: MTU 与连接句柄, 供 status 输出与 App 显示协商结果. */
uint16_t ble_cli_mtu(void);
uint8_t  ble_cli_phy(void);
bool     ble_cli_connected(void);

#ifdef __cplusplus
}
#endif
