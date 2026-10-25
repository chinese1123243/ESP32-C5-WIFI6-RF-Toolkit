/*
 * ble_adv.h: BLE 广播伪造 (iBeacon / Eddystone-URL)
 *
 * 设计: 单实例「挂起/恢复」方案.
 *   - 启动时调用 ble_cli_adv_suspend() 停掉 NUS 广播 (已建立的 GATT 连接不受影响,
 *     App 仍可收发命令), 然后设置伪造广播数据并启动非连接广播.
 *   - 停止 / 超时后调用 ble_cli_adv_resume() 恢复 NUS 广播.
 *
 * 命令格式 (App 侧):
 *   bleadv ibeacon  <uuid32hex> <major> <minor> [sec]
 *   bleadv eddystone <url> [sec]
 *   bleadv stop
 *   bleadv status
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BLEADV_NONE = 0,
    BLEADV_IBEACON,
    BLEADV_EDDYSTONE,
    BLEADV_FASTPAIR,
    BLEADV_SWIFTPAIR,
    BLEADV_CONTINUITY,
} bleadv_type_t;

/* 启动 iBeacon 广播.
 * uuid: 32 位十六进制字符串 (可带或不带短横线).
 * major/minor: 0-65535.
 * sec: 持续秒数, 0 = 无限 (直到 stop). */
int bleadv_ibeacon(const char *uuid, uint16_t major, uint16_t minor, int sec);

/* 启动 Eddystone-URL 广播.
 * url: 完整 URL (http(s)://...).
 * sec: 持续秒数, 0 = 无限. */
int bleadv_eddystone(const char *url, int sec);

/* 弹窗模板 (研究用途, 触发取决于目标设备系统与厂商反滥用机制):
 *   fastpair:   Google Fast Pair, Service Data 0xFE2C. model_id 3 字节, 须是
 *               Google 注册过的真实 ID 才可能弹, 0 = 占位不弹.
 *   swiftpair:  Microsoft SwiftPair, Manufacturer Data 0x0006.
 *   continuity: Apple Continuity 邻近配对, Manufacturer Data 0x004C type 0x07.
 *               载荷加密且 iOS 校验, 伪造帧绝大多数被静默丢弃.
 * sec: 持续秒数, 0 = 无限. */
int bleadv_fastpair(uint32_t model_id, int sec);
int bleadv_swiftpair(int sec);
int bleadv_continuity(int sec);

/* 停止当前伪造广播并恢复 NUS. */
int bleadv_stop(void);

/* 输出 META 状态行. */
void bleadv_status(void);

/* 是否已在运行. */
bool bleadv_is_active(void);

/* 当前类型. */
bleadv_type_t bleadv_get_type(void);

/* 剩余秒数 (0 = 无限或未运行). */
int bleadv_get_remain(void);

/* 初始化 (创建信号量等). 在 BLE 启动后调用一次. */
void bleadv_init(void);

#ifdef __cplusplus
}
#endif
