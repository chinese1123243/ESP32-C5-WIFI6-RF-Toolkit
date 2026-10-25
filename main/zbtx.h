/*
 * zbtx.h: 802.15.4 (Zigbee / Thread) 发送
 *
 * 与 zbsniff 共用同一套 802.15.4 射频, 因此:
 *   - 启动前由 CLI 层保证 wifi_attack_stop_all() (射频分时)
 *   - zbsniff 已在跑时可以直接叠加上来 (同一信道), 发完靠 rx_when_idle 自动回 RX
 *
 * 帧格式与 esp_ieee802154_transmit() 约定一致:
 *   | Len | MHR | MAC Payload | FCS |
 *   Len = MHR + payload 长度 (不含 Len 自身, 不含 FCS), FCS 由硬件算.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZBTX_FRAME_MAX  127

/* 帧构造: 返回帧长 (含 1 字节长度前缀), 0 = 失败 */

/* Zigbee 协调器 beacon. pan=0 表示不指定(用随机). */
int zbtx_build_beacon(uint8_t *out, int cap, uint16_t pan, uint8_t ch, uint8_t seq);

/* Beacon Request (MAC cmd 7), dst 用广播 PAN 0xFFFF. 收到它的协调器会回 beacon. */
int zbtx_build_beacon_req(uint8_t *out, int cap, uint16_t pan, uint8_t seq);

/* 单播数据帧. payload 可空. */
int zbtx_build_data(uint8_t *out, int cap, uint16_t dst_pan, uint16_t dst,
                    uint16_t src_pan, uint16_t src,
                    const uint8_t *payload, int plen, uint8_t seq);

/* 发送 */

/* 在 ch 上打开发射通路 (需要 802.15.4 射频空闲). 已在跑返回 ESP_ERR_INVALID_STATE. */
esp_err_t zbtx_start(uint8_t ch);

/* 停止发射; zbsniff 还在跑时不动射频, 否则释放射频交回 Wi-Fi/BLE. */
esp_err_t zbtx_stop(void);

bool zbtx_is_on(void);
uint8_t zbtx_channel(void);

/* 发一帧, 阻塞等 transmit_done/failed, 最多 timeout_ms.
 * 返回 ESP_OK / ESP_FAIL(带错误码) / ESP_ERR_TIMEOUT. cca=true 先做空闲评估. */
esp_err_t zbtx_send(const uint8_t *frame, int len, uint32_t timeout_ms, bool cca);

/* 最近一次失败的错误码 (esp_ieee802154_tx_error_t) */
int zbtx_last_error(void);
/* 最近一次收到的 ACK 长度 (0 = 无 ACK); buf 可空 */
int zbtx_last_ack(uint8_t *buf, int cap);

/* 洪泛: 后台任务每 100ms 发一个 beacon, 共 n 个. n<=0 表示一直发到 stop.
 * 已在洪泛返回 ESP_ERR_INVALID_STATE. */
esp_err_t zbtx_flood_start(uint8_t ch, uint16_t pan, int n, bool cca);
esp_err_t zbtx_flood_stop(void);
bool     zbtx_flood_on(void);

/* 打印 META,ZB,TX,STATS */
void zbtx_status(void);

#ifdef __cplusplus
}
#endif
