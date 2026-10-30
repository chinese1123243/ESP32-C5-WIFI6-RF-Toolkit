/*
 * event_bus.h: 统一事件总线
 *
 * 目标: 新增/已有事件只写一处, 三个消费端自动可见:
 *   · 串口 CLI 行 (META,...)
 *   · BLE NUS notify (经 ble_event_post 限速发送)
 *   · HTTP 拉取 (/api/events?n=20)
 *
 * 设计取舍:
 *   - 不做 SSE: 当前 httpd 是单连接阻塞模型, 长连接会饿死其它请求.
 *     改成"环形缓冲 + 拉取", App 轮询即可, 也更省电.
 *   - 发布路径可能跑在 Wi-Fi 驱动任务里, 所以只做 memcpy + 非阻塞分发,
 *     拿不到锁就丢弃本条, 绝不阻塞回调.
 */
#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EVENT_TOPIC_LEN  20
#define EVENT_TEXT_LEN   96
#define EVENT_RING_LEN   16
#define EVENT_SUBS_MAX   8

typedef void (*event_cb_t)(const char *topic, const char *msg, void *ctx);

esp_err_t event_bus_init(void);

/* 发布一条事件. fmt 里不要带换行 (会被替换成空格). */
void event_publish(const char *topic, const char *fmt, ...);

/* 订阅: prefix 为空表示全部. 返回订阅 id (>=0), 失败 -1. */
int  event_subscribe(const char *prefix, event_cb_t cb, void *ctx);
void event_unsubscribe(int id);

/* 最近事件导出为 JSON: {"ok":true,"events":[{"seq":12,"topic":"SNIFF","msg":"..."}]}
 * limit<=0 表示用默认 10. 返回写入长度. */
int  event_snapshot_json(char *buf, size_t cap, int limit);

/* 已发布总数 / 当前缓冲条数 */
unsigned event_total(void);
int      event_buffered(void);

/* 计量口径:
 *   event_published  调用次数, 含被丢的; event_total 只数真进环的, 两者不等
 *   event_dropped    拿不到环形锁而整条丢弃 (环形缓冲与订阅者都没看到)
 * 都是单字读写, 任意任务上下文可读, 不加锁.
 * 到达率不在本模块: 真正压满链路的是 out_raw 的每包一行调用者, 见
 * out_stream.h 的 out_rate_x10(). */
unsigned event_published(void);
unsigned event_dropped(void);

#ifdef __cplusplus
}
#endif
