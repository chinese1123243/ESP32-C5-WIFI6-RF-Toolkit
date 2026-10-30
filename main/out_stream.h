#pragma once

#include <stdbool.h>
#include <stddef.h>

/* 输出汇点.
 *
 * 为什么需要: 领域层要往手机回传一行状态, 原来直接 include "ble_cli.h" 调
 * ble_event_post, 于是 7 个领域文件都反向依赖传输层. 新增一个模块就得再抄一遍.
 *
 * 现在领域层只调 out_raw()/out_line(), 谁听、怎么发由传输层在初始化时自己
 * out_sink_add() 注册. 领域层不需要知道 BLE 存在.
 *
 * 约束: 汇点回调可能跑在 Wi-Fi 驱动任务里, 只许做"拷进队列"这类非阻塞动作,
 * 不许 printf、不许阻塞、不许再发布事件 (会自己调自己).
 */

#define OUT_SINK_MAX 4

typedef void (*out_sink_fn)(const char *line, void *ctx);

/* 初始化. 幂等. */
void out_stream_init(void);

/* 注册/注销汇点. 返回 id (>=0), 满或参数非法返回 -1. */
int  out_sink_add(out_sink_fn fn, void *ctx);
void out_sink_remove(int id);

/* 发一行. out_raw 认为传入已是完整行; out_line 接受 printf 风格格式串.
 * 两者都不加换行, 换行由调用方决定 (与原 ble_event_post 的约定一致). */
void out_raw(const char *line);
void out_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* 到达率 x10 (行/秒), 最近一个 1 秒窗口.
 *
 * 为什么量在这里: 会压满 BLE 通道的是 sniff/cap/hs/phish 这些每包一行的
 * 调用者, 它们不经过 event_bus. 只在 event_publish 上量, 读到的永远是 0.
 * out_raw 是所有出站行的唯一汇点, 在这里算 λ 才是链路的真实负载.
 *
 * 返回 0 表示最近窗口内没有输出, 不是"精确的零速率".
 * 只读单字变量, 任意任务上下文可读. */
unsigned out_rate_x10(void);

/* BLE 广播闸门: 枚举 GATT 前需要暂停广播, 否则会挤掉手机连接.
 * 传输层注册实现, 领域层只表达"我要独占一下". 未注册时为空操作. */
typedef void (*out_adv_gate_fn)(bool hold);
void out_adv_gate_set(out_adv_gate_fn fn);
void out_adv_gate(bool hold);

/* 传输链路状态. 状态查询同样是领域层不该直连传输层的东西:
 * 有的模块要报告"手机连没连、MTU 多少", 但不该 include ble_cli.h. */
typedef struct {
    int  mtu;
    bool connected;
    int  phy;
} out_link_t;

typedef void (*out_link_fn)(out_link_t *out);
void out_link_set(out_link_fn fn);
void out_link(out_link_t *out);   /* 未注册时填 0 / false / 0 */

/* 通道吞吐与丢弃. 汇点自己知道限速多少、丢了多少, 上层不该为此 include
 * 具体传输层 (ble_cli.h). 用与 out_link 相同的手法: 传输层初始化时注册. */
typedef struct {
    int      capacity_per_s;   /* 该通道每秒最多发多少行 */
    unsigned dropped;          /* 因排队满而挤掉的条数 (累计) */
} out_stats_t;

typedef void (*out_stats_fn)(out_stats_t *out);
void out_stats_set(out_stats_fn fn);
void out_stats(out_stats_t *out);  /* 未注册时填 0 / 0 */
