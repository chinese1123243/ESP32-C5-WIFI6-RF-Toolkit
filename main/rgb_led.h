/*
 * rgb_led.h — 板载 WS2812B-0807 RGB LED 状态指示 (v2 扩展版)
 *
 * 硬件: WS2812 DIN 接 GPIO27 (经 RGB_CTRL 电源门控, 运行时常通).
 *   GPIO27 是 strapping 脚, strapping 仅复位时采样, 运行时作 GPIO 输出无碍.
 *
 * 驱动: RMT TX + 自定义 bytes/copy encoder 实现 WS2812 NRZ 时序
 *   (T0H=0.3us T0L=0.9us T1H=0.9us T1L=0.3us reset>=50us).
 *
 * v2 扩展设计: 任务可视化 + 瞬态事件
 *   1) 主状态 (rgb_status_t): 持久显示, 由模块主动切换, 单一事实源 s_cur_status
 *   2) 瞬态事件 (rgb_event_t): 短暂闪一下然后恢复主状态, 用于包级反馈
 *
 * 颜色语义 (主状态).  亮度原则: 背景态 <= 32, 事件 flash <= 80.
 *   +-------------------------+------+----------------------------------------+
 *   | 主状态枚举               | 颜色  | 语义说明                                 |
 *   +-------------------------+------+----------------------------------------+
 *   | RGB_OFF                 | 黑    | 启动早期 / 显式关灯                     |
 *   | RGB_BOOT                | 暗紫  | 初始化中 (NVS/Wi-Fi/DB 未就绪)           |
 *   | RGB_IDLE                | 暗蓝  | REPL 待命, 无后台任务                   |
 *   | RGB_SNIFF_SINGLE        | 深绿  | 单信道 promiscuous 嗅探 (固定信道)       |
 *   | RGB_SNIFF_AUTO          | 黄绿  | 自动信道轮询 (channel_rotate_task 运行)  |
 *   | RGB_INJECT_DEAUTH       | 亮红  | Deauth / Disassoc 帧注入                |
 *   | RGB_INJECT_BEACON       | 洋红  | Beacon Flood (伪造 AP)                   |
 *   | RGB_INJECT_PROBE        | 橙红  | Probe Flood (伪造探测请求)               |
 *   | RGB_HTTP_READY          | 青蓝  | HTTP REST API 已启动 (SoftAP 待机)       |
 *   | RGB_EXPORT              | 金黄  | 正在导出 CSV/JSON                        |
 *   | RGB_DUMP                | 浅紫  | 正在 dump 表到串口                       |
 *   | RGB_WARN                | 橙    | 参数错误 / 边界告警 (非致命)             |
 *   | RGB_ERROR               | 亮红  | 致命错误 (初始化失败 / 任务退出异常)      |
 *   | (兼容别名) RGB_SNIFF    | =SNIFF_SINGLE | 兼容旧 api 调用                  |
 *   | (兼容别名) RGB_INJECT   | =INJECT_DEAUTH  | 兼容旧 api 调用                 |
 *   +-------------------------+------+----------------------------------------+
 *
 * 事件颜色 (瞬态):
 *   RGB_EV_EAPOL_CAPTURED   闪白  抓到 EAPOL M1/M2 握手包 (重要!)
 *   RGB_EV_CHAN_SWITCH      闪蓝  自动信道轮询跳变
 *   RGB_EV_TX_OK            闪同色 当前注入任务包 TX 成功 (低频触发)
 *   RGB_EV_CMD_SUCCESS      闪绿  CLI 命令成功
 *   RGB_EV_CMD_ERROR        闪红  CLI 命令参数/执行错误
 *   RGB_EV_STA_JOIN         闪青  HTTP SoftAP 接有 STA 连接
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* ===== 基础状态 (原有 6 个序号保持不变, 兼容 ABI) ===== */
    RGB_OFF = 0,
    RGB_BOOT,
    RGB_IDLE,
    RGB_SNIFF_SINGLE,          /* 新: 单信道嗅探 (深绿) */
    RGB_INJECT_DEAUTH,         /* 新: Deauth 注入 (亮红) */
    RGB_ERROR,

    /* ===== v2 扩展状态 (序号 6+) ===== */
    RGB_SNIFF_AUTO,            /* 黄绿: 自动信道轮询 */
    RGB_INJECT_BEACON,         /* 洋红: Beacon Flood */
    RGB_INJECT_PROBE,          /* 橙红: Probe Flood  */
    RGB_HTTP_READY,            /* 青蓝: HTTP 服务器在线 */
    RGB_EXPORT,                /* 金黄: 导出 CSV/JSON */
    RGB_DUMP,                  /* 浅紫: dump 表输出  */
    RGB_WARN,                  /* 橙:   非致命告警    */

    /* ===== 兼容旧 API 的别名 ===== */
    RGB_SNIFF  = RGB_SNIFF_SINGLE,
    RGB_INJECT = RGB_INJECT_DEAUTH,
} rgb_status_t;

/* 瞬态事件类型 (事件发生调用 rgb_led_event(), 闪完自动恢复主状态) */
typedef enum {
    RGB_EV_EAPOL_CAPTURED = 0,   /* 白, 150ms: 抓到握手包 */
    RGB_EV_CHAN_SWITCH,          /* 蓝, 40ms:  信道切换 */
    RGB_EV_TX_OK,                /* 主色加深, 15ms: 注入包 TX 完成 */
    RGB_EV_CMD_SUCCESS,          /* 绿, 100ms: CLI 成功 */
    RGB_EV_CMD_ERROR,            /* 红, 100ms: CLI 失败 */
    RGB_EV_STA_JOIN,             /* 青, 80ms:  STA 连入 SoftAP */
    RGB_EV_MAX,
} rgb_event_t;

/* ===== 公共 API ===== */

/* 初始化 RMT 通道 + encoder, 点亮紫色 (BOOT).
 * 多次调用安全: 仅首次生效. */
esp_err_t rgb_led_init(void);

/* 直接设 RGB (0..255). 注意: 不更新主状态, 下次 set_status/event 会覆盖.
 * 业务代码尽量使用 set_status/event 而不是裸 set. */
esp_err_t rgb_led_set(uint8_t r, uint8_t g, uint8_t b);

/* 按枚举切换主状态 (持久生效, 单一事实源). 业务模块首选. */
esp_err_t rgb_led_set_status(rgb_status_t s);

/* 查询当前主状态 (用于 UI/日志判断当前模式). */
rgb_status_t rgb_led_get_status(void);

/* 瞬态事件: 闪一下然后恢复主状态.
 * 注意: 内部 vTaskDelay, 不可在 ISR/回调里直接调用; 高频注入路径用参数节流.
 * @param ev   事件类型
 * @param skip_if_same_interval_ms  为 0 不节流; >0 时若上次同类事件在该窗口内则跳过 */
void rgb_led_event(rgb_event_t ev, uint32_t skip_if_same_interval_ms);

/* 通用脉冲 (与旧 API 兼容, 但会恢复到"主状态"色而不是任意上次 set 的色) */
void rgb_led_pulse(uint8_t r, uint8_t g, uint8_t b, uint32_t ms);

#ifdef __cplusplus
}
#endif
