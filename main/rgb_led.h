/*
 * rgb_led.h: WS2812B-0807 状态指示 (RMT TX + 自定义 encoder)
 *
 * 硬件: DIN 接 GPIO27 (经 RGB_CTRL 门控, 运行时常通).
 *   GPIO27 是 strapping 脚, 仅复位采样, 运行时作 GPIO 输出无碍.
 * 驱动: RMT bytes/copy encoder 生成 WS2812 NRZ
 *   (T0H/T1H = 0.3/0.9us, T0L/T1L = 0.9/0.3us, reset >= 50us).
 *
 * 刷新模型: 单一写入者. 调用方只改状态 (s_cur_status / s_flash_*),
 *   由 rgb_task 独占 RMT 以 50Hz 渲染. 因此 rgb_led_event() 不含
 *   vTaskDelay, 可安全用于驱动回调与 HTTP 任务上下文.
 *
 * 视觉语义:
 *   呼吸  常态. 感知域三角波经 gamma 转 PWM, 全程等速明暗
 *   闪烁  告警/错误. 硬边方波, 与渐变呼吸一眼可分
 *   事件  瞬态抢占, 纯色不呼吸, 到点回落主状态
 * 亮度分档与色相见 rgb_led.c 的 s_style.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* 基础状态 (原有 6 个序号保持不变, 兼容 ABI) */
    RGB_OFF = 0,
    RGB_BOOT,
    RGB_IDLE,
    RGB_SNIFF_SINGLE,          /* 新: 单信道嗅探 (深绿) */
    RGB_INJECT_DEAUTH,         /* 新: Deauth 注入 (亮红) */
    RGB_ERROR,

    /* v2 扩展状态 (序号 6+) */
    RGB_SNIFF_AUTO,            /* 黄绿: 自动信道轮询 */
    RGB_INJECT_BEACON,         /* 洋红: Beacon Flood */
    RGB_INJECT_PROBE,          /* 橙红: Probe Flood  */
    RGB_HTTP_READY,            /* 青蓝: HTTP 服务器在线 */
    RGB_EXPORT,                /* 金黄: 导出 CSV/JSON */
    RGB_DUMP,                  /* 浅紫: dump 表输出  */
    RGB_WARN,                  /* 橙:   非致命告警    */

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
    RGB_EV_BLE_CONNECT,          /* 紫, 200ms: BLE 客户端连接 */
    RGB_EV_MAX,
} rgb_event_t;


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
