/*
 * rgb_led.c: WS2812 RMT 驱动实现 (v2: 扩展状态 + 瞬态事件)
 *
 * 适配 ESP-IDF v5.5.3 (无 led_strip 组件, 用 RMT + 自定义 encoder).
 * encoder 逻辑移植自 examples/peripherals/rmt/led_strip/led_strip_encoder.c.
 */
#include "rgb_led.h"

#include <stdatomic.h>
#include "radio_common.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_check.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_encoder.h"

static const char *TAG = "RGB";

#define RMT_RES_HZ    10000000   /* 10 MHz, 1 tick = 0.1us */
#define GRB_BYTES     3          /* 单颗 WS2812 = 3 字节 (G R B, msb first) */

static rmt_channel_handle_t s_chan = NULL;
static rmt_encoder_handle_t s_enc  = NULL;
static _Atomic rgb_status_t s_cur_status = RGB_OFF;   /* 单一事实源: 当前主状态 */
static bool                 s_inited = false;
static TaskHandle_t         s_task = NULL;            /* 呼吸/刷新任务 */

/* 瞬态事件节流: 每种事件记录上次触发时间(ms) */
static uint32_t s_ev_last_tick[RGB_EV_MAX] = {0};

/* 状态层: 调用方只写这些, 硬件刷新由 rgb_task 独占.
 * 分离前 rgb_led_event() 内部 vTaskDelay(事件时长), phish.c 在 HTTP 任务里
 * 闪 EAPOL 要卡 150ms, 阻塞的是处理请求的那个任务. */
static _Atomic uint32_t s_flash_until = 0;   /* 事件截止时间, 0=无事件 */
static _Atomic uint8_t  s_fr = 0, s_fg = 0, s_fb = 0;

#define BREATH_PERIOD_MS   2200u   /* 一个完整明暗周期 */
#define BREATH_TICK_MS     20u     /* 50Hz 刷新 */
#define BREATH_MIN_Q16     20971u  /* 感知域下限 0.32; 压到全黑会看成"灭了再亮" */

/* gamma 2.2 查表: 感知域 Q16 -> PWM Q16.
 * 33 项 + 线性插值, 实测最大误差 0.03%, 小于 1 个 LED 量化级 (0.39%). */
static const uint16_t kGammaQ16[33] = {
    0, 32, 147, 359, 676, 1104, 1648, 2314,
    3104, 4022, 5072, 6255, 7574, 9033, 10632, 12375,
    14263, 16298, 18482, 20816, 23303, 25943, 28739, 31692,
    34802, 38072, 41503, 45097, 48853, 52774, 56860, 61114,
    65535
};

/* WS2812 RMT encoder (移植自官方 example) */

typedef struct {
    rmt_encoder_t base;
    rmt_encoder_t *bytes_encoder;
    rmt_encoder_t *copy_encoder;
    int state;
    rmt_symbol_word_t reset_code;
} rmt_led_encoder_t;

RMT_ENCODER_FUNC_ATTR
static size_t rmt_encode_led(rmt_encoder_t *encoder, rmt_channel_handle_t channel,
                             const void *primary_data, size_t data_size,
                             rmt_encode_state_t *ret_state)
{
    rmt_led_encoder_t *led = __containerof(encoder, rmt_led_encoder_t, base);
    rmt_encode_state_t session_state = RMT_ENCODING_RESET;
    rmt_encode_state_t state = RMT_ENCODING_RESET;
    size_t encoded = 0;
    switch (led->state) {
    case 0:
        encoded += led->bytes_encoder->encode(led->bytes_encoder, channel, primary_data, data_size, &session_state);
        if (session_state & RMT_ENCODING_COMPLETE) led->state = 1;
        if (session_state & RMT_ENCODING_MEM_FULL) { state |= RMT_ENCODING_MEM_FULL; goto out; }
        /* fall-through */
    case 1:
        encoded += led->copy_encoder->encode(led->copy_encoder, channel, &led->reset_code,
                                              sizeof(led->reset_code), &session_state);
        if (session_state & RMT_ENCODING_COMPLETE) {
            led->state = RMT_ENCODING_RESET;
            state |= RMT_ENCODING_COMPLETE;
        }
        if (session_state & RMT_ENCODING_MEM_FULL) { state |= RMT_ENCODING_MEM_FULL; goto out; }
    }
out:
    *ret_state = state;
    return encoded;
}

static esp_err_t rmt_del_led(rmt_encoder_t *encoder)
{
    rmt_led_encoder_t *led = __containerof(encoder, rmt_led_encoder_t, base);
    rmt_del_encoder(led->bytes_encoder);
    rmt_del_encoder(led->copy_encoder);
    free(led);
    return ESP_OK;
}

static esp_err_t rmt_led_reset(rmt_encoder_t *encoder)
{
    rmt_led_encoder_t *led = __containerof(encoder, rmt_led_encoder_t, base);
    rmt_encoder_reset(led->bytes_encoder);
    rmt_encoder_reset(led->copy_encoder);
    led->state = RMT_ENCODING_RESET;
    return ESP_OK;
}

static esp_err_t rmt_new_led_encoder(uint32_t resolution, rmt_encoder_handle_t *ret_encoder)
{
    esp_err_t ret = ESP_OK;
    rmt_led_encoder_t *led = rmt_alloc_encoder_mem(sizeof(*led));
    ESP_GOTO_ON_FALSE(led, ESP_ERR_NO_MEM, err, TAG, "no mem");
    led->base.encode = rmt_encode_led;
    led->base.del    = rmt_del_led;
    led->base.reset  = rmt_led_reset;
    rmt_bytes_encoder_config_t bcfg = {
        .bit0 = { .level0 = 1, .duration0 = 0.3 * resolution / 1000000,
                  .level1 = 0, .duration1 = 0.9 * resolution / 1000000 },
        .bit1 = { .level0 = 1, .duration0 = 0.9 * resolution / 1000000,
                  .level1 = 0, .duration1 = 0.3 * resolution / 1000000 },
        .flags.msb_first = 1,
    };
    ESP_GOTO_ON_ERROR(rmt_new_bytes_encoder(&bcfg, &led->bytes_encoder), err, TAG, "bytes enc");
    rmt_copy_encoder_config_t ccfg = {};
    ESP_GOTO_ON_ERROR(rmt_new_copy_encoder(&ccfg, &led->copy_encoder), err, TAG, "copy enc");
    uint32_t rt = resolution / 1000000 * 50 / 2;
    led->reset_code = (rmt_symbol_word_t){ .level0 = 0, .duration0 = rt,
                                           .level1 = 0, .duration1 = rt };
    *ret_encoder = &led->base;
    return ESP_OK;
err:
    if (led) {
        if (led->bytes_encoder) rmt_del_encoder(led->bytes_encoder);
        if (led->copy_encoder)  rmt_del_encoder(led->copy_encoder);
        free(led);
    }
    return ret;
}


/* rgb_tx 只允许 rgb_task 调 (单一写入者).
 * 以前每个调用方都直接写 RMT: 并发 transmit 会返回 INVALID_STATE 并等 100ms,
 * 而 rgb_led_event 还带 vTaskDelay(事件时长): phish.c 在 HTTP 任务里闪
 * EAPOL 就是 150ms, 阻塞的是处理请求的那个任务. 现在调用方只改状态变量,
 * 硬件刷新全部收敛到 rgb_task. */
static esp_err_t rgb_tx(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_inited) return ESP_ERR_INVALID_STATE;

    uint8_t grb[GRB_BYTES] = { g, r, b };
    rmt_transmit_config_t tx = { .loop_count = 0 };
    esp_err_t e = rmt_transmit(s_chan, s_enc, grb, sizeof(grb), &tx);
    if (e == ESP_OK) e = rmt_tx_wait_all_done(s_chan, 30);
    return e;
}

static void rgb_task(void *arg);

esp_err_t rgb_led_init(void)
{
    if (s_inited) return ESP_OK;
    rmt_tx_channel_config_t txcfg = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = (gpio_num_t)RFTOOL_RGB_GPIO,
        .mem_block_symbols = 64,
        .resolution_hz = RMT_RES_HZ,
        .trans_queue_depth = 4,
    };
    ESP_RETURN_ON_ERROR(rmt_new_tx_channel(&txcfg, &s_chan), TAG, "new tx ch");
    ESP_RETURN_ON_ERROR(rmt_new_led_encoder(RMT_RES_HZ, &s_enc), TAG, "new encoder");
    ESP_RETURN_ON_ERROR(rmt_enable(s_chan), TAG, "enable");
    s_inited = true;
    s_cur_status = RGB_BOOT;
    rgb_tx(20, 0, 20);  /* 先点亮, 不等任务首次调度 */

    /* 刷新任务: 唯一写 RMT 的地方. 优先级 2, 低于业务任务但高于 IDLE,
     * 这样业务忙时不会把 50Hz 的呼吸节奏挤没. */
    if (xTaskCreate(rgb_task, "rgb", 2048, NULL, 2, &s_task) != pdPASS) {
        ESP_LOGW(TAG, "呼吸任务创建失败, LED 只保留静态色");
    }
    ESP_LOGI(TAG, "WS2812 init ok, GPIO=%d", RFTOOL_RGB_GPIO);
    return ESP_OK;
}

/* 主状态样式: 色相(三通道比例) + 呼吸峰值 + 闪烁半周期
 * - 峰值: 背景态压低(护眼), 活跃态抬高(要看得见). 呼吸作用在峰值上,
 *   不是简单乘基色: 基色最暗的 IDLE 蓝只有 12, 直接乘只剩 12 级量化,
 *   根本看不出渐变.
 * - 闪烁: 0=呼吸(平滑渐变); >0=方波半周期ms. 硬边方波和渐变呼吸在视觉上
 *   一眼可分, 所以告警/错误用闪, 正常态用呼吸. */
typedef struct { uint8_t r, g, b; uint8_t peak; uint16_t blink_ms; } status_style_t;

static const status_style_t s_style[] = {
    [RGB_OFF]           = { 0,  0,  0,    0,   0   },
    [RGB_BOOT]          = { 8,  0,  8,   40,   0   },  /* 紫 */
    [RGB_IDLE]          = { 0,  0,  12,  44,   0   },  /* 蓝 */
    [RGB_SNIFF_SINGLE]  = { 0,  24, 0,   84,   0   },  /* 绿 */
    [RGB_SNIFF_AUTO]    = { 16, 24, 0,   84,   0   },  /* 黄绿 */
    [RGB_INJECT_DEAUTH] = { 32, 0,  0,  120,   0   },  /* 红 */
    [RGB_INJECT_BEACON] = { 32, 0,  24, 120,   0   },  /* 洋红 */
    [RGB_INJECT_PROBE]  = { 32, 12, 0,  120,   0   },  /* 橙红 */
    [RGB_HTTP_READY]    = { 0,  16, 24,  72,   0   },  /* 青蓝 */
    [RGB_EXPORT]        = { 24, 20, 0,   72,   0   },  /* 金黄 */
    [RGB_DUMP]          = { 12, 0,  20,  72,   0   },  /* 浅紫 */
    [RGB_WARN]          = { 24, 12, 0,  110, 400  },  /* 橙, 慢闪 */
    [RGB_ERROR]         = { 48, 0,  0,  150, 200  },  /* 红, 快闪 */
};

static const status_style_t *style_of(rgb_status_t s)
{
    return (s < (rgb_status_t)(sizeof(s_style)/sizeof(s_style[0]))) ? &s_style[s] : &s_style[RGB_OFF];
}

static uint8_t style_max(const status_style_t *st)
{
    uint8_t mx = st->r;
    if (st->g > mx) mx = st->g;
    if (st->b > mx) mx = st->b;
    return mx;
}

/* v2: 瞬态事件 -> (颜色, 持续ms) 映射 */
typedef struct { uint8_t r, g, b; uint32_t ms; } ev_flash_t;

static const ev_flash_t s_ev_flash[RGB_EV_MAX] = {
    [RGB_EV_EAPOL_CAPTURED] = { 60, 60, 60, 150 },  /* 白, 150ms */
    [RGB_EV_CHAN_SWITCH]     = { 0,  0,  48, 40 },   /* 蓝, 40ms  */
    [RGB_EV_TX_OK]           = { 0,  0,  0,  0 },     /* 特殊: 加深主色 15ms */
    [RGB_EV_CMD_SUCCESS]     = { 0,  40, 0,  100 },  /* 绿, 100ms */
    [RGB_EV_CMD_ERROR]       = { 48, 0,  0,  100 },  /* 红, 100ms */
    [RGB_EV_STA_JOIN]        = { 0,  32, 32, 80 },   /* 青, 80ms  */
    [RGB_EV_BLE_CONNECT]     = { 48, 0,  48, 200 },  /* 紫, 200ms */
};

static uint32_t now_ms(void)
{
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

/* 呼吸曲线. 三角波必须先走在感知域、再过 gamma 表转成 PWM:
 * 直接在 PWM 域线性明暗, 实测暗端的感知变化速度是亮端的 3.35 倍,
 * 看着就是"底部一跳一跳"; 而最小亮度若加在 PWM 域, 暗端又会几乎不动. */
static uint16_t breath_level_q16(uint32_t now)
{
    uint32_t ph  = (now % BREATH_PERIOD_MS) * 65536u / BREATH_PERIOD_MS;
    uint32_t tri = (ph < 32768u) ? (ph * 2u) : ((65536u - ph) * 2u);
    uint32_t p   = BREATH_MIN_Q16 + (((65535u - BREATH_MIN_Q16) * tri) >> 16);

    uint32_t x = p * 32u;                 /* Q16, 值域 0..32 */
    uint32_t i = x >> 16;
    if (i >= 32u) return kGammaQ16[32];
    uint32_t f = x & 0xFFFFu;
    return (uint16_t)(kGammaQ16[i] + (((kGammaQ16[i + 1] - kGammaQ16[i]) * f) >> 16));
}

/* 登记一次闪烁, 只写状态: 调用方可能在驱动或 HTTP 上下文, 不能碰硬件也不能延时 */
static void set_flash(uint8_t r, uint8_t g, uint8_t b, uint32_t ms)
{
    s_fr = r; s_fg = g; s_fb = b;
    s_flash_until = now_ms() + (ms ? ms : 40u);
}

static void render_frame(uint32_t now)
{
    /* 事件抢占: 闪纯色且不呼吸, 到点自动回落 */
    if (s_flash_until) {
        if (now < s_flash_until) { rgb_tx(s_fr, s_fg, s_fb); return; }
        s_flash_until = 0;
    }

    const status_style_t *st = style_of(s_cur_status);
    uint8_t mx = style_max(st);
    if (mx == 0) { rgb_tx(0, 0, 0); return; }

    /* 闪烁态: 硬边方波, 与呼吸的平滑渐变一眼可分 */
    if (st->blink_ms) {
        bool on = (((now / st->blink_ms) & 1u) == 0u);
        rgb_tx(on ? st->r : 0, on ? st->g : 0, on ? st->b : 0);
        return;
    }

    /* 呼吸: 保持色相比例, 把最亮的分量缩放到该状态的峰值 */
    uint32_t k = ((uint32_t)st->peak * breath_level_q16(now)) / mx;
    rgb_tx((uint8_t)((st->r * k) >> 16),
           (uint8_t)((st->g * k) >> 16),
           (uint8_t)((st->b * k) >> 16));
}

static void rgb_task(void *arg)
{
    (void)arg;
    while (1) {
        render_frame(now_ms());
        vTaskDelay(pdMS_TO_TICKS(BREATH_TICK_MS));
    }
}

esp_err_t rgb_led_set(uint8_t r, uint8_t g, uint8_t b)
{
    /* 手动设色按 2s 事件处理, 否则下一帧就被呼吸盖掉 */
    set_flash(r, g, b, 2000);
    return ESP_OK;
}

esp_err_t rgb_led_set_status(rgb_status_t s)
{
    s_cur_status = s;
    return ESP_OK;
}

rgb_status_t rgb_led_get_status(void)
{
    return s_cur_status;
}

void rgb_led_event(rgb_event_t ev, uint32_t skip_if_same_interval_ms)
{
    if (!s_inited || ev >= RGB_EV_MAX) return;

    /* 节流: 同类事件在窗口内跳过 */
    if (skip_if_same_interval_ms > 0) {
        uint32_t now = now_ms();
        if (now - s_ev_last_tick[ev] < skip_if_same_interval_ms) return;
        s_ev_last_tick[ev] = now;
    }

    if (ev == RGB_EV_TX_OK) {
        /* 同色加深: 峰值抬 40 再按色相比例展开 */
        const status_style_t *st = style_of(s_cur_status);
        uint8_t mx = style_max(st);
        if (mx == 0) return;
        uint32_t k = ((uint32_t)(st->peak + 40u) * 65536u) / mx;
        set_flash((uint8_t)((st->r * k) >> 16),
                  (uint8_t)((st->g * k) >> 16),
                  (uint8_t)((st->b * k) >> 16), 40);
        return;
    }

    const ev_flash_t *f = &s_ev_flash[ev];
    set_flash(f->r, f->g, f->b, f->ms);
}

void rgb_led_pulse(uint8_t r, uint8_t g, uint8_t b, uint32_t ms)
{
    if (!s_inited) return;
    set_flash(r, g, b, ms);
}
