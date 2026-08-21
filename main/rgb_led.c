/*
 * rgb_led.c — WS2812 RMT 驱动实现
 *
 * 适配 ESP-IDF v5.5.3 (无 led_strip 组件, 用 RMT + 自定义 encoder).
 * encoder 逻辑移植自 examples/peripherals/rmt/led_strip/led_strip_encoder.c.
 */
#include "rgb_led.h"
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
static rgb_status_t         s_last = RGB_OFF;
static bool                 s_inited = false;

/* ---------- WS2812 RMT encoder (移植自官方 example) ---------- */

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
    /* 注意: ESP_GOTO_ON_* 宏内部固定写入名为 `ret` 的变量, 故输出参数须改名
     * (官方 led_strip_encoder.c 亦如此), 并声明本地 esp_err_t ret. */
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

/* ---------- 公共 API ---------- */

static esp_err_t rgb_tx(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_inited) return ESP_ERR_INVALID_STATE;
    /* WS2812 字节序: G7..G0 R7..R0 B7..B0 (msb first) */
    uint8_t grb[GRB_BYTES] = { g, r, b };
    rmt_transmit_config_t tx = { .loop_count = 0 };
    ESP_RETURN_ON_ERROR(rmt_transmit(s_chan, s_enc, grb, sizeof(grb), &tx),
                        TAG, "rmt_transmit");
    ESP_RETURN_ON_ERROR(rmt_tx_wait_all_done(s_chan, 100), TAG, "tx wait");
    return ESP_OK;
}

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
    s_last = RGB_BOOT;
    rgb_tx(20, 0, 20);  /* 启动: 紫 */
    ESP_LOGI(TAG, "WS2812 init ok, GPIO=%d", RFTOOL_RGB_GPIO);
    return ESP_OK;
}

/* 状态 -> 颜色映射 (亮度调暗, 护眼/省电) */
static void status_to_rgb(rgb_status_t s, uint8_t *r, uint8_t *g, uint8_t *b)
{
    switch (s) {
    case RGB_OFF:    *r = 0;   *g = 0;   *b = 0;   break;
    case RGB_BOOT:   *r = 8;   *g = 0;   *b = 8;   break;  /* 暗紫 */
    case RGB_IDLE:   *r = 0;   *g = 0;   *b = 12;  break;  /* 暗蓝 */
    case RGB_SNIFF:  *r = 0;   *g = 24;  *b = 0;   break;  /* 绿 */
    case RGB_INJECT: *r = 32;  *g = 0;   *b = 0;   break;  /* 红 */
    case RGB_ERROR:  *r = 48;  *g = 0;   *b = 0;   break;  /* 亮红 */
    default:         *r = 0;   *g = 0;   *b = 0;   break;
    }
}

esp_err_t rgb_led_set(uint8_t r, uint8_t g, uint8_t b)
{
    return rgb_tx(r, g, b);
}

esp_err_t rgb_led_set_status(rgb_status_t s)
{
    s_last = s;
    uint8_t r, g, b;
    status_to_rgb(s, &r, &g, &b);
    return rgb_tx(r, g, b);
}

void rgb_led_pulse(uint8_t r, uint8_t g, uint8_t b, uint32_t ms)
{
    if (!s_inited) return;
    rgb_tx(r, g, b);
    if (ms) vTaskDelay(pdMS_TO_TICKS(ms));
    uint8_t r0, g0, b0;
    status_to_rgb(s_last, &r0, &g0, &b0);
    rgb_tx(r0, g0, b0);
}
