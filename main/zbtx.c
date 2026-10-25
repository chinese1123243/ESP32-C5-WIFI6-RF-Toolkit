/*
 * zbtx.c: 802.15.4 发送实现
 *
 * 与 zbsniff 的分工: zbsniff 只管收, 这里只管发. 两个模块都只在自己的
 * start 里调 esp_ieee802154_enable(), IDF 内部有引用计数, 叠用不会重复初始化.
 *
 * transmit_done/failed 跑在 ISR 上下文, 只置标志, 不发信号量 (esp_ieee802154
 * 的 ISR 里调 xSemaphoreGiveFromISR 是允许的, 但置标志 + 轮询更省心, 发送
 * 频率本来就不高).
 */
#include "zbtx.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_random.h"

#include "zbsniff.h"

/* WDT 辅助 (与 wifi_attack.c 同款) */
#if CONFIG_ESP_TASK_WDT_EN
#include "esp_task_wdt.h"
#define WDT_ADD()    do { esp_task_wdt_add(NULL); } while (0)
#define WDT_RESET()  do { esp_task_wdt_reset(); } while (0)
#define WDT_DEL()    do { esp_task_wdt_delete(NULL); } while (0)
#else
#define WDT_ADD()    do { } while (0)
#define WDT_RESET()  do { } while (0)
#define WDT_DEL()    do { } while (0)
#endif

#if CONFIG_IEEE802154_ENABLED

#include "esp_ieee802154.h"

static const char *TAG = "ZBTX";

/* FCF 位, 802.15.4-2003 (Zigbee 用的版本 0) */
#define FCF_TYPE(t)       ((uint16_t)((t) & 0x7))
#define FCF_DST_MODE(m)   ((uint16_t)(((m) & 0x3) << 10))
#define FCF_SRC_MODE(m)   ((uint16_t)(((m) & 0x3) << 14))
#define FCF_PAN_COMP      (1u << 6)

#define FT_BEACON     0
#define FT_DATA       1
#define FT_MAC_CMD    3

#define AM_NONE   0
#define AM_SHORT  2
#define AM_EXT    3

/* Zigbee NWK beacon payload: 协议ID + 版本/Profile + 容量 + 扩展PAN + TxOffset + UpdateId */
#define ZB_PROTO_ID        0x00
#define ZB_STACK_PROFILE   0x12   /* 版本 2, profile 1 (Zigbee) */

/* 状态 */
static _Atomic bool     s_on      = false;
static _Atomic uint8_t  s_ch      = 11;
static _Atomic bool     s_tx_busy = false;
static _Atomic esp_err_t s_tx_res = ESP_OK;
static _Atomic int      s_tx_err  = 0;      /* esp_ieee802154_tx_error_t */
static _Atomic uint32_t s_sent    = 0;
static _Atomic uint32_t s_fail    = 0;
static volatile uint8_t s_ack_len = 0;
static volatile uint8_t s_ack[ZBTX_FRAME_MAX + 1];
static volatile uint8_t s_seq     = 0;

/* 洪泛 */
static _Atomic bool s_flood_run = false;
static _Atomic int  s_flood_left = 0;
static uint16_t     s_flood_pan = 0;
static _Atomic bool s_flood_cca = true;
static TaskHandle_t s_flood_task = NULL;

static IRAM_ATTR void tx_copy(uint8_t *dst, const uint8_t *src, int n)
{
    for (int i = 0; i < n; i++) dst[i] = src[i];
}

/* ISR: 发送完成 */
IRAM_ATTR void esp_ieee802154_transmit_done(const uint8_t *frame,
                                            const uint8_t *ack,
                                            esp_ieee802154_frame_info_t *ack_frame_info)
{
    (void)frame; (void)ack_frame_info;
    atomic_fetch_add(&s_sent, 1);
    s_ack_len = 0;
    if (ack && ack[0] > 0 && ack[0] <= ZBTX_FRAME_MAX) {
        tx_copy(s_ack, ack, (int)ack[0] + 1);
        s_ack_len = ack[0];
    }
    atomic_store(&s_tx_res, ESP_OK);
    atomic_store(&s_tx_busy, false);
}

/* ISR: 发送失败 */
IRAM_ATTR void esp_ieee802154_transmit_failed(const uint8_t *frame,
                                              esp_ieee802154_tx_error_t error)
{
    (void)frame;
    atomic_fetch_add(&s_fail, 1);
    atomic_store(&s_tx_err, (int)error);
    atomic_store(&s_tx_res, ESP_FAIL);
    atomic_store(&s_tx_busy, false);
}

/* 帧构造 */

static int put_fcf(uint8_t *o, uint16_t fcf)
{
    o[0] = (uint8_t)(fcf & 0xFF);
    o[1] = (uint8_t)(fcf >> 8);
    return 2;
}

int zbtx_build_beacon(uint8_t *out, int cap, uint16_t pan, uint8_t ch, uint8_t seq)
{
    if (cap < 1 + 11 + 15) return 0;
    if (pan == 0) pan = (uint16_t)(esp_random() & 0xFFFF);
    if (pan == 0xFFFF) pan = 0xFFFE;      /* 广播 PAN 不能当协调器 */

    /* [0] 留给长度前缀, 内容从 1 开始写 */
    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_BEACON) | FCF_SRC_MODE(AM_SHORT));
    out[n++] = seq;
    out[n++] = (uint8_t)(pan & 0xFF);      /* src PAN (beacon 无 dst, 压缩位必须为 0) */
    out[n++] = (uint8_t)(pan >> 8);
    out[n++] = 0x00;                       /* src short addr = 0 (协调器) */
    out[n++] = 0x00;

    /* superframe: BO=15, SO=15, PAN coord=1, assoc permit=1 */
    out[n++] = 0xFF;
    out[n++] = 0xCF;
    out[n++] = 0x00;                       /* GTS: 无 */
    out[n++] = 0x00;                       /* Pending addr: 无 */

    /* Zigbee NWK beacon payload */
    out[n++] = ZB_PROTO_ID;
    out[n++] = ZB_STACK_PROFILE;
    out[n++] = 0x05;                       /* 容量: depth 1, router cap 1 */
    for (int i = 0; i < 8; i++) out[n++] = (uint8_t)(0x10 + i);   /* 扩展 PAN ID */
    out[n++] = 0x00;                       /* Tx offset (3 字节) */
    out[n++] = 0x00;
    out[n++] = 0x00;
    out[n++] = 0x00;                       /* Update ID */

    out[0] = (uint8_t)(n - 1);             /* 长度不含自身, 不含 FCS */
    (void)ch;
    return n;
}

int zbtx_build_beacon_req(uint8_t *out, int cap, uint16_t pan, uint8_t seq)
{
    if (cap < 1 + 10) return 0;

    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_MAC_CMD) | FCF_DST_MODE(AM_SHORT) |
                            FCF_SRC_MODE(AM_SHORT) | FCF_PAN_COMP);
    out[n++] = seq;
    /* dst PAN 用 0xFFFF (广播), 压缩位为 1 意味着 src PAN 与 dst 相同, 不再重复 */
    out[n++] = 0xFF;
    out[n++] = 0xFF;
    out[n++] = 0xFF;                       /* dst short = 广播 */
    out[n++] = 0xFF;
    out[n++] = 0x34;                       /* src short (随便给一个) */
    out[n++] = 0x12;
    out[n++] = 0x07;                       /* cmd id 7 = Beacon Request */

    out[0] = (uint8_t)(n - 1);
    (void)pan;
    return n;
}

int zbtx_build_data(uint8_t *out, int cap, uint16_t dst_pan, uint16_t dst,
                    uint16_t src_pan, uint16_t src,
                    const uint8_t *payload, int plen, uint8_t seq)
{
    if (cap < 1 + 9 + plen) return 0;
    if (plen < 0) plen = 0;
    if (plen > ZBTX_FRAME_MAX - 10) plen = ZBTX_FRAME_MAX - 10;

    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_DATA) | FCF_DST_MODE(AM_SHORT) |
                            FCF_SRC_MODE(AM_SHORT) | FCF_PAN_COMP);
    out[n++] = seq;
    out[n++] = (uint8_t)(dst_pan & 0xFF);
    out[n++] = (uint8_t)(dst_pan >> 8);
    out[n++] = (uint8_t)(dst & 0xFF);
    out[n++] = (uint8_t)(dst >> 8);
    out[n++] = (uint8_t)(src & 0xFF);      /* 压缩位为 1: src PAN 省略, 视为与 dst 相同 */
    out[n++] = (uint8_t)(src >> 8);
    (void)src_pan;
    for (int i = 0; i < plen; i++) out[n++] = payload[i];

    out[0] = (uint8_t)(n - 1);
    return n;
}

/* 发送 */

static uint8_t s_txbuf[ZBTX_FRAME_MAX + 2];

esp_err_t zbtx_start(uint8_t ch)
{
    if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) return ESP_ERR_INVALID_ARG;
    if (atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;

    esp_err_t e = zb_radio_acquire();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "radio acquire: %s", esp_err_to_name(e));
        return e;
    }

    e = esp_ieee802154_set_channel(ch);
    if (e != ESP_OK) ESP_LOGW(TAG, "set_channel(%u): %s", ch, esp_err_to_name(e));

    /* 发完自动回 RX, 这样能收到 ACK 与 beacon request 的回应 */
    esp_ieee802154_set_rx_when_idle(true);
    e = esp_ieee802154_receive();
    if (e != ESP_OK) ESP_LOGW(TAG, "receive(): %s", esp_err_to_name(e));

    atomic_store(&s_ch, ch);
    atomic_store(&s_tx_busy, false);
    atomic_store(&s_on, true);
    ESP_LOGI(TAG, "tx ready on channel %u", ch);
    return ESP_OK;
}

esp_err_t zbtx_stop(void)
{
    if (!atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;
    if (atomic_load(&s_flood_run)) zbtx_flood_stop();
    atomic_store(&s_on, false);

    /* 引用计数归零时才真关; zbsniff 可能还在用同一射频 */
    zb_radio_release();
    ESP_LOGI(TAG, "tx closed (radio refs=%d)", zb_radio_refs());
    return ESP_OK;
}

bool     zbtx_is_on(void)    { return atomic_load(&s_on); }
uint8_t  zbtx_channel(void)  { return atomic_load(&s_ch); }
int      zbtx_last_error(void) { return atomic_load(&s_tx_err); }

int zbtx_last_ack(uint8_t *buf, int cap)
{
    int n = s_ack_len;
    if (n > 0 && buf && cap > 0) {
        if (n > cap) n = cap;
        for (int i = 0; i < n; i++) buf[i] = s_ack[i];
    }
    return s_ack_len;
}

esp_err_t zbtx_send(const uint8_t *frame, int len, uint32_t timeout_ms, bool cca)
{
    if (!atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;
    if (len <= 0 || len > ZBTX_FRAME_MAX) return ESP_ERR_INVALID_ARG;
    if (frame[0] == 0 || frame[0] > ZBTX_FRAME_MAX) return ESP_ERR_INVALID_ARG;
    if (atomic_load(&s_tx_busy)) return ESP_ERR_INVALID_STATE;

    memcpy(s_txbuf, frame, (size_t)len + 1);
    atomic_store(&s_tx_res, ESP_ERR_TIMEOUT);
    atomic_store(&s_tx_err, 0);
    atomic_store(&s_tx_busy, true);

    esp_err_t e = esp_ieee802154_transmit(s_txbuf, cca);
    if (e != ESP_OK) {
        atomic_store(&s_tx_busy, false);
        return e;
    }

    uint32_t t0 = xTaskGetTickCount();
    while (atomic_load(&s_tx_busy)) {
        if (timeout_ms == 0 ||
            (xTaskGetTickCount() - t0) >= pdMS_TO_TICKS(timeout_ms)) {
            return ESP_ERR_TIMEOUT;
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    return atomic_load(&s_tx_res);
}

/* 洪泛 */

static void flood_task(void *pv)
{
    (void)pv;
    WDT_ADD();
    uint8_t frame[64];
    while (atomic_load(&s_flood_run)) {
        int left = atomic_load(&s_flood_left);
        if (left == 0) break;
        int n = zbtx_build_beacon(frame, sizeof(frame), s_flood_pan, 0, s_seq++);
        if (n > 0) {
            esp_err_t e = zbtx_send(frame, n, 200, atomic_load(&s_flood_cca));
            if (e == ESP_OK && left > 0) atomic_store(&s_flood_left, left - 1);
        }
        WDT_RESET();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    atomic_store(&s_flood_run, false);
    s_flood_task = NULL;
    WDT_DEL();
    vTaskDelete(NULL);
}

esp_err_t zbtx_flood_start(uint8_t ch, uint16_t pan, int n, bool cca)
{
    atomic_store(&s_flood_cca, cca);
    if (atomic_load(&s_flood_run)) return ESP_ERR_INVALID_STATE;
    if (!atomic_load(&s_on)) {
        esp_err_t e = zbtx_start(ch);
        if (e != ESP_OK) return e;
    }
    s_flood_pan = pan;
    atomic_store(&s_flood_left, n);
    atomic_store(&s_flood_run, true);
    if (xTaskCreate(flood_task, "zbflood", 3072, NULL, 3, &s_flood_task) != pdPASS) {
        atomic_store(&s_flood_run, false);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t zbtx_flood_stop(void)
{
    if (!atomic_load(&s_flood_run)) return ESP_ERR_INVALID_STATE;
    atomic_store(&s_flood_run, false);
    atomic_store(&s_flood_left, 0);
    for (int i = 0; i < 50 && s_flood_task; i++) vTaskDelay(pdMS_TO_TICKS(10));
    return ESP_OK;
}

bool zbtx_flood_on(void) { return atomic_load(&s_flood_run); }

void zbtx_status(void)
{
    printf("META,ZB,TX,STATS,sent,%u,failed,%u,ch,%u,on,%d,flood,%d,lasterr,%d\n",
           (unsigned)atomic_load(&s_sent), (unsigned)atomic_load(&s_fail),
           (unsigned)atomic_load(&s_ch), zbtx_is_on() ? 1 : 0,
           zbtx_flood_on() ? 1 : 0, zbtx_last_error());
    fflush(stdout);
}

#else  /* !CONFIG_IEEE802154_ENABLED */

int zbtx_build_beacon(uint8_t *out, int cap, uint16_t pan, uint8_t ch, uint8_t seq)
{ (void)out; (void)cap; (void)pan; (void)ch; (void)seq; return 0; }
int zbtx_build_beacon_req(uint8_t *out, int cap, uint16_t pan, uint8_t seq)
{ (void)out; (void)cap; (void)pan; (void)seq; return 0; }
int zbtx_build_data(uint8_t *out, int cap, uint16_t dp, uint16_t d, uint16_t sp,
                    uint16_t s, const uint8_t *p, int pl, uint8_t seq)
{ (void)out;(void)cap;(void)dp;(void)d;(void)sp;(void)s;(void)p;(void)pl;(void)seq; return 0; }
esp_err_t zbtx_start(uint8_t ch) { (void)ch; return ESP_ERR_NOT_SUPPORTED; }
esp_err_t zbtx_stop(void) { return ESP_ERR_NOT_SUPPORTED; }
bool zbtx_is_on(void) { return false; }
uint8_t zbtx_channel(void) { return 11; }
esp_err_t zbtx_send(const uint8_t *f, int l, uint32_t t, bool c)
{ (void)f;(void)l;(void)t;(void)c; return ESP_ERR_NOT_SUPPORTED; }
int zbtx_last_error(void) { return 0; }
int zbtx_last_ack(uint8_t *b, int c) { (void)b; (void)c; return 0; }
esp_err_t zbtx_flood_start(uint8_t ch, uint16_t pan, int n, bool cca)
{ (void)ch;(void)pan;(void)n;(void)cca; return ESP_ERR_NOT_SUPPORTED; }
esp_err_t zbtx_flood_stop(void) { return ESP_ERR_NOT_SUPPORTED; }
bool zbtx_flood_on(void) { return false; }
void zbtx_status(void) { printf("META,ZB,TX,ERR,msg,not_supported\n"); fflush(stdout); }

#endif
