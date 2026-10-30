/*
 * zbsniff.c: 802.15.4 (Zigbee / Thread) 混杂嗅探实现
 *
 * 数据流 (两级缓冲, 兼顾 ISR 安全与容量):
 *   802.15.4 硬件 RX 完成 → ISR: esp_ieee802154_receive_done()
 *       └─ 只写 **内部 RAM 小暂存环** (s_stage, ~1.7KB) + receive_handle_done()
 *   zb 任务 (50ms): zb_drain() 把暂存环搬进 **PSRAM 大表** (s_tab, 512 条)
 *                   每 ~1s 打印 META,ZB,PROGRESS 进度
 *   CLI: zbsniff <ch>|stop|status|dump|clear
 *
 * 为什么要两级:
 *   ISR 上下文绝不能长时间占用, 且若此刻有 flash 写 (cap/钓鱼 HTML),
 *   cache 被关, 访问 PSRAM 会崩. 所以 ISR 只碰内部 RAM; PSRAM 读写
 *   全部交给任务上下文. 这也让内部 RAM 占用从 9KB 降到 ~1.7KB, *   之前直接放 9KB 内部 RAM 表, 直接导致 NimBLE 起不来
 *   (HCI BLE_ERR_MEM_CAPACITY).
 */
#include "zbsniff.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "out_stream.h"

/* WDT 辅助 (与 wifi_attack.c / cap.c 同款) */
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
#include "radio_arb.h"

static const char *TAG = "ZBSNIFF";

typedef struct {
    uint64_t ts;                 /* 硬件 SFD 时间戳 (原样) */
    uint8_t  len;                /* frame[0] 的值: MHR+payload 长度 (不含 FCS) */
    int8_t   rssi;
    uint8_t  lqi;
    uint8_t  channel;
    uint8_t  pad;
    uint8_t  frame[ZB_FRAME_MAX + 1];   /* 含 1 字节长度域 */
} zb_rec_t;

/* ISR 暂存环: 内部 RAM, 小 (12 * ~144B ≈ 1.7KB) */
#define ZB_STAGE_MAX 12
static zb_rec_t s_stage[ZB_STAGE_MAX];

/* 大表: PSRAM, 任务上下文访问 */
static zb_rec_t *s_tab = NULL;

static _Atomic int      s_st_head = 0;   /* 生产者: ISR 写 */
static _Atomic int      s_st_tail = 0;   /* 消费者: 任务读 */
static _Atomic uint32_t s_total   = 0;   /* 累计收帧 (含因暂存满而丢的) */
static _Atomic uint32_t s_drops   = 0;   /* 暂存环满导致的丢弃 */
static _Atomic uint32_t s_written = 0;   /* 已搬进 PSRAM 表的条数 (单调) */
static _Atomic bool     s_on      = false;
static _Atomic uint8_t  s_ch      = ZB_CH_MIN;

static TaskHandle_t s_task = NULL;
static _Atomic bool s_task_run = false;

/* 纯字节拷贝: 不用 memcpy (其可能在 flash, ISR 中不安全) */
static IRAM_ATTR void zb_copy(uint8_t *dst, const uint8_t *src, int n)
{
    for (int i = 0; i < n; i++) dst[i] = src[i];
}

/* ISR: 收帧回调 */
/* IDF 里同名函数是 weak, 这里给出强定义覆盖之. 必须 IRAM, 只碰内部 RAM. */
IRAM_ATTR void esp_ieee802154_receive_done(uint8_t *frame,
                                           esp_ieee802154_frame_info_t *frame_info)
{
    if (atomic_load(&s_on) && frame) {
        int h = atomic_load(&s_st_head);
        int t = atomic_load(&s_st_tail);
        if ((h - t) >= ZB_STAGE_MAX) {
            atomic_fetch_add(&s_drops, 1);   /* 暂存满, 丢弃 */
        } else {
            uint8_t flen = frame[0];
            if (flen > ZB_FRAME_MAX) flen = ZB_FRAME_MAX;
            zb_rec_t *d = &s_stage[h % ZB_STAGE_MAX];
            d->len     = flen;
            d->rssi    = frame_info ? frame_info->rssi : 0;
            d->lqi     = frame_info ? frame_info->lqi : 0;
            d->channel = frame_info ? frame_info->channel : (uint8_t)atomic_load(&s_ch);
            d->ts      = frame_info ? frame_info->timestamp : 0;
            zb_copy(d->frame, frame, (int)flen + 1);
            atomic_store(&s_st_head, h + 1);   /* 填好再发布 */
            atomic_fetch_add(&s_total, 1);
        }
    }
    /* 必须通知驱动释放 RX 缓冲 (ISR 内, 不可省) */
    esp_ieee802154_receive_handle_done(frame);
}

/* 任务: 搬运 + 进度 */
/* 把暂存环里的记录搬进 PSRAM 大表 (任务上下文, PSRAM 安全) */
static void zb_drain(void)
{
    if (!s_tab) return;
    int t = atomic_load(&s_st_tail);
    int h = atomic_load(&s_st_head);
    while (t != h) {
        const zb_rec_t *src = &s_stage[t % ZB_STAGE_MAX];
        uint32_t w = atomic_load(&s_written);
        memcpy(&s_tab[w % ZB_TAB_MAX], src, sizeof(zb_rec_t));
        atomic_store(&s_written, w + 1);
        t++;
    }
    atomic_store(&s_st_tail, t);
}

static void zb_task(void *pv)
{
    (void)pv;
    WDT_ADD();
    int ticks = 0;
    uint32_t last = UINT32_MAX;
    while (atomic_load(&s_task_run)) {
        vTaskDelay(pdMS_TO_TICKS(50));
        WDT_RESET();
        zb_drain();
        if (++ticks >= 20) {          /* 每 ~1s 报一次进度 */
            ticks = 0;
            uint32_t tt = atomic_load(&s_total);
            if (tt != last) {
                last = tt;
                printf("META,ZB,PROGRESS,total,%u,frames,%d,drops,%u,channel,%u\n",
                       (unsigned)tt, zbsniff_count(),
                       (unsigned)atomic_load(&s_drops), (unsigned)atomic_load(&s_ch));
                fflush(stdout);
                char evt[112];
                snprintf(evt, sizeof(evt),
                         "META,ZB,PROGRESS,total,%u,frames,%d,drops,%u,channel,%u",
                         (unsigned)tt, zbsniff_count(),
                         (unsigned)atomic_load(&s_drops), (unsigned)atomic_load(&s_ch));
                out_raw(evt);
            }
        }
    }
    zb_drain();                        /* 收尾搬运 */
    s_task = NULL;
    WDT_DEL();
    vTaskDelete(NULL);
}

/* 射频引用计数, zbsniff 与 zbtx 共用 */
static _Atomic int s_radio_refs = 0;

esp_err_t zb_radio_acquire(void)
{
    if (atomic_fetch_add(&s_radio_refs, 1) > 0) return ESP_OK;   /* 别人已经开过 */

    esp_err_t e = esp_ieee802154_enable();
    if (e != ESP_OK) {
        atomic_fetch_sub(&s_radio_refs, 1);
        return e;
    }
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);
    radio_acquire(RES_15_4, "154", 0);
    return ESP_OK;
}

void zb_radio_release(void)
{
    int left = atomic_fetch_sub(&s_radio_refs, 1) - 1;
    if (left > 0) return;                    /* 还有使用者, 射频不能关 */
    radio_release(RES_15_4);

    if (left < 0) {                          /* 防御: 多 release 会把 refs 压成负数 */
        atomic_store(&s_radio_refs, 0);
        return;
    }
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_set_promiscuous(false);
    esp_ieee802154_disable();
}

int zb_radio_refs(void) { return atomic_load(&s_radio_refs); }

esp_err_t zbsniff_start(uint8_t channel)
{
    if (channel < ZB_CH_MIN || channel > ZB_CH_MAX) return ESP_ERR_INVALID_ARG;
    if (atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;

    if (!s_tab) {
        s_tab = heap_caps_calloc(ZB_TAB_MAX, sizeof(zb_rec_t),
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_tab) {
            ESP_LOGE(TAG, "PSRAM table alloc failed (%u B)",
                     (unsigned)(ZB_TAB_MAX * sizeof(zb_rec_t)));
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t e = zb_radio_acquire();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "radio acquire failed: %s", esp_err_to_name(e));
        return e;
    }

    /* 清空计数 (先清后开) */
    atomic_store(&s_st_head, 0);
    atomic_store(&s_st_tail, 0);
    atomic_store(&s_written, 0);
    atomic_store(&s_total, 0);
    atomic_store(&s_drops, 0);
    atomic_store(&s_ch, channel);

    e = esp_ieee802154_set_channel(channel);
    if (e != ESP_OK) ESP_LOGW(TAG, "set_channel(%u): %s", channel, esp_err_to_name(e));

    esp_ieee802154_set_promiscuous(true);   /* 收所有帧, 不做地址过滤 */
    esp_ieee802154_set_rx_when_idle(true);  /* 空闲自动续收, 免 ISR 重挂 */

    atomic_store(&s_on, true);

    e = esp_ieee802154_receive();           /* 首次进入接收态 */
    if (e != ESP_OK) ESP_LOGW(TAG, "receive() = %s (rx_when_idle 仍会接收)", esp_err_to_name(e));

    if (!atomic_load(&s_task_run)) {
        atomic_store(&s_task_run, true);
        if (xTaskCreate(zb_task, "zb", 3584, NULL, 3, &s_task) != pdPASS) {
            atomic_store(&s_task_run, false);
            ESP_LOGW(TAG, "task create failed");
        }
    }

    ESP_LOGI(TAG, "started on 802.15.4 channel %u", channel);
    return ESP_OK;
}

esp_err_t zbsniff_stop(void)
{
    if (!atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;

    atomic_store(&s_on, false);
    atomic_store(&s_task_run, false);

    /* 引用计数归零时才真关; zbtx 可能还在用同一射频 */
    zb_radio_release();

    ESP_LOGI(TAG, "stopped (total=%u drops=%u)",
             (unsigned)atomic_load(&s_total), (unsigned)atomic_load(&s_drops));

    /* PSRAM 表 (512 * 141B ≈ 72KB) 停就还回去. 留着复用能省一次分配,
     * 但 health 看到的堆水位会一直低着, 排查内存问题时先得知道它在谁手上. */
    if (s_tab) {
        free(s_tab);
        s_tab = NULL;
    }
    atomic_store(&s_st_head, 0);
    atomic_store(&s_st_tail, 0);
    atomic_store(&s_written, 0);
    atomic_store(&s_total, 0);
    atomic_store(&s_drops, 0);

    return ESP_OK;
}

bool zbsniff_is_on(void)     { return atomic_load(&s_on); }
uint32_t zbsniff_total(void) { return atomic_load(&s_total); }

int zbsniff_count(void)
{
    uint32_t w = atomic_load(&s_written);
    return w < ZB_TAB_MAX ? (int)w : ZB_TAB_MAX;
}

void zbsniff_clear(void)
{
    atomic_store(&s_st_head, 0);
    atomic_store(&s_st_tail, 0);
    atomic_store(&s_written, 0);
    atomic_store(&s_total, 0);
    atomic_store(&s_drops, 0);
}

int zbsniff_get(int i, uint8_t *out, int out_max, int8_t *rssi,
                uint8_t *lqi, uint8_t *channel, uint64_t *ts)
{
    if (i < 0 || !s_tab) return 0;
    uint32_t w = atomic_load(&s_written);
    int valid = w < ZB_TAB_MAX ? (int)w : ZB_TAB_MAX;
    if (i >= valid) return 0;

    uint32_t base = (w > ZB_TAB_MAX) ? (w - ZB_TAB_MAX) : 0;
    const zb_rec_t *r = &s_tab[(base + (uint32_t)i) % ZB_TAB_MAX];

    int n = (int)r->len + 1;
    if (n > out_max) n = out_max;
    if (out) memcpy(out, r->frame, (size_t)n);
    if (rssi)    *rssi = r->rssi;
    if (lqi)     *lqi = r->lqi;
    if (channel) *channel = r->channel;
    if (ts)      *ts = r->ts;
    return (int)r->len + 1;
}

void zbsniff_status(void)
{
    printf("META,ZB,STATUS,on,%d,channel,%u,total,%u,frames,%d,drops,%u,cap,%d\n",
           atomic_load(&s_on) ? 1 : 0,
           (unsigned)atomic_load(&s_ch),
           (unsigned)atomic_load(&s_total),
           zbsniff_count(), (unsigned)atomic_load(&s_drops), ZB_TAB_MAX);
    fflush(stdout);
}

#else  /* !CONFIG_IEEE802154_ENABLED, 组件未编译时给出明确提示 */

esp_err_t zbsniff_start(uint8_t channel) { (void)channel; return ESP_ERR_NOT_SUPPORTED; }
esp_err_t zbsniff_stop(void)             { return ESP_ERR_NOT_SUPPORTED; }
bool      zbsniff_is_on(void)            { return false; }
uint32_t  zbsniff_total(void)            { return 0; }
int       zbsniff_count(void)            { return 0; }
void      zbsniff_clear(void)            { }
int zbsniff_get(int i, uint8_t *o, int m, int8_t *r, uint8_t *l, uint8_t *c, uint64_t *t)
{ (void)i;(void)o;(void)m;(void)r;(void)l;(void)c;(void)t; return 0; }
void zbsniff_status(void)
{
    printf("META,ZB,ERR,msg,ieee802154_disabled (CONFIG_IEEE802154_ENABLED=n)\n");
    fflush(stdout);
}

#endif
