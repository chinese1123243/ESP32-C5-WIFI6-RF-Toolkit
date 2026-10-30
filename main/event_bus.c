/* event_bus.c: 统一事件总线实现 */
#include "event_bus.h"
#include "out_stream.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

static const char *TAG = "EVT";

typedef struct {
    uint32_t seq;
    char     topic[EVENT_TOPIC_LEN];
    char     msg[EVENT_TEXT_LEN];
} ev_rec_t;

typedef struct {
    bool       used;
    char       prefix[EVENT_TOPIC_LEN];
    event_cb_t cb;
    void      *ctx;
} sub_t;

static ev_rec_t         *s_ring = NULL;   /* PSRAM: 内部 RAM 要留给 NimBLE */
static int               s_head  = 0;      /* 下一个写入位置 */
static int               s_count = 0;      /* 已填充条数 */
static uint32_t          s_seq   = 0;
static SemaphoreHandle_t s_mtx   = NULL;
static sub_t             s_subs[EVENT_SUBS_MAX];

esp_err_t event_bus_init(void)
{
    if (!s_mtx) s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx) return ESP_ERR_NO_MEM;
    if (!s_ring) {
        s_ring = heap_caps_calloc(EVENT_RING_LEN, sizeof(ev_rec_t),
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_ring) return ESP_ERR_NO_MEM;
    }
    memset(s_ring, 0, EVENT_RING_LEN * sizeof(ev_rec_t));
    memset(s_subs, 0, sizeof(s_subs));
    s_head = s_count = 0; s_seq = 0;
    ESP_LOGI(TAG, "event bus ready (ring=%d, subs=%d)", EVENT_RING_LEN, EVENT_SUBS_MAX);
    return ESP_OK;
}

static void sanitize(char *s)
{
    for (; *s; s++) {
        if (*s == '\r' || *s == '\n' || *s == ',') *s = ' ';   /* 行/字段分隔符会破坏解析 */
    }
}

void event_publish(const char *topic, const char *fmt, ...)
{
    if (!topic || !*topic) return;

    char msg[EVENT_TEXT_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    sanitize(msg);

    /* 1) 入环 (拿不到锁就丢, 不阻塞驱动任务) */
    if (s_ring && s_mtx && xSemaphoreTake(s_mtx, pdMS_TO_TICKS(10)) == pdTRUE) {
        ev_rec_t *r = &s_ring[s_head];
        r->seq = ++s_seq;
        snprintf(r->topic, sizeof(r->topic), "%s", topic);
        snprintf(r->msg, sizeof(r->msg), "%s", msg);
        s_head = (s_head + 1) % EVENT_RING_LEN;
        if (s_count < EVENT_RING_LEN) s_count++;
        xSemaphoreGive(s_mtx);
    }

    /* 2) 订阅者分发 */
    for (int i = 0; i < EVENT_SUBS_MAX; i++) {
        if (!s_subs[i].used) continue;
        if (s_subs[i].prefix[0] && strncmp(topic, s_subs[i].prefix, strlen(s_subs[i].prefix)) != 0) continue;
        s_subs[i].cb(topic, msg, s_subs[i].ctx);
    }

    /* 3) BLE 通道 (排队, 自带限速) */
    char line[EVENT_TOPIC_LEN + EVENT_TEXT_LEN + 2];
    snprintf(line, sizeof(line), "%s,%s", topic, msg);
    out_raw(line);
}

int event_subscribe(const char *prefix, event_cb_t cb, void *ctx)
{
    if (!cb) return -1;
    for (int i = 0; i < EVENT_SUBS_MAX; i++) {
        if (s_subs[i].used) continue;
        s_subs[i].used = true;
        s_subs[i].cb = cb;
        s_subs[i].ctx = ctx;
        s_subs[i].prefix[0] = '\0';
        if (prefix) snprintf(s_subs[i].prefix, sizeof(s_subs[i].prefix), "%s", prefix);
        return i;
    }
    return -1;
}

void event_unsubscribe(int id)
{
    if (id >= 0 && id < EVENT_SUBS_MAX) s_subs[id].used = false;
}

static int json_escape(const char *src, char *dst, size_t cap)
{
    size_t o = 0;
    for (; *src && o + 2 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c < 0x20)          { dst[o++] = ' '; }
        else                        { dst[o++] = (char)c; }
    }
    dst[o] = '\0';
    return (int)o;
}

int event_snapshot_json(char *buf, size_t cap, int limit)
{
    if (!buf || cap < 32 || !s_ring) return 0;
    if (limit <= 0) limit = 10;
    if (limit > EVENT_RING_LEN) limit = EVENT_RING_LEN;

    int n = s_count < limit ? s_count : limit;
    int o = snprintf(buf, cap, "{\"ok\":true,\"total\":%u,\"events\":[",
                     (unsigned)s_seq);
    /* 从最新往前取 */
    for (int k = 0; k < n && (size_t)o + 64 < cap; k++) {
        int idx = (s_head - 1 - k + EVENT_RING_LEN * 2) % EVENT_RING_LEN;
        ev_rec_t *r = &s_ring[idx];
        char msg[EVENT_TEXT_LEN * 2];
        json_escape(r->msg, msg, sizeof(msg));
        o += snprintf(buf + o, cap - (size_t)o,
                      "%s{\"seq\":%u,\"topic\":\"%s\",\"msg\":\"%s\"}",
                      k ? "," : "", (unsigned)r->seq, r->topic, msg);
    }
    o += snprintf(buf + o, cap - (size_t)o, "]}");
    return o;
}

unsigned event_total(void)    { return (unsigned)s_seq; }
int      event_buffered(void) { return s_count; }
