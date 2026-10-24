/*
 * cap.c: 原始 802.11 帧落盘 / EAPOL+PMKID 过滤 / 分段拉取
 *
 * 数据流:
 *   wifi_sniff_cb (WiFi 驱动任务)
 *        └─ cap_feed():  分类打标 + memcpy 进 PSRAM 暂存环   [绝不碰 flash]
 *   cap_flush_task (低优先级)
 *        └─ 暂存环 -> pcap 记录 -> 4KB 写缓冲 -> 惰性擦除 -> flash
 *
 * 为什么必须这么绕:
 *   混杂回调在 WiFi 驱动任务上下文里跑, 一旦在里面做 flash 擦写 (几十到几百毫秒),
 *   WiFi 驱动会被自己阻塞, 整机假死 (这个坑之前踩过). 所以回调只做纯内存拷贝,
 *   落盘交给独立任务.
 */
#include "cap.h"
#include "radio_common.h"
#include "ble_cli.h"
#include "config.h"   /* 记录当前段号 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

/* 受控看门狗辅助 : flusher 任务自订阅 + 循环喂狗 */
#if CONFIG_ESP_TASK_WDT_EN
#include "esp_task_wdt.h"
#define WDT_ADD()    do { esp_task_wdt_add(NULL); } while (0)
#define WDT_RESET()  do { esp_task_wdt_reset(); } while (0)
#else
#define WDT_ADD()    do { } while (0)
#define WDT_RESET()  do { } while (0)
#endif

static const char *TAG = "CAP";

/* pcap 全局头: magic + v2.4 + thiszone/sigfigs + snaplen + LINKTYPE_IEEE802_11 */
#define PCAP_MAGIC   0xa1b2c3d4u
#define PCAP_LINKTYPE_IEEE802_11  105

/* 暂存环 (PSRAM). 只做一次 memcpy, 交给 flusher 落盘. */
#define STAGE_BYTES   (384 * 1024)
/* 落盘写缓冲: 攒够再一次性写, 减少 flash 调用次数 */
#define WBUF_BYTES    4096
/* 惰性擦除粒度 */
#define ERASE_CHUNK   (64 * 1024)

typedef struct {
    uint64_t ts_us;      /* esp_timer 微秒 */
    uint16_t len;        /* 帧长 */
    int8_t   rssi;
    uint8_t  chan;
    uint8_t  flags;      /* CAP_K_* */
    uint8_t  pad[3];
} stage_hdr_t;           /* 16 字节, 天然对齐 */

typedef struct {
    uint8_t  kind;
    int8_t   rssi;
    uint8_t  chan;
    uint8_t  pad;
    uint32_t rec_off;    /* 该记录在 pcap 文件中的偏移 (含 24B 全局头) */
    uint32_t rec_len;    /* 记录总长 (16B 记录头 + 对齐后的帧) */
    uint32_t ts_ms;      /* 开机以来毫秒, 便于展示 */
} key_ent_t;

static const esp_partition_t *s_part = NULL;
static uint32_t s_pcap_off = 0;      /* pcap 区在分区内的起始偏移 */
static uint32_t s_capacity = 0;      /* pcap 区可用字节数 */

/* storage 磨损均衡
 * 原来每次 cap start 都从 storage+1MB 处重写, 反复擦同一批扇区.
 * 现在把抓包区分成 N 个 512KB 段, 每次开会话轮转到下一段, 段号记 NVS,
 * 断电重启也能接着轮. 代价: 上一次的 pcap 不再可直接读 (工具里 pcap 本就是
 * 一次性的), 换来擦写均匀分布到 8MB 上. */
#define CAP_SEG_BYTES (512 * 1024)
static int s_seg_idx = 0;
static int s_seg_cnt = 1;

static volatile bool s_on = false;
static volatile bool s_key_only = false;
static volatile bool s_full = false;

static uint32_t s_flushed = 0;       /* 已经落到 flash 的字节数 */
static uint32_t s_erased_upto = 0;   /* [0, s_erased_upto) 已擦干净 */
/* 写缓冲必须留在内部 RAM: esp_partition_write 期间 flash cache 会被关掉,
 * 放在 PSRAM 的数据可能读不到. 4KB 内部 RAM 换安全, 值. */
static uint8_t  s_wbuf[WBUF_BYTES];
static int      s_wbuf_len = 0;

static volatile uint32_t s_frames = 0;
static volatile uint32_t s_drops = 0;

/* 关键帧索引: 512*20B 放 PSRAM, 给内部 RAM 腾地方 (内部 RAM 紧张会导致
 * xTaskCreate(cli) 失败, 整机没有 REPL). */
static key_ent_t *s_keys = NULL;
static volatile uint32_t s_key_cnt = 0;     /* 累计 (含被挤掉的) */
static uint32_t s_key_head = 0;

/* PSRAM 暂存环: 单生产 (WiFi 任务) 单消费 (flusher) */
static uint8_t *s_stage = NULL;
static volatile uint32_t s_st_head = 0, s_st_tail = 0;

static TaskHandle_t s_flush_task = NULL;


static inline uint32_t align4(uint32_t v) { return (v + 3u) & ~3u; }

void cap_pcap_header(uint8_t *dst)
{
    uint32_t v32;
    uint16_t v16;
    int o = 0;
    v32 = PCAP_MAGIC;           memcpy(dst + o, &v32, 4); o += 4;
    v16 = 2;                    memcpy(dst + o, &v16, 2); o += 2;
    v16 = 4;                    memcpy(dst + o, &v16, 2); o += 2;
    v32 = 0;                    memcpy(dst + o, &v32, 4); o += 4;   /* thiszone */
    v32 = 0;                    memcpy(dst + o, &v32, 4); o += 4;   /* sigfigs  */
    v32 = 65535;                memcpy(dst + o, &v32, 4); o += 4;   /* snaplen  */
    v32 = PCAP_LINKTYPE_IEEE802_11;
    memcpy(dst + o, &v32, 4);
}

/* 保证 [0, upto) 已擦除; 按 ERASE_CHUNK 分块, 块间让路 */
static esp_err_t ensure_erased(uint32_t upto)
{
    if (!s_part) return ESP_ERR_INVALID_STATE;
    if (upto > s_capacity) upto = s_capacity;
    upto = (upto + 4095u) & ~4095u;             /* 向上取整到扇区 */
    while (s_erased_upto < upto) {
        uint32_t end = s_erased_upto + ERASE_CHUNK;
        if (end > upto) end = upto;
        esp_err_t e = esp_partition_erase_range(s_part, s_pcap_off + s_erased_upto,
                                                end - s_erased_upto);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "erase @%u failed: %s", (unsigned)s_erased_upto, esp_err_to_name(e));
            return e;
        }
        s_erased_upto = end;
        vTaskDelay(1);                          /* 别把 CPU 占死 */
    }
    return ESP_OK;
}

static esp_err_t wbuf_flush(void)
{
    if (s_wbuf_len <= 0 || !s_part) return ESP_OK;
    uint32_t len = (uint32_t)s_wbuf_len;        /* 始终是 4 的倍数 */
    if (ensure_erased(s_flushed + len) != ESP_OK) {
        s_wbuf_len = 0;
        return ESP_FAIL;
    }
    esp_err_t e = esp_partition_write(s_part, s_pcap_off + s_flushed, s_wbuf, len);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "write @%u len=%u failed: %s", (unsigned)s_flushed, (unsigned)len,
                 esp_err_to_name(e));
        s_wbuf_len = 0;
        return e;
    }
    s_flushed += len;
    s_wbuf_len = 0;
    return ESP_OK;
}

/* 分类 (回调热路径, 只做字节比较) */

static uint8_t classify(const uint8_t *f, int len)
{
    if (len < 24) return 0;
    uint8_t ftype = (uint8_t)((f[0] >> 2) & 0x3);
    uint8_t fsub  = (uint8_t)((f[0] >> 4) & 0xF);

    if (ftype == FC_TYPE_MGMT) {
        return (fsub == 0xC) ? CAP_K_DEAUTH : 0;      /* Deauth */
    }
    if (ftype != FC_TYPE_DATA) return 0;

    /* LLC/SNAP 起点: 24B MAC 头 + QoS(2, 若 subtype bit3) + HT control(4, 若 Order) */
    int off = 24;
    if (fsub & 0x08) off += 2;
    if (f[1] & 0x80) off += 4;
    if (off + 8 > len) return 0;
    if (f[off] != 0xAA || f[off + 1] != 0xAA || f[off + 2] != 0x03) return 0;
    if (!((f[off + 6] == 0x88) && (f[off + 7] == 0x8E))) return 0;   /* EAPOL */

    uint8_t flags = CAP_K_EAPOL;
    int eo = off + 8;                                  /* EAPOL 帧起点 */
    if (eo + 5 > len) return flags;
    if (f[eo + 1] != 3) return flags;                  /* 只关心 EAPOL-Key */
    flags |= CAP_K_EAPOLKEY;

    /* Key Information 是 16 位大端 */
    if (eo + 6 >= len) return flags;
    uint16_t ki = (uint16_t)((f[eo + 5] << 8) | f[eo + 6]);
    /* 4 次握手 msg1: ACK=1, MIC=0, INSTALL=0, SECURE=0 */
    if (!(ki & 0x0080) || (ki & 0x0008) || (ki & 0x0040) || (ki & 0x0200)) return flags;

    /* Key Data 起点 = EAPOL 头(4) + EAPOL-Key 固定部分(95) */
    int kdo = eo + 99;
    if (kdo + 2 > len) return flags;
    int p = kdo;
    while (p + 2 <= len) {
        uint8_t t = f[p], kl = f[p + 1];
        if (p + 2 + kl > len) break;
        /* PMKID KDE: DD len 00-0F-AC 04 */
        if (t == 0xDD && kl >= 5 && f[p + 2] == 0x00 && f[p + 3] == 0x0F &&
            f[p + 4] == 0xAC && f[p + 5] == 0x04) {
            flags |= CAP_K_PMKID;
            break;
        }
        p += 2 + kl;
    }
    return flags;
}

/* 投喂 (WiFi 驱动任务上下文) */

/* 暂存环支持记录跨尾: 生产/消费两侧都按"环位置 + 长度"搬运, 分两段处理.
 * (之前遇到跨尾就丢帧, 而 head 不前进 → 之后每一帧都被丢, 抓包会永久卡死.) */
static inline void ring_put(uint32_t pos, const uint8_t *src, uint32_t n)
{
    pos %= STAGE_BYTES;
    uint32_t first = STAGE_BYTES - pos;
    if (n <= first) { memcpy(s_stage + pos, src, n); return; }
    memcpy(s_stage + pos, src, first);
    memcpy(s_stage, src + first, n - first);
}

static inline void ring_get(uint32_t pos, uint8_t *dst, uint32_t n)
{
    pos %= STAGE_BYTES;
    uint32_t first = STAGE_BYTES - pos;
    if (n <= first) { memcpy(dst, s_stage + pos, n); return; }
    memcpy(dst, s_stage + pos, first);
    memcpy(dst + first, s_stage, n - first);
}

void cap_feed(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t chan)
{
    if (!s_on || !s_stage || s_full) return;
    if (!frame || len == 0 || len > CAP_MAX_FRAME) return;
    /* FULL 帧 (FCS 失败) 已在调用侧过滤 */

    uint8_t flags = classify(frame, len);
    if (s_key_only && !(flags & (CAP_K_EAPOL | CAP_K_PMKID | CAP_K_DEAUTH))) return;

    uint32_t need = (uint32_t)sizeof(stage_hdr_t) + len;
    uint32_t head = s_st_head, tail = s_st_tail;
    if ((head - tail) + need > STAGE_BYTES) { s_drops++; return; }

    stage_hdr_t h;
    h.ts_us = (uint64_t)esp_timer_get_time();
    h.len = len;
    h.rssi = rssi;
    h.chan = chan;
    h.flags = flags;
    memset(h.pad, 0, sizeof(h.pad));

    ring_put(head, (const uint8_t *)&h, sizeof(h));
    ring_put(head + (uint32_t)sizeof(h), frame, len);

    s_st_head = head + need;      /* 最后发布, 保证消费者看到完整数据 */
}


static void push_key_event(const key_ent_t *k)
{
    static int64_t last_ms = 0;
    int64_t now = esp_timer_get_time() / 1000;
    if (now - last_ms < 200) return;      /* 限速, 别把 BLE 打满 */
    last_ms = now;

    char buf[192];
    snprintf(buf, sizeof(buf),
             "META,CAP,KEY,kind,%u,off,%u,len,%u,ts,%u,chan,%u,rssi,%d",
             (unsigned)k->kind, (unsigned)k->rec_off,
             (unsigned)k->rec_len, (unsigned)k->ts_ms,
             (unsigned)k->chan, (int)k->rssi);
    ble_event_post(buf);
}

static void index_key(const stage_hdr_t *h, uint32_t rec_off, uint32_t rec_len)
{
    if (!s_keys) return;
    key_ent_t *k = &s_keys[s_key_head % CAP_KEY_MAX];
    s_key_head++;
    s_key_cnt++;
    k->kind = h->flags;
    k->rssi = h->rssi;
    k->chan = h->chan;
    k->pad = 0;
    k->rec_off = rec_off;
    k->rec_len = rec_len;
    k->ts_ms = (uint32_t)(h->ts_us / 1000);
    if (h->flags & (CAP_K_EAPOL | CAP_K_PMKID | CAP_K_DEAUTH)) push_key_event(k);
}

/* 把暂存区里的一条编码成 pcap 记录塞进写缓冲. body_pos 是帧体在环里的位置. */
static bool append_rec(const stage_hdr_t *h, uint32_t body_pos)
{
    uint32_t plen = align4(h->len);
    uint32_t need = 16 + plen;
    if (need > WBUF_BYTES) return false;

    if (s_wbuf_len + (int)need > WBUF_BYTES) {
        if (wbuf_flush() != ESP_OK) return false;
    }
    /* 容量检查 (用落盘后总长) */
    if (s_flushed + (uint32_t)s_wbuf_len + need > s_capacity) {
        s_full = true;
        return false;
    }

    uint32_t rec_off = s_flushed + (uint32_t)s_wbuf_len;
    uint64_t sec = h->ts_us / 1000000ull;
    uint32_t usec = (uint32_t)(h->ts_us % 1000000ull);

    uint8_t *w = s_wbuf + s_wbuf_len;
    uint32_t v;
    v = (uint32_t)sec;    memcpy(w + 0, &v, 4);
    v = usec;             memcpy(w + 4, &v, 4);
    v = h->len;           memcpy(w + 8, &v, 4);     /* incl_len (不含填充) */
    v = h->len;           memcpy(w + 12, &v, 4);    /* orig_len */
    ring_get(body_pos, w + 16, h->len);
    if (plen > h->len) memset(w + 16 + h->len, 0, plen - h->len);   /* 对齐填充 */

    s_wbuf_len += (int)need;
    s_frames++;

    if (h->flags & (CAP_K_EAPOL | CAP_K_PMKID | CAP_K_DEAUTH | CAP_K_EAPOLKEY)) {
        index_key(h, rec_off, need);
    }
    return true;
}

static void cap_flush_task(void *pv)
{
    (void)pv;
    WDT_ADD();
    while (1) {
        if (!s_on || !s_stage) { vTaskDelay(pdMS_TO_TICKS(60)); WDT_RESET(); continue; }

        int did = 0;
        while (did < 96) {
            uint32_t head = s_st_head, tail = s_st_tail;
            if (tail == head) break;

            stage_hdr_t h;
            ring_get(tail, (uint8_t *)&h, sizeof(h));
            if (h.len == 0 || h.len > CAP_MAX_FRAME) { s_st_tail = tail + sizeof(h); continue; }

            if (!append_rec(&h, tail + (uint32_t)sizeof(h))) {
                /* 写满或写失败: 把剩余暂存直接丢弃, 避免死循环 */
                s_st_tail = head;
                break;
            }
            s_st_tail = tail + sizeof(h) + h.len;
            did++;
        }

        if (did) vTaskDelay(1);
        else     vTaskDelay(pdMS_TO_TICKS(20));
        WDT_RESET();
    }
}


esp_err_t cap_init(void)
{
    if (s_part) return ESP_OK;

    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "storage");
    if (!s_part) {
        ESP_LOGW(TAG, "storage partition not found, capture disabled");
        return ESP_ERR_NOT_FOUND;
    }
    if (s_part->size <= CAP_HTML_RESERVE + 64 * 1024) {
        ESP_LOGW(TAG, "storage too small for capture area");
        s_part = NULL;
        return ESP_ERR_INVALID_SIZE;
    }
    {
        uint32_t area = s_part->size - CAP_HTML_RESERVE;
        s_seg_cnt = (int)(area / CAP_SEG_BYTES);
        if (s_seg_cnt < 1) s_seg_cnt = 1;
        s_pcap_off = CAP_HTML_RESERVE;
        s_capacity = (s_seg_cnt == 1) ? area : CAP_SEG_BYTES;
    }

    s_stage = heap_caps_malloc(STAGE_BYTES, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_stage) {
        ESP_LOGW(TAG, "stage alloc failed, capture disabled");
        s_part = NULL;
        return ESP_ERR_NO_MEM;
    }

    s_keys = heap_caps_calloc(CAP_KEY_MAX, sizeof(key_ent_t),
                              MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_keys) {
        s_keys = calloc(CAP_KEY_MAX, sizeof(key_ent_t));   /* 兜底内部 RAM */
    }
    if (!s_keys) ESP_LOGW(TAG, "key index alloc failed (关键帧索引不可用)");

    if (xTaskCreate(cap_flush_task, "cap_flush", 3072, NULL, 3, &s_flush_task) != pdPASS) {
        ESP_LOGE(TAG, "flush task create failed");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ready: area=%u B @0x%08x (+%u), stage=%u B PSRAM",
             (unsigned)s_capacity, (unsigned)(s_part->address + s_pcap_off),
             (unsigned)s_pcap_off, (unsigned)STAGE_BYTES);
    return ESP_OK;
}

esp_err_t cap_start(bool key_only)
{
    if (!s_part) {
        esp_err_t e = cap_init();
        if (e != ESP_OK) return e;
    }
    if (s_on) cap_stop();

    /* 轮转到下一段 (段号存 NVS, 重启不掉) */
    {
        const char *v = config_get("cap_seg");
        int cur = v ? atoi(v) : 0;
        if (cur < 0 || cur >= s_seg_cnt) cur = 0;
        s_seg_idx = (cur + 1) % s_seg_cnt;
        char buf[12];
        snprintf(buf, sizeof(buf), "%d", s_seg_idx);
        config_set("cap_seg", buf);
        s_pcap_off = CAP_HTML_RESERVE + (uint32_t)s_seg_idx * CAP_SEG_BYTES;
        s_capacity = (s_seg_cnt == 1)
                   ? (s_part->size - CAP_HTML_RESERVE)
                   : CAP_SEG_BYTES;
    }

    s_drops = 0; s_frames = 0;
    s_key_cnt = 0; s_key_head = 0;
    s_flushed = 0; s_erased_upto = 0; s_full = false;
    s_st_head = s_st_tail = 0;
    s_wbuf_len = 0;
    s_key_only = key_only;

    /* 先把 pcap 全局头放进写缓冲, 首次 flush 时会连带擦除扇区 */
    cap_pcap_header(s_wbuf);
    s_wbuf_len = CAP_PCAP_HDR;

    s_on = true;
    ESP_LOGI(TAG, "capture started (key_only=%d)", (int)key_only);
    return ESP_OK;
}

esp_err_t cap_stop(void)
{
    if (!s_on) return ESP_ERR_INVALID_STATE;
    s_on = false;
    vTaskDelay(pdMS_TO_TICKS(80));      /* 让 flusher 收尾 */
    wbuf_flush();
    ESP_LOGI(TAG, "capture stopped: frames=%u drops=%u bytes=%u keys=%u",
             (unsigned)s_frames, (unsigned)s_drops, (unsigned)s_flushed, (unsigned)s_key_cnt);
    return ESP_OK;
}

void cap_clear(void)
{
    if (s_on) cap_stop();
    s_flushed = 0; s_erased_upto = 0; s_wbuf_len = 0;
    s_full = false; s_frames = 0; s_drops = 0;
    s_key_cnt = 0; s_key_head = 0;
    s_st_head = s_st_tail = 0;
}

bool     cap_is_on(void)      { return s_on; }
bool     cap_key_only(void)   { return s_key_only; }
bool     cap_is_full(void)    { return s_full; }
uint32_t cap_frames(void)     { return s_frames; }
uint32_t cap_drops(void)      { return s_drops; }
uint32_t cap_key_count(void)  { return s_keys ? (s_key_cnt < CAP_KEY_MAX ? s_key_cnt : CAP_KEY_MAX) : 0; }
uint32_t cap_capacity(void)   { return s_capacity; }

uint32_t cap_pcap_size(void)
{
    if (s_wbuf_len > 0) wbuf_flush();
    return s_flushed;
}

int cap_key_get(uint32_t i, uint8_t *kind_out, uint32_t *off_out,
                uint32_t *len_out, uint32_t *ts_ms_out,
                uint8_t *chan_out, int8_t *rssi_out)
{
    uint32_t n = cap_key_count();
    if (i >= n) return -1;
    /* 环形: 最旧一条的下标 */
    uint32_t first = (s_key_cnt > CAP_KEY_MAX) ? (s_key_head % CAP_KEY_MAX) : 0;
    key_ent_t *k = &s_keys[(first + i) % CAP_KEY_MAX];
    if (kind_out) *kind_out = k->kind;
    if (off_out)  *off_out  = k->rec_off;
    if (len_out)  *len_out  = k->rec_len;
    if (ts_ms_out) *ts_ms_out = k->ts_ms;
    if (chan_out) *chan_out = k->chan;
    if (rssi_out) *rssi_out = k->rssi;
    return 0;
}

int cap_read(uint32_t off, uint8_t *dst, uint32_t len)
{
    if (!s_part || !dst) return -1;
    uint32_t size = cap_pcap_size();        /* 内部会先 flush */
    if (off >= size) return 0;
    uint32_t n = len;
    if (off + n > size) n = size - off;
    if (esp_partition_read(s_part, s_pcap_off + off, dst, n) != ESP_OK) return -1;
    return (int)n;
}

/* 当前段信息 (供 cap info / 上层展示) */
int cap_segment_index(void) { return s_seg_idx; }
int cap_segment_count(void) { return s_seg_cnt; }
