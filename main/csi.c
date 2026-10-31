/*
 * csi.c: Wi-Fi CSI 采集 + 幅度域动作检测
 *
 * 回调跑在 Wi-Fi 驱动任务里, 只做一次 memcpy 进 PSRAM 环; 解析、开方、
 * 打印全部放在独立任务. 跟 cap.c 是同一个坑: 在回调里 printf 或做浮点运算
 * 会把驱动任务拖住, 整机假死.
 *
 * 指标: 相邻两帧同一子载波的幅度绝对差, 对子载波取平均.
 *   静止时这个值只剩噪声底, 人走动时多径变化快, 会明显抬高.
 *   基线用慢速 EMA 跟踪, 判定用 metric > base * K 且 metric > 绝对下限,
 *   避免安静环境下 base 趋近 0 导致噪声也触发.
 */
#include "csi.h"
#include "csi_det.h"
#include "radio_common.h"
#include "wifi_attack.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "radio_arb.h"

static const char *TAG = "CSI";

#define CSI_MAX_LEN       256
#define CSI_RING_ENTRIES  256
#define CSI_MAX_SUB       128      /* 256 字节 = 128 对 I/Q */
#define CSI_SAMPLE_EVERY  10
#define CSI_MOTION_K      2.0f
#define CSI_MOTION_FLOOR  0.15f

typedef struct {
    uint32_t ts_us;
    int8_t   rssi;
    uint8_t  chan;
    uint8_t  len;        /* 有效 CSI 字节数 */
    uint8_t  flags;      /* bit0: first_word_invalid */
    uint8_t  mac[6];
    uint8_t  pad[2];
    uint8_t  data[CSI_MAX_LEN];
} csi_ent_t;

static csi_ent_t *s_ring = NULL;
static _Atomic uint32_t s_head = 0, s_tail = 0;
static volatile uint32_t s_dropped = 0;
static volatile bool     s_on = false;
static TaskHandle_t      s_task = NULL;
static uint8_t           s_ch = 6;

/* 统计 */
static volatile uint32_t s_frames = 0, s_invalid = 0;
static volatile uint16_t s_len_min = 0xFFFF, s_len_max = 0;
static uint8_t  s_macs[32][6];
static volatile int s_mac_cnt = 0;
static volatile uint32_t s_raw_left = 0;
static volatile uint32_t s_motion_cnt = 0;
static volatile bool     s_selftest = false;
static uint8_t s_selftest_mac[6];

/* 每个源 AP 单独一份状态: 不同 AP 的信道响应没有可比性, 混在一起算差值
 * 噪声底会被抬到 40 上下, 真动作反而看不出来. */
#define CSI_MAC_SLOTS 4
typedef struct {
    bool     used;
    uint8_t  mac[6];
    float    prev[CSI_MAX_SUB];
    int      n;
    float    base;       /* 自检与输出用的慢速基线, 判定见 csi_det_t */
    float    peak;       /* 该源出现过的最大相邻帧差, 自检用它判定 */
    uint32_t frames;
    csi_det_t det;       /* 动作判定: 非对称基线 + 离散度归一 + CUSUM 兜底 */
} mac_stat_t;
static mac_stat_t s_ms[CSI_MAC_SLOTS];

static void csi_rx_cb(void *ctx, wifi_csi_info_t *info)
{
    (void)ctx;
    if (!s_on || !info || !info->buf || info->len < 8) return;

    uint32_t h = atomic_load(&s_head);
    uint32_t t = atomic_load(&s_tail);
    if (h - t >= CSI_RING_ENTRIES) { s_dropped++; return; }

    csi_ent_t *e = &s_ring[h % CSI_RING_ENTRIES];
    uint16_t len = info->len > CSI_MAX_LEN ? CSI_MAX_LEN : info->len;
    e->ts_us = (uint32_t)esp_timer_get_time();
    e->rssi  = info->rx_ctrl.rssi;
    e->chan  = (uint8_t)info->rx_ctrl.channel;
    e->len   = (uint8_t)len;
    e->flags = info->first_word_invalid ? 1 : 0;
    memcpy(e->mac, info->mac, 6);
    memcpy(e->data, info->buf, len);
    atomic_store(&s_head, h + 1);
}

static void csi_noop_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)buf; (void)type;
}

static int amp_of(int8_t i, int8_t q)
{
    return (int)sqrtf((float)((int)i * i) + (float)((int)q * q));
}

static bool mac_seen(const uint8_t mac[6])
{
    for (int i = 0; i < s_mac_cnt; i++) {
        if (memcmp(s_macs[i], mac, 6) == 0) return true;
    }
    if (s_mac_cnt < 32) {
        memcpy(s_macs[s_mac_cnt], mac, 6);
        s_mac_cnt++;
    }
    return false;
}

static void csi_task(void *arg)
{
    (void)arg;
    uint32_t win_start = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t win_frames = 0;
    uint32_t s_sample_cnt = 0;
    int16_t amp[CSI_MAX_SUB];

    while (1) {
        uint32_t t = atomic_load(&s_tail);
        uint32_t h = atomic_load(&s_head);
        if (t == h) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        csi_ent_t *e = &s_ring[t % CSI_RING_ENTRIES];
        atomic_store(&s_tail, t + 1);

        int n = (e->len & ~1) / 2;      /* 106 字节: 52 个子载波 + 1 字节补齐 */
        if (n > CSI_MAX_SUB) n = CSI_MAX_SUB;
        int skip = (e->flags & 1) ? 2 : 0;   /* 首字无效: 丢前 4 字节 */
        if (n <= skip + 4) continue;

        for (int i = skip; i < n; i++) {
            amp[i] = (int16_t)amp_of((int8_t)e->data[i * 2], (int8_t)e->data[i * 2 + 1]);
        }

        mac_stat_t *ms = NULL;
        for (int i = 0; i < CSI_MAC_SLOTS; i++) {
            if (s_ms[i].used && memcmp(s_ms[i].mac, e->mac, 6) == 0) { ms = &s_ms[i]; break; }
        }
        if (!ms) {
            for (int i = 0; i < CSI_MAC_SLOTS; i++) {
                if (!s_ms[i].used) {
                    ms = &s_ms[i];
                    ms->used = true;
                    memcpy(ms->mac, e->mac, 6);
                    ms->n = 0;
                    ms->base = -1.0f;
                    ms->frames = 0;
                    csi_det_reset(&ms->det);   /* 槽位复用, 旧基线不许带过来 */
                    break;
                }
            }
        }

        /* 归一化后再比: AGC 增益逐帧变化, 绝对幅度本身就会跳几十个单位,
         * 直接算差的话噪声底在 40 上下, 真动作也看不出来. 除以模长把增益
         * 因子消掉, 只留下多径结构的相对变化. */
        float sumsq = 0.0f;
        for (int i = skip; i < n; i++) sumsq += (float)amp[i] * amp[i];
        float norm = sqrtf(sumsq);

        float metric = 0.0f;
        if (ms) {
            ms->frames++;
            if (ms->n == n && norm > 1e-3f) {
                float sum = 0.0f;
                for (int i = skip; i < n; i++) {
                    float a = (float)amp[i] / norm;
                    sum += fabsf(a - ms->prev[i]);
                    ms->prev[i] = a;
                }
                metric = sum / (float)(n - skip);
                if (metric > ms->peak) ms->peak = metric;
                if (ms->base < 0.0f) ms->base = metric;
                else                  ms->base = ms->base * 0.98f + metric * 0.02f;
            } else if (norm > 1e-3f) {
                for (int i = skip; i < n; i++) ms->prev[i] = (float)amp[i] / norm;
            }
            ms->n = n;
        }

        s_frames++;
        if (e->flags & 1) s_invalid++;
        if (e->len < s_len_min) s_len_min = e->len;
        if (e->len > s_len_max) s_len_max = e->len;
        mac_seen(e->mac);
        win_frames++;

        if (s_raw_left > 0) {
            s_raw_left--;
            printf("META,CSI,RAW,ts,%u,rssi,%d,ch,%u,len,%u,inv,%u,mac,%02x%02x%02x%02x%02x%02x,data,",
                   (unsigned)e->ts_us, (int)e->rssi, (unsigned)e->chan, (unsigned)e->len,
                   (unsigned)(e->flags & 1), e->mac[0], e->mac[1], e->mac[2],
                   e->mac[3], e->mac[4], e->mac[5]);
            for (int i = 0; i < e->len; i++) printf("%02x", e->data[i]);
            printf("\n");
            fflush(stdout);
        }

        /* 采样输出按帧数计而不是按时间: 时间门在多源交替时会被判空的帧占满 */
        if (++s_sample_cnt % CSI_SAMPLE_EVERY == 0) {
            /* 判定交给 csi_det: 固定 2 倍门限在持续动作时会被自己的基线学走
             * (离线合成序列 1600 样本只有 1% 仍报动作), 且不看噪声水平. */
            bool motion = ms && csi_det_update(&ms->det, metric);
            float score = ms ? ms->det.score : 0.0f;
            printf("META,CSI,SAMPLE,mac,%02x%02x%02x%02x%02x%02x,metric,%.2f,base,%.2f,"
                   "z,%.1f,motion,%d,rssi,%d,len,%u\n",
                   e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
                   metric, ms ? ms->base : 0.0f, score, motion ? 1 : 0,
                   (int)e->rssi, (unsigned)e->len);
            if (motion) s_motion_cnt++;
            fflush(stdout);
        }

        if (s_selftest && atomic_load(&s_tail) == atomic_load(&s_head)) {
            /* 看合成源自己的 peak, 不看采样点: 采样每 10 帧一次, 真实帧会把
             * 合成帧冲稀, 等采样点命中跳变帧纯靠运气. */
            float peak = 0.0f;
            for (int i = 0; i < CSI_MAC_SLOTS; i++) {
                if (s_ms[i].used && memcmp(s_ms[i].mac, s_selftest_mac, 6) == 0) {
                    peak = s_ms[i].peak;
                    break;
                }
            }
            printf("META,CSI,SELFTEST,result,%s,peak,%.3f\n",
                   peak > CSI_MOTION_FLOOR ? "pass" : "FAIL", peak);
            fflush(stdout);
            s_selftest = false;
        }

        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        if (now - win_start >= 1000) {
            printf("META,CSI,RATE,ts,%u,fps,%u,dropped,%u\n",
                   (unsigned)now, (unsigned)win_frames, (unsigned)s_dropped);
            fflush(stdout);
            win_start = now;
            win_frames = 0;
        }

        if (!s_on && (atomic_load(&s_tail) == atomic_load(&s_head))) {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
}

static esp_err_t csi_lazy_init(void)
{
    if (!s_ring) {
        s_ring = heap_caps_malloc(sizeof(csi_ent_t) * CSI_RING_ENTRIES,
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_ring) {
            ESP_LOGE(TAG, "ring alloc failed (%u bytes)",
                     (unsigned)(sizeof(csi_ent_t) * CSI_RING_ENTRIES));
            return ESP_ERR_NO_MEM;
        }
        atomic_store(&s_head, 0);
        atomic_store(&s_tail, 0);
    }
    if (!s_task) {
        BaseType_t r = xTaskCreate(csi_task, "csi", 4096, NULL, 5, &s_task);
        if (r != pdPASS) { s_task = NULL; return ESP_ERR_NO_MEM; }
    }
    return ESP_OK;
}

esp_err_t csi_start(uint8_t ch)
{
    if (!((ch >= 1 && ch <= 14) || (ch >= 36 && ch <= 177))) return ESP_ERR_INVALID_ARG;

    wifi_attack_stop_all();
    if (wifi_atk_state_val() != 0) return ESP_ERR_INVALID_STATE;

    esp_err_t e = csi_lazy_init();
    if (e != ESP_OK) return e;
    radio_acquire(RES_RX_PROMISC, "csi", 0);

    s_ch = ch;
    s_dropped = 0;
    s_frames = 0;
    s_invalid = 0;
    s_len_min = 0xFFFF;
    s_len_max = 0;
    s_mac_cnt = 0;
    memset(s_ms, 0, sizeof(s_ms));

    e = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (e != ESP_OK) return e;

    /* CSI 的 config 与 enable 都要求已经处于混杂模式, 顺序不能换 */
    wifi_csi_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable                  = 1;
    cfg.acquire_csi_legacy      = 1;   /* 11g 的 L-LTF, beacon 走这条 */
    cfg.acquire_csi_force_lltf  = 1;
    cfg.acquire_csi_ht20        = 1;
    cfg.acquire_csi_ht40        = 1;
    cfg.acquire_csi_vht         = 1;
    cfg.acquire_csi_su          = 1;
    cfg.acquire_csi_mu          = 1;
    cfg.acquire_csi_dcm         = 1;
    cfg.acquire_csi_beamformed  = 1;
    cfg.acquire_csi_he_stbc_mode = 2;
    cfg.val_scale_cfg           = 2;
    cfg.dump_ack_en             = 0;

    esp_wifi_set_promiscuous_rx_cb(csi_noop_cb);
    e = esp_wifi_set_promiscuous(true);
    if (e != ESP_OK) return e;

    e = esp_wifi_set_csi_config(&cfg);
    if (e != ESP_OK) return e;

    e = esp_wifi_set_csi_rx_cb(csi_rx_cb, NULL);
    if (e != ESP_OK) return e;

    e = esp_wifi_set_csi(true);
    if (e != ESP_OK) return e;
    s_on = true;
    return ESP_OK;
}

esp_err_t csi_stop(void)
{
    if (!s_on) return ESP_ERR_INVALID_STATE;
    radio_release(RES_RX_PROMISC);
    s_on = false;
    esp_wifi_set_csi(false);
    esp_wifi_set_promiscuous(false);
    return ESP_OK;
}

bool csi_is_on(void) { return s_on; }

void csi_stats(void)
{
    printf("META,CSI,STATS,on,%d,ch,%u,frames,%u,invalid,%u,len_min,%u,len_max,%u,"
           "macs,%d,dropped,%u\n",
           s_on ? 1 : 0, (unsigned)s_ch, (unsigned)s_frames, (unsigned)s_invalid,
           (unsigned)(s_len_min == 0xFFFF ? 0 : s_len_min), (unsigned)s_len_max,
           s_mac_cnt, (unsigned)s_dropped);
    fflush(stdout);
}

/* 合成序列自检: 灌 30 帧一个形状 + 10 帧另一个形状, 归一化后两者差得远,
 * 检测器应当报 motion. 它验的是判定链路, 不是真实人体的检出率. */
void csi_selftest(void)
{
    if (!s_ring || !s_task) {
        printf("META,CSI,ERR,msg,not_running\n");
        fflush(stdout);
        return;
    }
    static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x99};
    for (int k = 0; k < 40; k++) {
        uint32_t h = atomic_load(&s_head);
        uint32_t t = atomic_load(&s_tail);
        if (h - t >= CSI_RING_ENTRIES) break;
        csi_ent_t *e = &s_ring[h % CSI_RING_ENTRIES];
        e->ts_us = (uint32_t)esp_timer_get_time();
        e->rssi  = -70;
        e->chan  = s_ch;
        e->len   = 106;
        e->flags = 0;
        memcpy(e->mac, mac, 6);
        for (int i = 0; i < 53; i++) {
            /* 每 5 帧在"左半有值"与"右半有值"之间翻一次. 归一化之后两种形状的
             * 平均绝对差约 0.185, 超过判定下限 0.15; 同一段内帧与帧完全相同,
             * base 趋近 0, 所以这里验的是"形状变了"而不是噪声.
             * 只翻一次不够: 采样每 10 帧一次, 一次跳变很可能整个错过. */
            int v = (((k / 5) % 2) == 0) ? (i < 26) : (i >= 26);
            v = v ? 20 : 1;
            e->data[i * 2]     = (int8_t)v;
            e->data[i * 2 + 1] = (int8_t)(v / 2);
        }
        atomic_store(&s_head, h + 1);
    }
    memcpy(s_selftest_mac, mac, 6);
    s_selftest = true;
}

void csi_raw(int n)
{
    if (n < 0) n = 0;
    if (n > 64) n = 64;
    s_raw_left = (uint32_t)n;
}
