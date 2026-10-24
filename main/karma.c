/*
 * karma.c: Probe Request SSID 收集
 *
 * 表很小 (32 条) 且访问都在非热路径上, 直接静态分配; 但为省内部 RAM
 * 仍按需惰性分配 (这块板子的内部 RAM 一直在临界点).
 */
#include "karma.h"

#include <string.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"

static const char *TAG = "KARMA";

typedef struct {
    char     ssid[33];
    uint8_t  len;
    uint16_t count;
    int8_t   rssi;
    uint32_t last_ms;
} k_ent_t;

static k_ent_t *s_tab = NULL;
static int      s_used = 0;

static bool ensure(void)
{
    if (s_tab) return true;
    s_tab = heap_caps_calloc(KARMA_MAX, sizeof(k_ent_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_tab) s_tab = calloc(KARMA_MAX, sizeof(k_ent_t));
    if (!s_tab) { ESP_LOGW(TAG, "alloc failed"); return false; }
    return true;
}

void karma_clear(void) { s_used = 0; if (s_tab) memset(s_tab, 0, KARMA_MAX * sizeof(k_ent_t)); }
int  karma_count(void) { return s_used; }

/* Probe Request: 管理帧 subtype 4, 24 字节头后紧跟 IE 区 (首个通常是 SSID) */
void karma_feed(const uint8_t *f, int len, int8_t rssi)
{
    if (!f || len < 24) return;
    if (((f[0] >> 2) & 0x3) != 0) return;          /* 非管理帧 */
    if (((f[0] >> 4) & 0xF) != 4) return;          /* 非 Probe Request */
    if (!ensure()) return;

    const uint8_t *ies = f + 24;
    int n = len - 24;
    int p = 0;
    while (p + 2 <= n) {
        uint8_t id = ies[p], sl = ies[p + 1];
        if (p + 2 + sl > n) break;
        if (id == 0) {
            if (sl == 0 || sl > 32) return;        /* 广播探测, 不带 SSID, 忽略 */
            char ssid[33];
            memcpy(ssid, ies + p + 2, sl);
            ssid[sl] = '\0';

            uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
            for (int i = 0; i < s_used; i++) {
                if (s_tab[i].len == sl && memcmp(s_tab[i].ssid, ssid, sl) == 0) {
                    s_tab[i].count++;
                    s_tab[i].rssi = rssi;
                    s_tab[i].last_ms = now;
                    return;
                }
            }
            if (s_used >= KARMA_MAX) return;
            k_ent_t *e = &s_tab[s_used++];
            memcpy(e->ssid, ssid, sl + 1);
            e->len = (uint8_t)sl;
            e->count = 1;
            e->rssi = rssi;
            e->last_ms = now;
            return;
        }
        p += 2 + sl;
    }
}

/* 取"第 i 名": 按 count 降序, 同 count 按最近时间新的优先 (插入排序按需选) */
const char *karma_get(int i, int *count_out, int8_t *rssi_out)
{
    if (!s_tab || i < 0 || i >= s_used) return NULL;
    /* 复制一份索引做简单选择排序的第 i 轮, 表只有 32 条, 不值得维护有序结构 */
    int idx[KARMA_MAX];
    for (int k = 0; k < s_used; k++) idx[k] = k;
    for (int a = 0; a < s_used; a++) {
        for (int b = a + 1; b < s_used; b++) {
            bool swap = s_tab[idx[b]].count > s_tab[idx[a]].count ||
                        (s_tab[idx[b]].count == s_tab[idx[a]].count &&
                         s_tab[idx[b]].last_ms > s_tab[idx[a]].last_ms);
            if (swap) { int t = idx[a]; idx[a] = idx[b]; idx[b] = t; }
        }
    }
    k_ent_t *e = &s_tab[idx[i]];
    if (count_out) *count_out = e->count;
    if (rssi_out)  *rssi_out  = e->rssi;
    return e->ssid;
}

const char *karma_top(int *count_out)
{
    return karma_get(0, count_out, NULL);
}
