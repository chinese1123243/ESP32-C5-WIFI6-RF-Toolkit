/* locate.c: 信号定位实现 */
#include "locate.h"
#include "wifi_db.h"
#include "radio_common.h"
#include "event_bus.h"
#include "wifi_attack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"   /* 采样表放 PSRAM, 省内部 RAM */

#define LOC_MAX      300          /* 150s @2Hz */
#define LOC_PERIOD   500          /* ms */

typedef struct { int16_t rssi; uint8_t ch; uint32_t t_ms; } loc_sample_t;

/* 300 个采样点若放内部 RAM 要 2.4KB, NimBLE 会因此起不来, 改 PSRAM. */
static loc_sample_t *s_smp = NULL;
static int          s_n = 0;
static volatile bool s_run = false;
static TaskHandle_t s_task = NULL;
static uint8_t      s_mac[6];
static bool         s_is_client = false;
static uint32_t     s_secs = 30;
static int          s_miss = 0;

static int rssi_now(void)
{
    if (s_is_client) {
        const client_entry_t *c = wifi_db_find_client(s_mac);
        return c ? c->rssi : 0;
    }
    const ap_entry_t *a = wifi_db_find_ap(s_mac);
    return a ? a->rssi : 0;
}

static int ch_now(void)
{
    if (s_is_client) {
        /* 客户端条目不存信道, 用当前嗅探信道代表采样时的信道 */
        return (int)wifi_atk_channel();
    }
    const ap_entry_t *a = wifi_db_find_ap(s_mac);
    return a ? a->channel : 0;
}

static void statistics(int *avg, int *mn, int *mx, const char **trend)
{
    int sum = 0, lo = 0, hi = -127;
    for (int i = 0; i < s_n; i++) {
        int v = s_smp[i].rssi;
        sum += v;
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    *avg = s_n ? sum / s_n : 0;
    *mn = s_n ? lo : 0;
    *mx = s_n ? hi : 0;

    /* 趋势: 最近 4 个样本 vs 最早 4 个 */
    const char *t = "flat";
    if (s_n >= 8) {
        int a = 0, b = 0;
        for (int i = 0; i < 4; i++) { a += s_smp[i].rssi; b += s_smp[s_n - 1 - i].rssi; }
        if (b - a >= 4) t = "up";          /* 数值变大 = 更近 */
        else if (a - b >= 4) t = "down";
    }
    *trend = t;
}

static void locate_task(void *arg)
{
    (void)arg;
    int64_t t0 = esp_timer_get_time();
    int tick = 0;

    while (s_run) {
        int rssi = rssi_now();
        int ch   = ch_now();
        if (rssi == 0) {
            s_miss++;
        } else if (s_n < LOC_MAX) {
            s_smp[s_n].rssi = (int16_t)rssi;
            s_smp[s_n].ch = (uint8_t)ch;
            s_smp[s_n].t_ms = (uint32_t)((esp_timer_get_time() - t0) / 1000);
            s_n++;
        }

        if (++tick % 4 == 0) {                 /* 每 2s 报一次, 不刷屏 */
            int avg, mn, mx; const char *trend;
            statistics(&avg, &mn, &mx, &trend);
            char macs[18]; mac_to_str(s_mac, macs);
            printf("META,LOCATE,T,mac,%s,rssi,%d,avg,%d,min,%d,max,%d,n,%d,trend,%s\n",
                   macs, rssi, avg, mn, mx, s_n, trend);
            fflush(stdout);
            event_publish("LOCATE", "mac=%s rssi=%d avg=%d trend=%s", macs, rssi, avg, trend);
        }

        if (s_secs && (esp_timer_get_time() - t0) >= (int64_t)s_secs * 1000000) break;
        vTaskDelay(pdMS_TO_TICKS(LOC_PERIOD));
    }

    int avg, mn, mx; const char *trend;
    statistics(&avg, &mn, &mx, &trend);
    printf("META,LOCATE,DONE,samples,%d,avg,%d,min,%d,max,%d,miss,%d\n",
           s_n, avg, mn, mx, s_miss);
    fflush(stdout);
    event_publish("LOCATE", "done samples=%d avg=%d", s_n, avg);

    s_run = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t locate_start(const uint8_t mac[6], bool is_client, uint32_t secs)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    if (s_run) return ESP_ERR_INVALID_STATE;
    if (secs == 0) secs = 30;
    if (secs > 150) secs = 150;

    if (!s_smp) {
        s_smp = heap_caps_malloc(LOC_MAX * sizeof(loc_sample_t),
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_smp) s_smp = malloc(LOC_MAX * sizeof(loc_sample_t));
        if (!s_smp) return ESP_ERR_NO_MEM;
    }

    memcpy(s_mac, mac, 6);
    s_is_client = is_client;
    s_secs = secs;
    s_n = 0;
    s_miss = 0;
    s_run = true;

    char macs[18]; mac_to_str(s_mac, macs);
    printf("META,LOCATE,START,mac,%s,kind,%s,secs,%u\n",
           macs, is_client ? "client" : "ap", (unsigned)secs);
    fflush(stdout);
    event_publish("LOCATE", "start %s %s", macs, is_client ? "client" : "ap");

    if (xTaskCreate(locate_task, "locate", 3072, NULL, 4, &s_task) != pdPASS) {
        s_run = false;
        return ESP_FAIL;
    }
    return ESP_OK;
}

void locate_stop(void)
{
    if (!s_run) return;
    s_run = false;
    printf("META,LOCATE,STOP\n");
    fflush(stdout);
    event_publish("LOCATE", "stop");
}

bool locate_running(void) { return s_run; }
int  locate_samples(void) { return s_n; }

void locate_status(void)
{
    int avg, mn, mx; const char *trend;
    statistics(&avg, &mn, &mx, &trend);
    char macs[18]; mac_to_str(s_mac, macs);
    printf("META,LOCATE,STATUS,running,%d,mac,%s,kind,%s,samples,%d,avg,%d,min,%d,max,%d,trend,%s,miss,%d\n",
           s_run ? 1 : 0, macs, s_is_client ? "client" : "ap",
           s_n, avg, mn, mx, trend, s_miss);
    fflush(stdout);
}

int locate_export_csv(void)
{
    fputs("t_ms,rssi,channel\n", stdout);
    for (int i = 0; i < s_n; i++) {
        printf("%u,%d,%u\n", (unsigned)s_smp[i].t_ms, s_smp[i].rssi, (unsigned)s_smp[i].ch);
    }
    fflush(stdout);
    return s_n + 1;
}
