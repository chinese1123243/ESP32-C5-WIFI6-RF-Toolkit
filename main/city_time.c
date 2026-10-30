#include "city_time.h"

#include <stdbool.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "esp_timer.h"
#include "nvs.h"

/* 与 config.c 共用同一个命名空间, 避免多开一个 NVS 分区 */
#define CITY_NVS_NS  "rftool"
#define CITY_NVS_KEY "boot_cnt"

/* 2020-01-01 00:00:00 UTC. time() 早于这个值说明还没对时. */
#define CITY_EPOCH_FLOOR 1577836800u

static uint32_t s_boot_count;
static bool     s_inited;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

esp_err_t city_time_init(void)
{
    if (s_inited) return ESP_OK;

    uint32_t n = 0;
    nvs_handle_t h;
    esp_err_t e = nvs_open(CITY_NVS_NS, NVS_READWRITE, &h);
    if (e == ESP_OK) {
        if (nvs_get_u32(h, CITY_NVS_KEY, &n) != ESP_OK) n = 0;
        n++;
        if (n == 0) n = 1;   /* 回绕时回到 1, 不让计数变 0 被当成"没记录" */
        nvs_set_u32(h, CITY_NVS_KEY, n);
        /* 掉电前必须落地, 崩一次少一次计数会让事故无法按开机序对齐 */
        nvs_commit(h);
        nvs_close(h);
    } else {
        n = 1;
    }

    taskENTER_CRITICAL(&s_mux);
    s_boot_count = n;
    s_inited = true;
    taskEXIT_CRITICAL(&s_mux);
    return ESP_OK;
}

static uint32_t wallclock_now(void)
{
    time_t t = time(NULL);
    return ((uint32_t)t > CITY_EPOCH_FLOOR) ? (uint32_t)t : 0;
}

city_time_t city_clock(void)
{
    city_time_t t;
    if (!s_inited) city_time_init();

    t.monotonic_ms = (uint32_t)(esp_timer_get_time() / 1000);
    t.wallclock_s = wallclock_now();

    taskENTER_CRITICAL(&s_mux);
    t.boot_count = s_boot_count;
    taskEXIT_CRITICAL(&s_mux);
    return t;
}

uint32_t city_boot_count(void)
{
    if (!s_inited) city_time_init();
    taskENTER_CRITICAL(&s_mux);
    uint32_t n = s_boot_count;
    taskEXIT_CRITICAL(&s_mux);
    return n;
}
