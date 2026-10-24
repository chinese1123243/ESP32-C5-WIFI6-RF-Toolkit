/*
 * config.c: 配置持久化 (NVS 键值存储)
 *
 * 内存表用简单动态数组 (配置项数量少, < 32 项, 线性查找足够).
 * NVS namespace = "rftool".
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "CFG";

#define NVS_NS      "rftool"
#define MAX_KEYS    48
#define MAX_VAL_LEN 128

typedef struct {
    char key[32];
    char val[MAX_VAL_LEN];
} cfg_entry_t;

static cfg_entry_t s_table[MAX_KEYS];
static int         s_count = 0;
static SemaphoreHandle_t s_mtx = NULL;


static cfg_entry_t *find_entry(const char *key)
{
    for (int i = 0; i < s_count; i++) {
        if (strcmp(s_table[i].key, key) == 0) return &s_table[i];
    }
    return NULL;
}

static int nvs_set_str_safe(nvs_handle_t h, const char *key, const char *val)
{
    if (!val || val[0] == '\0') {
        /* 删除 */
        esp_err_t e = nvs_erase_key(h, key);
        return (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) ? 0 : -1;
    }
    return nvs_set_str(h, key, val) == ESP_OK ? 0 : -1;
}


esp_err_t config_init(void)
{
    s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx) return ESP_ERR_NO_MEM;

    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open(%s) failed: %s — config will be in-memory only",
                 NVS_NS, esp_err_to_name(e));
        return ESP_OK;  /* 降级: 仅内存, 不致命 */
    }

    /* 遍历 NVS 中所有 key, 加载到内存表 */
    nvs_iterator_t it = NULL;
    esp_err_t it_err = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NS, NVS_TYPE_STR, &it);
    while (it_err == ESP_OK && it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (s_count < MAX_KEYS) {
            strncpy(s_table[s_count].key, info.key, sizeof(s_table[s_count].key) - 1);
            s_table[s_count].key[sizeof(s_table[s_count].key) - 1] = 0;
            size_t len = MAX_VAL_LEN;
            if (nvs_get_str(h, info.key, s_table[s_count].val, &len) == ESP_OK) {
                s_count++;
            }
        }
        it_err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    nvs_close(h);

    /* 首次启动自动生成 API token (HTTP 危险操作鉴权).
     * 若 NVS 中已有则沿用, 保证重启后 token 不变. */
    if (!find_entry("api_token")) {
        static const char alnum[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        char tok[17];
        for (int i = 0; i < 16; i++) {
            tok[i] = alnum[esp_random() % (sizeof(alnum) - 1)];
        }
        tok[16] = 0;
        config_set("api_token", tok);
        ESP_LOGI(TAG, "generated api_token=%s (for HTTP auth)", tok);
    }

    ESP_LOGI(TAG, "loaded %d config entries from NVS", s_count);
    return ESP_OK;
}

const char *config_get(const char *key)
{
    if (!key) return NULL;
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    cfg_entry_t *e = find_entry(key);
    const char *r = e ? e->val : NULL;
    if (s_mtx) xSemaphoreGive(s_mtx);
    return r;
}

int config_set(const char *key, const char *value)
{
    if (!key || !*key) return -1;

    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);

    /* 写 NVS */
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str_safe(h, key, value);
        nvs_commit(h);
        nvs_close(h);
    }

    /* 更新内存表 */
    cfg_entry_t *e = find_entry(key);
    if (value && value[0]) {
        if (!e) {
            if (s_count >= MAX_KEYS) {
                if (s_mtx) xSemaphoreGive(s_mtx);
                return -1;
            }
            e = &s_table[s_count++];
            strncpy(e->key, key, sizeof(e->key) - 1);
            e->key[sizeof(e->key) - 1] = 0;
        }
        strncpy(e->val, value, sizeof(e->val) - 1);
        e->val[sizeof(e->val) - 1] = 0;
    } else if (e) {
        /* 删除: 把最后一项移过来 */
        int idx = (int)(e - s_table);
        s_table[idx] = s_table[--s_count];
    }

    if (s_mtx) xSemaphoreGive(s_mtx);
    return 0;
}

void config_foreach(config_iter_cb cb, void *ctx)
{
    if (!cb) return;
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        cb(s_table[i].key, s_table[i].val, ctx);
    }
    if (s_mtx) xSemaphoreGive(s_mtx);
}

void config_reset(void)
{
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
    s_count = 0;
    if (s_mtx) xSemaphoreGive(s_mtx);
}
