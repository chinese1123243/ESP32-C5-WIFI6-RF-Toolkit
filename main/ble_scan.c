/*
 * ble_scan.c: 板子侧 BLE 近邻扫描
 *
 * 扫描回调跑在 NimBLE host 任务上下文里, 所以里面只做"解析 + 拷进表",
 * 不做任何打印 (打印会拖慢 host 任务, 进而卡住 BLE 事件处理).
 */
#include "ble_scan.h"

#include <string.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "nimble/ble.h"

static const char *TAG = "BLESCAN";

typedef struct {
    uint8_t addr[6];
    int8_t  rssi;
    char    name[32];
} bs_ent_t;

static bs_ent_t *s_tab = NULL;
static int       s_cnt = 0;
static bool      s_on = false;

static bool ensure(void)
{
    if (s_tab) return true;
    s_tab = heap_caps_calloc(BLE_SCAN_MAX, sizeof(bs_ent_t),
                             MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_tab) s_tab = calloc(BLE_SCAN_MAX, sizeof(bs_ent_t));
    if (!s_tab) { ESP_LOGW(TAG, "alloc failed"); return false; }
    return true;
}

/* 从 AD 数据里找名字 (0x08 短名 / 0x09 全名) */
static void extract_name(const uint8_t *data, uint8_t len, char *out, size_t out_sz)
{
    out[0] = '\0';
    int p = 0;
    while (p + 2 <= len) {
        uint8_t alen = data[p];
        if (alen == 0) break;
        if (p + 1 + alen > len) break;
        uint8_t type = data[p + 1];
        if ((type == 0x08 || type == 0x09) && alen >= 2) {
            int n = alen - 1;
            if (n > (int)out_sz - 1) n = (int)out_sz - 1;
            memcpy(out, data + p + 2, n);
            out[n] = '\0';
            /* 只保留可打印字符, 避免终端被控制字符搞乱.
             * >= 0x80 的字节是 UTF-8 多字节, 要留着 (中文 BLE 名很常见). */
            for (int i = 0; i < n; i++) {
                unsigned char c = (unsigned char)out[i];
                if (c < 0x20 || c == 0x7f) out[i] = '?';
            }
            return;
        }
        p += 1 + alen;
    }
}

static int scan_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type == BLE_GAP_EVENT_DISC) {
        if (!s_tab) return 0;
        const struct ble_gap_disc_desc *d = &event->disc;
        uint8_t addr[6];
        memcpy(addr, d->addr.val, 6);

        /* 已在表里就只更新 RSSI */
        for (int i = 0; i < s_cnt; i++) {
            if (memcmp(s_tab[i].addr, addr, 6) == 0) {
                s_tab[i].rssi = d->rssi;
                if (!s_tab[i].name[0] && d->length_data)
                    extract_name(d->data, d->length_data, s_tab[i].name, sizeof(s_tab[i].name));
                return 0;
            }
        }
        if (s_cnt >= BLE_SCAN_MAX) return 0;
        bs_ent_t *e = &s_tab[s_cnt++];
        memset(e, 0, sizeof(*e));
        memcpy(e->addr, addr, 6);
        e->rssi = d->rssi;
        if (d->length_data) extract_name(d->data, d->length_data, e->name, sizeof(e->name));
        return 0;
    }
    if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        s_on = false;
        ESP_LOGI(TAG, "scan complete");
    }
    return 0;
}

esp_err_t ble_scan_start(void)
{
    if (s_on) return ESP_OK;
    if (!ensure()) return ESP_ERR_NO_MEM;

    /* host 还没 sync 完就调 ble_gap_disc() 会返回 BLE_HS_EDISABLED/EINVAL,
     * 用户侧只看到「开始扫描」但表永远是空. 明确区分出来. */
    if (!ble_hs_synced()) {
        ESP_LOGW(TAG, "host not synced yet");
        return ESP_ERR_INVALID_STATE;
    }

    struct ble_gap_disc_params p = {0};
    p.itvl = 0;              /* 0 = 用控制器默认 */
    p.window = 0;
    p.filter_duplicates = 1;
    p.passive = 0;

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &p, scan_cb, NULL);
    if (rc != 0) {
        /* 常见: 12 == BLE_HS_ENOTSYNCED, 6 == BLE_HS_ENOMEM, 8 == BLE_HS_EBUSY.
         * 若已有连接在跑, 改用随机地址重试一次 (部分控制器 public 地址被占用). */
        ESP_LOGW(TAG, "ble_gap_disc failed: rc=%d", rc);
        rc = ble_gap_disc(BLE_OWN_ADDR_RANDOM, BLE_HS_FOREVER, &p, scan_cb, NULL);
        if (rc != 0) {
            ESP_LOGW(TAG, "ble_gap_disc(random) failed: rc=%d", rc);
            return ESP_FAIL;
        }
    }
    s_on = true;
    ESP_LOGI(TAG, "scanning");
    return ESP_OK;
}

esp_err_t ble_scan_stop(void)
{
    if (!s_on) return ESP_ERR_INVALID_STATE;
    int rc = ble_gap_disc_cancel();
    s_on = false;
    if (rc != 0) {
        ESP_LOGW(TAG, "disc_cancel rc=%d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

bool ble_scan_is_on(void) { return s_on; }

void ble_scan_clear(void) { s_cnt = 0; }

int ble_scan_count(void) { return s_cnt; }

bool ble_scan_get(int i, uint8_t addr[6], int8_t *rssi, const char **name)
{
    if (!s_tab || i < 0 || i >= s_cnt) return false;
    /* 按 RSSI 降序做选择排序的第 i 轮 (表很小, 不必维护有序结构) */
    int idx[BLE_SCAN_MAX];
    for (int k = 0; k < s_cnt; k++) idx[k] = k;
    for (int a = 0; a < s_cnt; a++) {
        for (int b = a + 1; b < s_cnt; b++) {
            if (s_tab[idx[b]].rssi > s_tab[idx[a]].rssi) {
                int t = idx[a]; idx[a] = idx[b]; idx[b] = t;
            }
        }
    }
    bs_ent_t *e = &s_tab[idx[i]];
    if (addr) memcpy(addr, e->addr, 6);
    if (rssi) *rssi = e->rssi;
    if (name) *name = e->name;
    return true;
}
