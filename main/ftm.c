/*
 * ftm.c: 802.11mc FTM 精细测距实现
 *
 * 流程:
 *   CLI: ftm range <bssid> [ch] [count]
 *     └─ ftm_range(): 填 cfg → esp_wifi_ftm_initiate_session()
 *        → 等 WIFI_EVENT_FTM_REPORT (事件任务) 给出的信号量
 *        → 打印 META,FTM,REPORT (含距离/ RTT / 每 burst 明细)
 *
 * 事件 (WIFI_EVENT_FTM_REPORT) 在 Wi-Fi 事件任务上下文异步到达, 故本模块
 * 用"信号量 + 结果快照"把异步事件桥接成同步 API, 方便 REPL 使用.
 */
#include "ftm.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

static const char *TAG = "FTM";

static SemaphoreHandle_t s_sem = NULL;
static _Atomic bool      s_active = false;

static struct {
    uint8_t  peer[6];
    int      status;
    uint32_t rtt_raw;
    uint32_t rtt_est;
    uint32_t dist_cm;
    uint8_t  num;
} s_res;

static const char *ftm_status_str(int st)
{
    switch (st) {
    case FTM_STATUS_SUCCESS:       return "SUCCESS";
    case FTM_STATUS_UNSUPPORTED:   return "UNSUPPORTED";
    case FTM_STATUS_CONF_REJECTED: return "CONF_REJECTED";
    case FTM_STATUS_NO_RESPONSE:   return "NO_RESPONSE";
    case FTM_STATUS_FAIL:          return "FAIL";
    case FTM_STATUS_NO_VALID_MSMT: return "NO_VALID_MSMT";
    case FTM_STATUS_USER_TERM:     return "USER_TERM";
    default:                       return "UNKNOWN";
    }
}

static void ftm_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base != WIFI_EVENT || id != WIFI_EVENT_FTM_REPORT) return;

    wifi_event_ftm_report_t *r = (wifi_event_ftm_report_t *)data;
    s_res.status  = (int)r->status;
    s_res.rtt_raw = r->rtt_raw;
    s_res.rtt_est = r->rtt_est;
    s_res.dist_cm = r->dist_est;
    s_res.num     = r->ftm_report_num_entries;
    memcpy(s_res.peer, r->peer_mac, 6);

    if (s_sem) xSemaphoreGive(s_sem);
}

esp_err_t ftm_init(void)
{
    if (!s_sem) {
        s_sem = xSemaphoreCreateBinary();
        if (!s_sem) return ESP_ERR_NO_MEM;
    }
    esp_err_t e = esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_FTM_REPORT, ftm_event_handler, NULL, NULL);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "register FTM handler: %s", esp_err_to_name(e));
    }
    return e;
}

bool ftm_is_active(void) { return atomic_load(&s_active); }

esp_err_t ftm_range(const uint8_t bssid[6], uint8_t channel,
                    uint8_t frm_count, uint16_t burst_period)
{
    if (!s_sem) return ESP_ERR_INVALID_STATE;
    if (atomic_load(&s_active)) return ESP_ERR_INVALID_STATE;

    wifi_ftm_initiator_cfg_t cfg = {0};
    memcpy(cfg.resp_mac, bssid, 6);
    cfg.channel             = channel;
    cfg.frm_count           = frm_count;      /* 0/16/24/32/64 */
    cfg.burst_period        = burst_period;   /* 0..100 (×100ms) */
    cfg.use_get_report_api  = true;           /* 用 get_report 取明细, 免手动 free */

    /* 清掉可能残留的信号量 */
    xSemaphoreTake(s_sem, 0);

    atomic_store(&s_active, true);
    esp_err_t e = esp_wifi_ftm_initiate_session(&cfg);
    if (e != ESP_OK) {
        atomic_store(&s_active, false);
        ESP_LOGW(TAG, "initiate_session: %s", esp_err_to_name(e));
        return e;
    }

    bool got = (xSemaphoreTake(s_sem, pdMS_TO_TICKS(6000)) == pdTRUE);
    atomic_store(&s_active, false);

    if (!got) {
        esp_wifi_ftm_end_session();
        printf("META,FTM,ERR,msg,timeout\n");
        fflush(stdout);
        return ESP_ERR_TIMEOUT;
    }

    printf("META,FTM,REPORT,peer,%02x:%02x:%02x:%02x:%02x:%02x,status,%s,status_code,%d,"
           "dist_cm,%u,dist_m,%.2f,rtt_est_ns,%u,rtt_raw_ns,%u,entries,%u\n",
           s_res.peer[0], s_res.peer[1], s_res.peer[2],
           s_res.peer[3], s_res.peer[4], s_res.peer[5],
           ftm_status_str(s_res.status), s_res.status,
           (unsigned)s_res.dist_cm, (double)s_res.dist_cm / 100.0,
           (unsigned)s_res.rtt_est, (unsigned)s_res.rtt_raw, (unsigned)s_res.num);

    /* 取每 burst 明细 (esp_wifi_ftm_get_report 一次性读取并释放内部报告) */
    if (s_res.status == FTM_STATUS_SUCCESS && s_res.num > 0) {
        uint8_t n = s_res.num > 16 ? 16 : s_res.num;
        wifi_ftm_report_entry_t *rep = calloc(n, sizeof(*rep));
        if (rep) {
            if (esp_wifi_ftm_get_report(rep, n) == ESP_OK) {
                for (uint8_t i = 0; i < n; i++) {
                    /* rtt 单位 pSec → 单程距离(cm) ≈ rtt/2(ps) * 3e10 cm/s = rtt*3/200000... 直接用 rtt 展示 */
                    printf("FTM,BURST,%u,rssi,%d,rtt_ps,%u\n",
                           (unsigned)i, (int)rep[i].rssi, (unsigned)rep[i].rtt);
                }
            }
            free(rep);
        }
    }
    fflush(stdout);
    /* 只要收到了报告就算成功, 测距是否达成由 REPORT 里的 status 表达
     * (UNSUPPORTED / NO_RESPONSE 等也是对端能力的真实结论, 不是命令失败).
     * 只有"报告都没等到"(超时) 才返回错误. */
    return ESP_OK;
}
