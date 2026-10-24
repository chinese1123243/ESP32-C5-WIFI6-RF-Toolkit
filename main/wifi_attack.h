/*
 * wifi_attack.h: Wi-Fi 攻击模块 (嗅探 / deauth 注入 / beacon flood / probe flood)
 *
 * 设计: 状态机 + 独立 FreeRTOS 注入任务. 嗅探在 promiscuous 回调内直接打印
 *   PKT/HEX 行 (低延迟, 不经队列). 注入由独立 task 循环 esp_wifi_80211_tx.
 *
 * 约束: 同一时刻仅一个注入任务运行; 启动新注入会停止旧任务. 嗅探与注入
 *   理论可并发 (STA 模式 RF 前端分时), 但实测注入会显著打断 RX, 故建议
 *   嗅探与 deauth/beacon flood 互斥 (cli 层强制).
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 模块状态 */
typedef enum {
    WIFI_ATK_IDLE = 0,
    WIFI_ATK_SNIFF,
    WIFI_ATK_INJECT,
    WIFI_ATK_DOWNGRADE,   /* WPA3->WPA2 downgrade AP + EAPOL 4-way capture */
    WIFI_ATK_PMKID,       /* 以 station 身份关联一次, 收 M1 取 PMKID */
} wifi_atk_state_t;

/* 初始化 Wi-Fi: NVS / netif / event_loop / STA 模式 / start / PS_NONE.
 * 调用前 rgb_led_init 已就绪. 失败 RGB_ERROR. */
esp_err_t wifi_attack_init(void);

/* 启动 promiscuous 嗅探. channel: 1..13 (2.4G), count=0 表示持续直到 stop.
 * 返回 ESP_ERR_INVALID_STATE 若当前非 IDLE. */
esp_err_t wifi_attack_sniff_start(uint8_t channel, uint32_t count);

/* 停止嗅探. */
esp_err_t wifi_attack_sniff_stop(void);

/* 启动 deauth 注入任务. count=0 持续直到 stop. interval_ms 每发间隔.
 * bssid: 目标 AP MAC; sta: 目标站 MAC (可为 0:00:..:0 = 广播 deauth, 踢全部). */
esp_err_t wifi_attack_deauth_start(const uint8_t bssid[6], const uint8_t sta[6],
                                   uint32_t count, uint16_t reason, uint32_t interval_ms);

/* 启动 beacon flood 任务. prefix: SSID 前缀 (实际 SSID = prefix+随机N).
 * count=0 持续. interval_ms 每发间隔. */
esp_err_t wifi_attack_beacon_flood_start(const char *prefix, uint32_t count,
                                        uint32_t interval_ms, uint8_t channel);

/* 启动 probe request flood. count=0 持续. */
esp_err_t wifi_attack_probe_flood_start(uint32_t count, uint32_t interval_ms);

/* 停止当前注入任务 (若有). 安全可重复调用. */
esp_err_t wifi_attack_inject_stop(void);

/* 启动信道自动轮询嗅探. dwell_ms: 每信道基准停留毫秒.
 * count: 抓够这么多包自动停 (0 = 永续).
 * 默认开启自适应调度, 按各信道命中率在 [0.55x, 3x] 范围内缩放驻留. */
esp_err_t wifi_attack_sniff_auto_start(uint32_t dwell_ms, uint32_t count);

/* 主动 PMKID: 以 station 身份对目标做一次真实关联, 只等 AP 的 M1.
 * 口令是随机的, 不需要正确: PMKID 在 M1 的 KDE 里, 与 MIC 无关.
 * 返回 ESP_OK 表示至少收到一条 EAPOL; m1_out / pmkid_out 是本次增量.
 * 阻塞 timeout_ms 或提前拿到 PMKID 就返回. */
esp_err_t wifi_attack_pmkid_active(const uint8_t bssid[6], const char *ssid,
                                   uint8_t ch, uint32_t timeout_ms,
                                   int *m1_out, int *pmkid_out);

/* CSA 伪造的结果. bytes 里是改过的完整 beacon, dry 模式回给 CLI 打印 hex. */
typedef struct {
    uint8_t bytes[512];
    int     len;
    int     sent;
    int     fail;
    bool    cloned;      /* true = 用了空口抓到的真实 beacon, false = 合成 */
} csa_result_t;

/* 克隆目标 beacon, 追加 CSA IE, 在目标信道连发 count 个 (倒计时递减).
 * 抓不到 beacon 时用 ssid_fallback 合成一个. dry=true 只组帧不发射.
 * 单射频: 会先停掉嗅探/注入/降级. */
esp_err_t wifi_attack_csa(const uint8_t bssid[6], const char *ssid_fallback,
                          uint8_t ch, uint8_t new_ch, uint8_t count, bool dry,
                          csa_result_t *res);

/* 单信道空口占用 */
typedef struct {
    uint8_t  ch;
    uint32_t frames;
    uint32_t bytes;
    uint32_t air_ms;     /* 按帧长与速率估算的占用时间 */
    uint8_t  util;       /* air_ms / dwell_ms, 百分比 */
    int8_t   rssi_max;
} air_ch_t;

/* 逐信道测空口占用. band: 0=2.4G, 1=5G, 2=全部; ch 非 0 时只测该信道.
 * 阻塞, 每信道驻留 dwell_ms. 返回写入 out 的信道数. */
int wifi_attack_airtime(uint8_t band, uint8_t ch, uint32_t dwell_ms,
                        air_ch_t *out, int max_out);

/* 自动轮询的调度策略. 必须在 sniff_auto_start 之前设置才生效.
 *   0 = wrl: 按帧率加权 (旧行为)
 *   1 = psd: 按每信道发现数排序 + 探测下限 (默认) */
void wifi_attack_set_auto_policy(int policy);
int  wifi_attack_get_auto_policy(void);

/* 打印自适应轮询统计 (滚轮轮次 / 总命中 / 热点信道 TOP8). */
void wifi_attack_auto_dump(void);

/* WPA3 -> WPA2 Downgrade AP
 * 启动一个 WPA2-PSK PMF-Disabled 同名 SoftAP, 诱导 WPA3-Transition 客户端
 * 降级走 WPA2 4-way handshake. 同时开 promiscuous 抓 EAPOL 存 wifi_db.
 * ssid: 伪造同名 AP 的 SSID (与目标网络同名)
 * pass: 伪造 AP 的 WPA2 密码 (随便, 客户端连不上反而重试暴露握手)
 * 返回 ESP_ERR_INVALID_STATE 若当前非 IDLE (会自动调 stop_all). */
esp_err_t wifi_attack_downgrade_start(const char *ssid, const char *pass);

/* 停止 downgrade AP (回到 IDLE). */
esp_err_t wifi_attack_downgrade_stop(void);

/* 全局互斥控制
 * 停止所有正在运行的功能 (sniff + inject + downgrade), 等 inject task 退出.
 * 任何 _start 函数内部都会先调用此函数实现"启动一个就停其他". */
esp_err_t wifi_attack_stop_all(void);

/* 打印 META 状态行 (state / channel / counters). */
void wifi_attack_status(void);

/* 供外部模块 (HTTP) 读取的原子 getter. */
int      wifi_atk_state_val(void);
uint8_t  wifi_atk_channel(void);
bool     wifi_atk_auto_ch(void);
uint32_t wifi_atk_sniff_total(void);
uint32_t wifi_atk_inject_total(void);

#ifdef __cplusplus
}
#endif
