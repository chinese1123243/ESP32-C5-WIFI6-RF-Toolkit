/*
 * main.c: rftool 入口
 *
 * 三层任务栈隔离:
 *   1. main task (IDF 默认 16KB): 仅创建 init_task → 立即自杀
 *   2. init_task (32KB): RGB init + Wi-Fi init/phy_init → 创建 cli_task → 自杀
 *   3. cli_task (32KB): 极简 fgets+dispatch REPL (无 esp_console, 栈可控)
 *      → fgets + split_args + arg_parse + cmd_xxx 最深约 8KB, 32KB 给 4x 余量
 *
 * sdkconfig: CONFIG_LIBC_NEWLIB_NANO_FORMAT=y 已压 vfprintf 栈 ~4KB
 *
 * RGB 状态联动: BOOT紫 → init完 暗蓝(IDLE) → 嗅探绿 / 注入红 / 错误亮红.
 */
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_heap_caps.h"
#include "rgb_led.h"
#include "wifi_attack.h"
#include "cli.h"
#include "ble_cli.h"
#include "ble_adv.h"
#include "cap.h"
#include "hs.h"
#include "ftm.h"
#include "config.h"   /* NVS 配置持久化 */
#include "ota.h"      /* 双区 OTA */
#include "event_bus.h" /* 统一事件总线 */

static const char *TAG = "MAIN";

#if CONFIG_ESP_TASK_WDT_EN
#include "esp_task_wdt.h"

/* 受控看门狗: 30s 超时, 不监控空闲任务, 超时触发 panic → 自动重启.
 *
 * 为什么 idle_core_mask=0:
 *   旧方案把 TWDT 全关, 理由是"REPL 长时间空闲会误触发". 真正的原因是
 *   默认会监控 IDLE 任务, 而 cli(prio 24) 长期阻塞在 fgets 时若把 CPU 让
 *   出去后仍不喂狗就会误报. 这里不监控 idle, 改由关键长跑任务各自
 *   esp_task_wdt_add(NULL) + 循环内 esp_task_wdt_reset(), 精确且无副作用.
 */
static void wdt_init_controlled(void)
{
    esp_task_wdt_config_t cfg = {
        .timeout_ms     = 30000,
        .idle_core_mask = 0,      /* 不监控 idle */
        .trigger_panic  = true,   /* 超时即重启 → 自愈 */
    };
    esp_err_t e = esp_task_wdt_init(&cfg);
    if (e == ESP_ERR_INVALID_STATE) {
        e = esp_task_wdt_reconfigure(&cfg);   /* 已被别处初始化则改配置 */
    }
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "task wdt init: %s", esp_err_to_name(e));
    } else {
        ESP_LOGI(TAG, "task wdt: 30s, idle unmonitored, panic=reboot");
    }
}
#endif

/* 第 3 层: CLI/REPL 独享 32KB 栈 */
static void cli_task(void *arg)
{
    (void)arg;
    esp_err_t err = cli_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "cli_start failed: %s", esp_err_to_name(err));
        rgb_led_set_status(RGB_ERROR);
    }
    vTaskDelete(NULL);
}

/* 第 2 层: RGB + Wi-Fi init 独享 32KB 栈 */
static void init_task(void *arg)
{
    (void)arg;

#if CONFIG_ESP_TASK_WDT_EN
    /* 0. 受控看门狗 (最先做, 之后任何卡死都能自愈) */
    wdt_init_controlled();
#endif

    /* 1. RGB (启动紫色) */
    esp_err_t err = rgb_led_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "RGB init failed: %s (继续, 无灯)", esp_err_to_name(err));
    }

    /* 2. Wi-Fi 攻击模块 (峰值 ~16KB 栈) */
    err = wifi_attack_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_attack_init failed: %s", esp_err_to_name(err));
        rgb_led_set_status(RGB_ERROR);
    }

    /* NVS 配置持久化 (在 wifi_attack_init 的 nvs_flash_init 之后) */
    config_init();

    /* 事件总线 (要早于各模块, 后续 start 事件才有人收) */
    event_bus_init();

    /* 3. 原始帧落盘: 定位 storage 分区 + 起 flusher 任务.
     *    必须在创建 CLI 任务之前完成, 否则 CLI 起来后立刻敲 cap info
     *    会看到还没初始化的容量 (0). */
    esp_err_t cerr = cap_init();
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG, "cap_init failed: %s (原始帧落盘不可用)", esp_err_to_name(cerr));
    }

    /* 4. EAPOL 握手跟踪: 归档 M1..M4 + PMKID, 供导出 hashcat 22000 */
    hs_init();

    /* 4b. FTM 测距事件处理. 必须在 esp_wifi_init 之后注册. */
    {
        esp_err_t ferr = ftm_init();
        if (ferr != ESP_OK) {
            ESP_LOGW(TAG, "ftm_init: %s (FTM 测距不可用)", esp_err_to_name(ferr));
        }
    }

    /* OTA 启动自检. 若当前固件是刚 OTA 进来、还没被确认的,
     *     起 45s 窗口; 期间崩溃则由引导器回滚到旧分区. */
    {
        esp_err_t oerr = ota_init();
        if (oerr != ESP_OK) {
            ESP_LOGW(TAG, "ota_init: %s", esp_err_to_name(oerr));
        }
    }

    /* 5. 创建 CLI 任务.
     *    内部 RAM 很紧 (WiFi + NimBLE 抢得厉害), 32KB 栈的连续块经常申请不到
     *    → 20000 字节 (最深调用链约 8KB, 仍有 2.5x 余量). */
    ESP_LOGI(TAG, "internal free=%u largest=%u", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    BaseType_t r = xTaskCreate(cli_task, "cli", 20480, NULL, 24, NULL);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(cli) FAILED");
        rgb_led_set_status(RGB_ERROR);
    }

    /* 6. 启动 BLE GATT 服务 (手机直连收发 CLI 命令) */
    esp_err_t berr = ble_cli_start();
    if (berr != ESP_OK) {
        ESP_LOGW(TAG, "ble_cli_start failed: %s (BLE 不可用, 仅 UART)", esp_err_to_name(berr));
    } else {
        /* 初始化 bleadv (信号量等), 在 BLE host 启动后调用 */
        bleadv_init();
    }

    vTaskDelete(NULL);
}

/* 第 1 层: main task 只创建 init_task */
void app_main(void)
{
    BaseType_t r = xTaskCreate(init_task, "rf_init", 32768, NULL, 5, NULL);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "FATAL: xTaskCreate(init_task) failed");
    }
}
