/*
 * main.c — rftool 入口
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
#include "rgb_led.h"
#include "wifi_attack.h"
#include "cli.h"

static const char *TAG = "MAIN";

/* ====== 第 3 层: CLI/REPL 独享 32KB 栈 ====== */
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

/* ====== 第 2 层: RGB + Wi-Fi init 独享 32KB 栈 ====== */
static void init_task(void *arg)
{
    (void)arg;

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

    /* 3. 创建 CLI 任务 (32KB 独立栈: 极简 REPL 无需 esp_console 的 80KB+) */
    BaseType_t r = xTaskCreate(cli_task, "cli", 32768, NULL, 24, NULL);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(cli) FAILED");
        rgb_led_set_status(RGB_ERROR);
    }

    vTaskDelete(NULL);
}

/* ====== 第 1 层: main task 只创建 init_task ====== */
void app_main(void)
{
    BaseType_t r = xTaskCreate(init_task, "rf_init", 32768, NULL, 5, NULL);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "FATAL: xTaskCreate(init_task) failed");
    }
}
