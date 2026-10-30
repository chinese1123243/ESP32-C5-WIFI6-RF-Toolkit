/* 真机 HAL 实现. 全工程只有这一个文件允许把 esp_wifi_80211_tx / esp_fill_random
 * / esp_timer_get_time 直接暴露给领域代码. */

#include "radio_hal.h"

#include <stdint.h>

#include "esp_wifi.h"
#include "esp_random.h"
#include "esp_timer.h"

static esp_err_t esp_tx_mgmt(const uint8_t *frame, int len, bool sys_seq)
{
    return esp_wifi_80211_tx(WIFI_IF_STA, frame, len, sys_seq);
}

static void esp_random_bytes(void *out, size_t n)
{
    esp_fill_random(out, n);
}

static uint32_t esp_millis(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static const radio_hal_t k_esp_hal = {
    .tx_mgmt = esp_tx_mgmt,
    .random_bytes = esp_random_bytes,
    .millis = esp_millis,
};

void radio_hal_esp_install(void)
{
    radio_hal_set(&k_esp_hal);
}
