#include "radio_hal.h"

/* 空实现: 未安装真机 HAL 时兜底.
 * 之所以不直接对 NULL 判空, 是为了让调用方只写 radio_hal()->xxx(...) 一处判断,
 * 不必在每个调用点都写 if. 返回值表明"没干成", 不会静默成功. */
static esp_err_t null_tx(const uint8_t *frame, int len, bool sys_seq)
{
    (void)frame;
    (void)len;
    (void)sys_seq;
    return ESP_ERR_INVALID_STATE;
}

static void null_random(void *out, size_t n)
{
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < n; i++) p[i] = 0;
}

static uint32_t null_millis(void) { return 0; }

static const radio_hal_t k_null = {
    .tx_mgmt = null_tx,
    .random_bytes = null_random,
    .millis = null_millis,
};

static const radio_hal_t *s_hal;

const radio_hal_t *radio_hal(void)
{
    return s_hal ? s_hal : &k_null;
}

void radio_hal_set(const radio_hal_t *h)
{
    s_hal = h;
}
