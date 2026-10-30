#include "radio_hal_mock.h"

#include <string.h>

#include "radio_hal.h"

static radio_hal_mock_t g;

static esp_err_t mock_tx(const uint8_t *frame, int len, bool sys_seq)
{
    g.tx_calls++;
    g.last_len = len;
    g.last_sys_seq = sys_seq;
    if (frame && len > 0 && len <= (int)sizeof(g.last_tx)) {
        memcpy(g.last_tx, frame, (size_t)len);
    }
    return g.tx_ret;
}

static void mock_random(void *out, size_t n)
{
    g.rand_calls++;
    memset(out, g.rand_fill, n);
}

static uint32_t mock_millis(void) { return 1234; }

static const radio_hal_t k_mock = {
    .tx_mgmt = mock_tx,
    .random_bytes = mock_random,
    .millis = mock_millis,
};

void radio_hal_mock_install(void)
{
    memset(&g, 0, sizeof(g));
    g.tx_ret = ESP_OK;
    g.rand_fill = 0x02;
    radio_hal_set(&k_mock);
}

radio_hal_mock_t *radio_hal_mock(void) { return &g; }
