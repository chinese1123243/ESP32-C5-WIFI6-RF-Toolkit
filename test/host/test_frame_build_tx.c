#include <stdio.h>
#include <string.h>

#include "frame_build.h"
#include "radio_hal.h"
#include "radio_hal_mock.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static const uint8_t BSSID[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t STA[6]   = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};

int main(void)
{
    radio_hal_mock_install();
    radio_hal_mock_t *m = radio_hal_mock();

    /* fb_tx 把帧原样交给 HAL, sys_seq 传 true */
    uint8_t f[64];
    int n = fb_deauth(f, (int)sizeof(f), BSSID, STA, 1);
    CHECK(n == 26, "deauth 组帧 26 字节");
    CHECK(m->tx_calls == 0, "组帧本身不发射");
    CHECK(fb_tx(f, n) == ESP_OK, "fb_tx 返回 ESP_OK");
    CHECK(m->tx_calls == 1, "HAL 收到一次发射");
    CHECK(m->last_len == 26, "发出去的是 26 字节");
    CHECK(m->last_tx[0] == 0xC0, "发出去的首字节是 0xC0");
    CHECK(m->last_sys_seq == true, "默认让驱动填序号");

    /* 数据帧 (type 2) 必须被挡在 HAL 之前, 不能送到驱动 */
    uint8_t data[32] = {0x08, 0x01, 0};
    int before = m->tx_calls;
    CHECK(fb_tx(data, 26) == ESP_ERR_INVALID_ARG, "数据帧被拒");
    CHECK(m->tx_calls == before, "数据帧没有下发");

    /* 驱动失败码要原样透传 */
    m->tx_ret = ESP_ERR_NO_MEM;
    CHECK(fb_tx(f, n) == ESP_ERR_NO_MEM, "驱动错误码透传");
    m->tx_ret = ESP_OK;

    /* fb_tx_hex: 太短要拒, 合法 hex 要发出去 */
    int out_len = 0;
    CHECK(fb_tx_hex("0011223344", &out_len) == ESP_ERR_INVALID_SIZE, "5 字节太短被拒");
    before = m->tx_calls;
    esp_err_t e = fb_tx_hex("c0000000aabbccddeeff0011223344550000", &out_len);
    CHECK(e == ESP_OK, "合法 hex 发射成功");
    CHECK(out_len == 18, "hex 解出 18 字节");
    CHECK(m->tx_calls == before + 1, "hex 路径确实发射了一次");
    CHECK(m->last_len == 18, "发出去 18 字节");

    /* 非法字符与奇数位 */
    CHECK(fb_tx_hex("zz11223344", &out_len) == ESP_ERR_INVALID_ARG, "非法 hex 字符被拒");
    CHECK(fb_tx_hex("c0000000aabbccddeeff001122334455000", &out_len) == ESP_ERR_INVALID_ARG,
          "奇数位被拒");

    /* 随机地址走 HAL, 且首字节 bit0=0 bit1=1 (本地管理单播) */
    uint8_t mac[6];
    memset(mac, 0xAA, sizeof(mac));
    fb_random_local_mac(mac);
    CHECK(m->rand_calls == 1, "随机数走 HAL");
    CHECK((mac[0] & 0x01) == 0, "首字节最低位清零 (单播)");
    CHECK((mac[0] & 0x02) != 0, "首字节次低位置位 (本地管理)");

    /* 未安装真机 HAL 也不能崩: 空实现返回 INVALID_STATE */
    radio_hal_set(NULL);
    CHECK(fb_tx(f, n) == ESP_ERR_INVALID_STATE, "无 HAL 时返回 INVALID_STATE 不崩");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
