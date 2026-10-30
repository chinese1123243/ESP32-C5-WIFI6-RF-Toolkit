#include <stdio.h>
#include <string.h>

#include "radio_hal_mock.h"
#include "zbtx_frame.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static uint8_t f[160];

int main(void)
{
    radio_hal_mock_install();
    radio_hal_mock_t *m = radio_hal_mock();

    /* --- Beacon --- */
    memset(f, 0xAA, sizeof(f));
    int n = zbtx_build_beacon(f, (int)sizeof(f), 0x1234, 11, 7);
    CHECK(n == 27, "beacon 总长 27");
    CHECK(f[0] == 26, "beacon 长度前缀 = 26 (不含自身)");
    /* FCF: type=0 (beacon), src mode=2 (short) -> 0x8000, 小端 */
    CHECK(f[1] == 0x00 && f[2] == 0x80, "beacon FCF = 0x8000");
    CHECK(f[3] == 7, "beacon seq");
    CHECK(f[4] == 0x34 && f[5] == 0x12, "beacon PAN 小端");
    CHECK(f[8] == 0xFF && f[9] == 0xCF, "superframe 0xFF 0xCF (BO=SO=15, coord, assoc)");
    CHECK(f[12] == 0x00 && f[13] == 0x12, "Zigbee 协议ID + stack profile");
    CHECK(f[14] == 0x05, "容量字节");

    /* 广播 PAN 不能当协调器: 0xFFFF 要落到 0xFFFE */
    n = zbtx_build_beacon(f, (int)sizeof(f), 0xFFFF, 11, 1);
    CHECK(n == 27, "广播 PAN 仍构造出 27");
    CHECK(f[4] == 0xFE && f[5] == 0xFF, "0xFFFF 改成 0xFFFE");

    /* pan=0 走 HAL 随机: mock 默认 0x02 -> PAN = 0x0202, 且必须调过 random */
    int before = m->rand_calls;
    n = zbtx_build_beacon(f, (int)sizeof(f), 0, 11, 1);
    CHECK(n == 27, "pan=0 也能构造");
    CHECK(m->rand_calls == before + 1, "pan=0 时向 HAL 要随机数");
    CHECK(f[4] == 0x02 && f[5] == 0x02, "随机 PAN 按小端写入");

    /* 容量不足必须拒绝 */
    uint8_t small[26];
    CHECK(zbtx_build_beacon(small, (int)sizeof(small), 0x1234, 11, 1) == 0, "cap 差 1 拒绝 beacon");

    /* --- Beacon Request --- */
    memset(f, 0xAA, sizeof(f));
    n = zbtx_build_beacon_req(f, (int)sizeof(f), 0x1234, 9);
    CHECK(n == 11, "beacon_req 总长 11");
    CHECK(f[0] == 10, "beacon_req 长度前缀 = 10");
    /* FCF: type=3 | dst mode 2 | src mode 2 | pan comp = 0x8843 */
    CHECK(f[1] == 0x43 && f[2] == 0x88, "beacon_req FCF = 0x8843");
    CHECK(f[3] == 9, "beacon_req seq");
    CHECK(f[4] == 0xFF && f[5] == 0xFF, "dst PAN 广播");
    CHECK(f[6] == 0xFF && f[7] == 0xFF, "dst 短地址广播");
    CHECK(f[10] == 0x07, "命令 ID 7 = Beacon Request");
    uint8_t small2[10];
    CHECK(zbtx_build_beacon_req(small2, (int)sizeof(small2), 0x1234, 1) == 0, "cap 差 1 拒绝 beacon_req");

    /* --- Data --- */
    const uint8_t pl[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    memset(f, 0xAA, sizeof(f));
    n = zbtx_build_data(f, (int)sizeof(f), 0x1234, 0x0001, 0x1234, 0x0002, pl, 4, 3);
    CHECK(n == 14, "data 总长 = 1 + 9 + 4");
    CHECK(f[0] == 13, "data 长度前缀 = 13");
    /* FCF: type=1 (data) | dst mode 2 | src mode 2 | pan comp = 0x8841 */
    CHECK(f[1] == 0x41 && f[2] == 0x88, "data FCF = 0x8841");
    CHECK(f[3] == 3, "data seq");
    CHECK(f[4] == 0x34 && f[5] == 0x12, "dst PAN 小端");
    CHECK(f[6] == 0x01 && f[7] == 0x00, "dst 短地址小端");
    CHECK(f[8] == 0x02 && f[9] == 0x00, "src 短地址小端");
    CHECK(memcmp(f + 10, pl, 4) == 0, "payload 原样跟在头后");

    /* plen 负数当 0 处理 */
    n = zbtx_build_data(f, (int)sizeof(f), 0x1234, 1, 0x1234, 2, pl, -5, 1);
    CHECK(n == 10, "plen<0 按 0 处理");

    /* plen 超上限要截断到 ZBTX_FRAME_MAX - 10 */
    /* 注意 cap 检查用的是未截断的 plen, 所以缓冲要能装下 1+9+plen 才走得到截断分支 */
    uint8_t big[300];
    uint8_t wide[400];
    memset(big, 0x5A, sizeof(big));
    n = zbtx_build_data(wide, (int)sizeof(wide), 0x1234, 1, 0x1234, 2, big, 300, 1);
    CHECK(n == ZBTX_FRAME_MAX, "plen 超限截断到 ZBTX_FRAME_MAX");
    CHECK(wide[0] == (uint8_t)(ZBTX_FRAME_MAX - 1), "截断后长度前缀自洽");

    /* 缓冲装不下未截断的 plen 时直接拒绝, 不是截断 */
    CHECK(zbtx_build_data(f, (int)sizeof(f), 0x1234, 1, 0x1234, 2, big, 300, 1) == 0,
          "cap 装不下原始 plen 时拒绝");

    /* cap 不足拒绝 */
    uint8_t small3[13];
    CHECK(zbtx_build_data(small3, (int)sizeof(small3), 0x1234, 1, 0x1234, 2, pl, 4, 1) == 0,
          "cap 差 1 拒绝 data");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
