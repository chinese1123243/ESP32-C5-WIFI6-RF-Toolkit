#include <stdio.h>

#include "chan_sched.h"

static int g_fail;
static int g_pass;

#define CHECK_EQ(got, want, what)                                           \
    do {                                                                    \
        if ((unsigned)(got) == (unsigned)(want)) { g_pass++; }               \
        else {                                                              \
            printf("  FAIL  %s  (got %u, want %u)\n", what,                  \
                   (unsigned)(got), (unsigned)(want));                      \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

int main(void)
{
    /* ---------- WR-λ ---------- */
    /* 样本不足 (mean<2): 均匀扫, 不做自适应 */
    CHECK_EQ(chan_dwell_wrl(300, 100, 1000, 0), 300, "mean<2 直接给 base");
    CHECK_EQ(chan_dwell_wrl(300, 100, 1000, 1), 300, "mean=1 也给 base");

    /* 收益率正好等于均值 -> 停留等于 base */
    CHECK_EQ(chan_dwell_wrl(300, 10, 1000, 10), 300, "r==mean 给 base");

    /* 冷信道: r=0, base×1/11 触发下限 max(base/6, 60) */
    CHECK_EQ(chan_dwell_wrl(300, 0, 1000, 10), 60, "冷信道落到下限 60");
    CHECK_EQ(chan_dwell_wrl(600, 0, 1000, 2), 200, "base=600 时下限是 200 (base/3 的 1/3)");

    /* 热信道: 远超均值, 触到上限 2×base */
    CHECK_EQ(chan_dwell_wrl(300, 5000, 1000, 10), 600, "热信道封顶 2×base");

    /* 上限绝对封顶 2000ms */
    CHECK_EQ(chan_dwell_wrl(1500, 5000, 1000, 10), 2000, "上限封顶 2000ms");

    /* 驻留不足 100ms 时样本不可靠, 按均值算 (即回 base) */
    CHECK_EQ(chan_dwell_wrl(300, 100, 50, 10), 300, "listen<100ms 按均值");

    /* ---------- PSD ---------- */
    /* 第一次接触一律给 base */
    CHECK_EQ(chan_dwell_psd(300, 0, 0, 0, 41), 300, "visits=0 给 base");
    CHECK_EQ(chan_dwell_psd(300, 99, 999, 0, 41), 300, "visits=0 即便 found 很高也给 base");

    /* 探过是空的: 40% 的探测下限, 便宜地复检 */
    CHECK_EQ(chan_dwell_psd(300, 0, 410, 5, 41), 150, "空信道 = 250×3/5");
    CHECK_EQ(chan_dwell_psd(200, 0, 410, 5, 41), 120, "base<250 时下限跟着降");

    /* 发现数等于均值 -> base */
    CHECK_EQ(chan_dwell_psd(300, 10, 410, 3, 41), 300, "found==mean 给 base");

    /* 开方抑制独占: 4 倍均值只拿 2 倍驻留, 不是 4 倍 */
    CHECK_EQ(chan_dwell_psd(300, 40, 410, 1, 41), 600, "4×均值 -> 2×base");
    CHECK_EQ(chan_dwell_psd(300, 20, 410, 1, 41), 424, "2×均值 -> sqrt(2)×base");

    /* 低于均值的信道不能低于探测下限 */
    CHECK_EQ(chan_dwell_psd(300, 1, 410, 1, 41), 250, "冷信道抬到 250");

    /* 绝对上限 */
    CHECK_EQ(chan_dwell_psd(1500, 40, 410, 1, 41), 2000, "PSD 上限封顶 2000ms");

    /* 除零保护 */
    CHECK_EQ(chan_dwell_psd(300, 5, 0, 1, 41), 150, "total=0 走空信道分支");
    CHECK_EQ(chan_dwell_psd(300, 5, 410, 1, 0), 150, "n_channels=0 走空信道分支");

    /* 探测下限常量本身 */
    CHECK_EQ(chan_dwell_floor(), 250, "探测下限 250ms");

    /* ---------- 排序 ---------- */
    const uint8_t ch[3] = {1, 6, 11};
    uint16_t w[256];
    uint8_t out[8];

    /* 发现数: 6 最多, 1 次之, 11 为空 */
    for (int i = 0; i < 256; i++) w[i] = 0;
    w[1] = 2; w[6] = 5; w[11] = 0;
    CHECK_EQ(chan_psd_order(ch, w, 3, out), 3, "排序返回信道数");
    CHECK_EQ(out[0], 6, "最热的排第一");
    CHECK_EQ(out[1], 1, "次热的排第二");
    CHECK_EQ(out[2], 11, "空信道排最后");

    /* 稳定性: 权重相同必须保持输入顺序, 否则每轮会来回抖 */
    for (int i = 0; i < 256; i++) w[i] = 3;
    chan_psd_order(ch, w, 3, out);
    CHECK_EQ(out[0], 1, "并列时保持原顺序 (1)");
    CHECK_EQ(out[1], 6, "并列时保持原顺序 (6)");
    CHECK_EQ(out[2], 11, "并列时保持原顺序 (11)");

    /* 空输入 */
    CHECK_EQ(chan_psd_order(ch, w, 0, out), 0, "n=0 返回 0");
    CHECK_EQ(chan_psd_order(NULL, w, 3, out), 0, "chans=NULL 返回 0");
    CHECK_EQ(chan_psd_order(ch, w, 3, NULL), 0, "out=NULL 返回 0");

    /* ---------- ADT: 按已发现台数反推饱和驻留 ---------- */
    /* 第一次接触给 base: 短探针在 102.4ms beacon 上只有三四成命中率 */
    CHECK_EQ(chan_dwell_adt(300, 0, 0, 50), 150, "首接触给下限的 60%");
    CHECK_EQ(chan_dwell_adt(300, 9, 0, 50), 150, "首接触不按台数加码");
    /* 探过但一台没发现: 只回探, 给下限 */
    CHECK_EQ(chan_dwell_adt(300, 0, 300, 50), 250, "空信道回探给下限");
    /* 9 台要 102.4*ln(9/0.05)=529.6ms; 已暴露 200ms, 还差 329ms */
    {
        unsigned d = chan_dwell_adt(300, 9, 200, 50);
        CHECK(d >= 325 && d <= 335, "9 台剩 329ms 左右");
    }
    CHECK_EQ(chan_dwell_adt(300, 1, 100, 50), 250, "差额不足下限时抬到下限");
    CHECK_EQ(chan_dwell_adt(300, 3, 2000, 50), 250, "已压满只回探");
    /* 30 台要 102.4*ln(600)=655ms, 已暴露 100ms, 还差 555ms (未触上限) */
    CHECK_EQ(chan_dwell_adt(300, 30, 100, 50), 555, "30 台还差 555ms");
    /* 已暴露很少时不夹的话会到 655ms, 超过 2*base=600 才夹 */
    CHECK_EQ(chan_dwell_adt(300, 30, 20, 50), 600, "超上限夹到 2*base");
    /* eps 从 5% 收到 0.6%: 9 台要 748ms, 已暴露 400ms, 还差 348ms */
    {
        unsigned d = chan_dwell_adt(300, 9, 400, 6);
        CHECK(d >= 344 && d <= 352, "eps=6 还差 348ms");
    }
    /* base 压到下限以下时, 上下限跟着降, 不许返回比 base 更大的值 */
    CHECK(chan_dwell_adt(150, 9, 0, 50) == 90, "小 base 首接触按 60% 下限");
    CHECK(chan_dwell_adt(150, 9, 1000, 50) <= 300, "小 base 上限 2*base");

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
