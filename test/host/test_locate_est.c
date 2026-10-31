/* RSSI 估计器的离线对照: 均值 vs 截尾均值 vs 中位数.
 *
 * 信道模型: 真实均值 m, 每个样本 = m + N(0, sigma) + 多径深衰落.
 * 深衰落按概率 q 发生, 幅度 U(6,15)dB 向下, 模拟同一 AP 的直达径被挡住.
 *
 * 指标是 RMSE(估计 - m). 这直接决定"定位时把 RSSI 换算成距离"的误差:
 * 路径损耗 3dB 对应距离约 1.4 倍 (n=2 时), 所以 4dB 的 RMSE 已经是米级误差.
 */
#include <math.h>
#include <stdio.h>

#include "locate_est.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

static unsigned s_seed = 20261031u;
static float urand(void)
{
    s_seed = s_seed * 1664525u + 1013904223u;
    return ((s_seed >> 8) & 0xFFFFFF) / 16777216.0f;
}
static float gauss(float sd)
{
    float u1 = urand();
    if (u1 < 1e-7f) u1 = 1e-7f;
    return sd * sqrtf(-2.0f * logf(u1)) * cosf(6.2831853f * urand());
}

/* 生成一帧样本, 返回真实均值 */
static float gen(int16_t *v, int n, float sigma, float q)
{
    const float m = -55.0f;
    for (int i = 0; i < n; i++) {
        float x = m + gauss(sigma);
        if (urand() < q) x -= 6.0f + 9.0f * urand();   /* 深衰落 6~15dB */
        v[i] = (int16_t)lrintf(x);
    }
    return m;
}

static void run(int n, float sigma, float q, int trials)
{
    int16_t v[128], scratch[128];
    double se_mean = 0, se_trim = 0, se_med = 0;
    for (int t = 0; t < trials; t++) {
        float m = gen(v, n, sigma, q);
        loc_stat_t st;
        loc_estimate(v, n, scratch, &st);
        double e1 = st.mean - m, e2 = st.trimmed - m, e3 = st.median - m;
        se_mean += e1 * e1;
        se_trim += e2 * e2;
        se_med  += e3 * e3;
    }
    printf("  n=%3d sigma=%.0f 离群=%2.0f%%   均值 RMSE %.2f dB   截尾 %.2f dB   中位 %.2f dB\n",
           n, sigma, q * 100, sqrt(se_mean / trials), sqrt(se_trim / trials),
           sqrt(se_med / trials));
}

int main(void)
{
    printf("=== RSSI 估计器对照 (每种 400 次) ===\n");
    run(16, 3.0f, 0.00f, 400);
    run(32, 2.5f, 0.10f, 400);
    run(32, 2.5f, 0.20f, 400);
    run(64, 2.5f, 0.20f, 400);
    run(64, 5.0f, 0.30f, 400);

    /* 结论性断言: 离群 20% 时, 中位数必须比均值稳 */
    {
        int16_t v[64], scratch[64];
        double se_m = 0, se_med = 0;
        const int trials = 600;
        for (int t = 0; t < trials; t++) {
            float m = gen(v, 64, 2.5f, 0.20f);
            loc_stat_t st;
            loc_estimate(v, 64, scratch, &st);
            double a = st.mean - m, b = st.median - m;
            se_m += a * a; se_med += b * b;
        }
        double rm = sqrt(se_m / trials), rd = sqrt(se_med / trials);
        printf("\n离群 20%% / n=64: 均值 %.2f dB, 中位 %.2f dB\n", rm, rd);
        CHECK(rd < rm, "离群 20% 时中位数优于均值");
    }

    /* 无离群时均值不该被甩开太多 (中位数有信息损失) */
    {
        int16_t v[64], scratch[64];
        double se_m = 0, se_med = 0;
        const int trials = 600;
        for (int t = 0; t < trials; t++) {
            float m = gen(v, 64, 2.5f, 0.0f);
            loc_stat_t st;
            loc_estimate(v, 64, scratch, &st);
            double a = st.mean - m, b = st.median - m;
            se_m += a * a; se_med += b * b;
        }
        double rm = sqrt(se_m / trials), rd = sqrt(se_med / trials);
        printf("无离群 / n=64:   均值 %.2f dB, 中位 %.2f dB\n", rm, rd);
        CHECK(rd < rm * 1.6, "无离群时中位数不显著劣于均值");
    }

    /* 趋势: 单调下降 10dB 的序列应给出负斜率 */
    {
        int16_t v[64], scratch[64];
        for (int i = 0; i < 64; i++) v[i] = (int16_t)(-50 - i / 3);
        int tr = loc_trend(v, 64, scratch);
        printf("趋势: 64 样本下降 21dB -> 每 10 样本 %d dB\n", tr);
        CHECK(tr < -2, "单调下降序列给出负斜率");
    }

    /* 有单点深衰落时, 趋势不该被带成正的 */
    {
        int16_t v[64], scratch[64];
        for (int i = 0; i < 64; i++) v[i] = -50;
        v[2] = -75;            /* 一个深衰落点 */
        int tr = loc_trend(v, 64, scratch);
        printf("趋势: 平坦序列插一个 -75 点 -> 每 10 样本 %d dB\n", tr);
        CHECK(tr > -2 && tr < 2, "单点深衰落不改变趋势判定");
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
