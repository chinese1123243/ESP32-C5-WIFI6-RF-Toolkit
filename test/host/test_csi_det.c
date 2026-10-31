/* CSI 检测器的离线验证: 合成序列, 对比新旧判据.
 *
 * 三条序列:
 *   静默   背景 N(0.10, 0.02), 9000 样本 (按 16Hz 约 9.4 分钟) -> 数误报
 *   阶跃   静默 600 样本后进 N(0.35, 0.02) -> 数检出延迟
 *   慢变   0.10 线性爬到 0.30, 400 样本 -> 看会不会漏
 *
 * 旧判据 = metric > 2*base && metric > 0.15, base 为 0.02 的匀速 EWMA.
 */
#include <math.h>
#include <stdio.h>

#include "csi_det.h"

static int g_fail;
static int g_pass;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { printf("  FAIL  %s\n", what); g_fail++; }                    \
    } while (0)

/* 确定性 LCG + Box-Muller, 不依赖 libc 的 rand 实现 */
static unsigned s_seed = 12345u;
static float urand(void)
{
    s_seed = s_seed * 1664525u + 1013904223u;
    return ((s_seed >> 8) & 0xFFFFFF) / 16777216.0f;
}
static float gauss(float mu, float sd)
{
    float u1 = urand();
    if (u1 < 1e-7f) u1 = 1e-7f;
    float u2 = urand();
    return mu + sd * sqrtf(-2.0f * logf(u1)) * cosf(6.2831853f * u2);
}

/* 旧判据 */
static bool old_rule(float *base, float metric)
{
    if (*base < 0.0f) *base = metric;
    else *base = *base * 0.98f + metric * 0.02f;
    return metric > (*base * 2.0f) && metric > 0.15f;
}

int main(void)
{
    /* ---------- 静默: 误报 ---------- */
    {
        csi_det_t d;
        csi_det_reset(&d);
        int fp_new = 0;
        bool prev = false;
        for (int i = 0; i < 9000; i++) {
            bool m = csi_det_update(&d, gauss(0.10f, 0.02f));
            if (m && !prev) fp_new++;
            prev = m;
        }
        float b = -1.0f;
        int fp_old = 0;
        prev = false;
        s_seed = 12345u;          /* 同一条序列 */
        for (int i = 0; i < 9000; i++) {
            bool m = old_rule(&b, gauss(0.10f, 0.02f));
            if (m && !prev) fp_old++;
            prev = m;
        }
        printf("静默 9000 样本: 新判据误报 %d 次, 旧判据误报 %d 次\n", fp_new, fp_old);
        CHECK(fp_new <= 2, "静默场景误报 <= 2 次 / 9.4 分钟");
    }

    /* ---------- 阶跃: 检出延迟 ---------- */
    {
        csi_det_t d;
        csi_det_reset(&d);
        for (int i = 0; i < 600; i++) csi_det_update(&d, gauss(0.10f, 0.02f));
        int latency = -1;
        for (int i = 0; i < 200; i++) {
            if (csi_det_update(&d, gauss(0.35f, 0.02f)) && latency < 0) latency = i;
        }
        printf("阶跃 0.10->0.35: 新判据延迟 %d 样本\n", latency);
        CHECK(latency >= 0 && latency <= 3, "阶跃延迟 <= 3 样本");
    }

    /* ---------- 慢变: 线性爬坡 ---------- */
    {
        csi_det_t d;
        csi_det_reset(&d);
        for (int i = 0; i < 600; i++) csi_det_update(&d, gauss(0.10f, 0.02f));
        /* 从"均值越过 0.15"那一刻开始算延迟: 在此之前信号本来就在背景里,
         * 报 motion 只能说明是噪声, 不能算检出. */
        int cross = -1, det = -1;
        for (int i = 0; i < 400; i++) {
            float mu = 0.10f + 0.20f * (float)i / 400.0f;
            bool m = csi_det_update(&d, gauss(mu, 0.02f));
            if (cross < 0 && mu >= 0.15f) cross = i;
            if (cross >= 0 && m && det < 0) det = i;
        }
        printf("慢变 0.10->0.30 / 400 样本: 半程在 %d, 检出在 %d (滞后 %d 样本)\n",
               cross, det, det < 0 ? -1 : det - cross);
        CHECK(det >= 0 && (det - cross) <= 120, "慢变在半程后 120 样本内检出");
    }

    /* ---------- 长动作不许被学成背景 ---------- */
    {
        csi_det_t d;
        csi_det_reset(&d);
        for (int i = 0; i < 200; i++) csi_det_update(&d, gauss(0.10f, 0.02f));
        int still = 0;
        for (int i = 0; i < 1600; i++) {
            if (csi_det_update(&d, gauss(0.35f, 0.02f))) still++;
        }
        /* 1600 样本 = 100 秒持续动作, 旧判据的 base 会爬到 0.35 附近然后停报 */
        printf("持续动作 1600 样本: 新判据仍报 %d 次 (%.0f%%)\n",
               still, 100.0f * (float)still / 1600.0f);
        CHECK(still > 1500, "持续动作期间保持检出");

        /* 同一条序列给旧判据: 基线会爬到动作电平上, 报着报着就停 */
        float b = -1.0f;
        int old_still = 0;
        s_seed = 777u;
        for (int i = 0; i < 200; i++) old_rule(&b, gauss(0.10f, 0.02f));
        for (int i = 0; i < 1600; i++) {
            if (old_rule(&b, gauss(0.35f, 0.02f))) old_still++;
        }
        printf("持续动作 1600 样本: 旧判据只报 %d 次 (%.0f%%), 基线被自己学走\n",
               old_still, 100.0f * (float)old_still / 1600.0f);
        CHECK(old_still < 900, "旧判据在持续动作下会漏报 (对照用)");
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
