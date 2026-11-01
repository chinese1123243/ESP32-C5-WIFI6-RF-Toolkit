/* 算法层的主机测试: 直接编 main/ 下的纯函数文件, 不碰 ESP-IDF.
 *
 * 为什么要有这一层: 真机测试只能证明"整条链路没炸", 证明不了边界行为.
 * 这里的断言覆盖单调性、夹取边界、抗离群、检测器的误报/漏报, 改算法时先在这
 * 里红, 再上板.
 *
 * 编译运行: bash tests/host/run.sh
 */

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chan_sched.h"
#include "csi_det.h"
#include "locate_est.h"

static int g_fail, g_pass;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (cond) { g_pass++; }                                                \
        else { g_fail++; printf("FAIL %s:%d  ", __FILE__, __LINE__);           \
               printf(__VA_ARGS__); printf("\n"); }                            \
    } while (0)

#define NEAR(a, b, tol, ...) CHECK(fabs((double)(a) - (double)(b)) <= (tol), __VA_ARGS__)

/* ---------- chan_sched: SACS ---------- */

static void test_dwell_opt(void)
{
    /* 切换 20ms / beacon 102.4ms: e^-x(x+0.195+1)=1 的解 x≈0.56 */
    uint32_t d = chan_dwell_opt(20);
    CHECK(d >= 50 && d <= 65, "chan_dwell_opt(20)=%u, 期望 50..65", d);

    /* 切换开销越大, 值得待得越久 */
    uint32_t d2 = chan_dwell_opt(60);
    CHECK(d2 > d, "opt(60)=%u 应大于 opt(20)=%u", d2, d);

    /* 开关开销为 0 时解应是 0 (只是无穷小的驻留就够) */
    CHECK(chan_dwell_opt(0) <= 2, "opt(0)=%u 应接近 0", chan_dwell_opt(0));
}

static void test_residual(void)
{
    /* 单台、零暴露: k*s/(1-s) 在 s→1 时发散, 用 floor 1e-3 夹住 */
    float r0 = chan_residual(1, 0);
    CHECK(r0 > 0.0f && r0 < 1000.0f, "residual(1,0)=%.1f 应有界", r0);

    /* 暴露越长, 剩余量越小 */
    float a = chan_residual(4, 150);
    float b = chan_residual(4, 400);
    float c = chan_residual(4, 1200);
    CHECK(a > b && b > c, "剩余量应随曝光递减: %.2f %.2f %.2f", a, b, c);

    /* 4 台已找到、暴露 400ms: s=0.75*e^-3.9+0.25*e^-1.95 ≈ 0.0559
     * r = 4*0.0559/0.944 ≈ 0.237 */
    NEAR(b, 0.24f, 0.04f, "residual(4,400)=%.3f 期望 ≈0.24", b);

    /* 空信道的后验随曝光衰减, 但永远大于 0 (不能判死) */
    float e1 = chan_residual(0, 250);
    float e2 = chan_residual(0, 5000);
    CHECK(e1 > 0.0f && e2 > 0.0f && e1 > e2,
          "空信道后验应递减且为正: %.3f %.3f", e1, e2);
    CHECK(e2 > 0.0f, "探过很久也不能判死, 否则中途上线的 AP 永远等不到");
}

static void test_dwell_sat(void)
{
    /* k<2 只给探针 */
    CHECK(chan_dwell_sat(100, 1200, 0, 0, 200) == 100, "k=0 应回探针");
    CHECK(chan_dwell_sat(100, 1200, 1, 1000, 200) == 100, "k=1 应回探针");

    /* k=9 需要 bi*ln(11/0.2)=411ms */
    uint32_t d = chan_dwell_sat(100, 1200, 9, 0, 200);
    CHECK(d >= 380 && d <= 440, "k=9 的饱和驻留 %u, 期望 ≈411", d);

    /* 已经压满就回探针 */
    CHECK(chan_dwell_sat(100, 1200, 9, 2000, 200) == 100, "压满后应回探针");

    /* 夹取: cap 很小时不超过 cap */
    CHECK(chan_dwell_sat(100, 150, 9, 0, 200) == 150, "应夹到 cap");
}

/* ---------- chan_sched: PSD 排序 ---------- */

static void test_psd_order(void)
{
    uint8_t chans[5] = {6, 1, 11, 36, 44};
    uint16_t w[64] = {0};
    uint8_t out[5];
    w[6] = 9; w[1] = 7; w[11] = 5; w[36] = 1;
    int n = chan_psd_order(chans, w, 5, out);
    CHECK(n == 5, "排序返回 %d", n);
    CHECK(out[0] == 6 && out[1] == 1 && out[2] == 11 && out[3] == 36,
          "降序错: %u %u %u %u", out[0], out[1], out[2], out[3]);
    /* 权重相同 (都是 0) 时保持原顺序: 36 与 44 都是 0, 但 36 权重 1 */
    CHECK(out[4] == 44, "尾部应是最低权重且保持原序: %u", out[4]);
}

/* ---------- locate_est ---------- */

static void test_locate(void)
{
    /* 20% 的多径离群: 真值 -60 附近, 插入 4 个 -85 */
    int16_t v[20] = {-59, -61, -60, -58, -62, -60, -59, -61,
                     -85, -86, -60, -59, -61, -60, -85, -58,
                     -60, -61, -59, -86};
    int16_t scratch[20];
    loc_stat_t st;
    loc_estimate(v, 20, scratch, &st);

    CHECK(st.n == 20, "n=%d", st.n);
    CHECK(st.median >= -61 && st.median <= -59, "中位数 %d 被离群带偏", st.median);
    CHECK(st.trimmed >= -61 && st.trimmed <= -59, "截尾均值 %d 被离群带偏", st.trimmed);
    CHECK(st.mean < st.trimmed, "算术均值应低于截尾均值 (被离群拉低)");
    CHECK(st.mad >= 0 && st.mad <= 4, "mad=%d 应很小", st.mad);

    /* 单调趋势: 每 10 个样本 -3dB */
    int16_t t[40];
    for (int i = 0; i < 40; i++) t[i] = (int16_t)(-50 - i * 3 / 10);
    int tr = loc_trend(t, 40, scratch);
    CHECK(tr < 0, "远离时应为负趋势, 得到 %d", tr);

    /* 样本不足时不出结论 */
    CHECK(loc_trend(t, 4, scratch) == 0, "n<8 应回 0");

    /* 中位数标准误: mad=2, n=20 -> 1.253*2/sqrt(20)=0.56, 取整 1 */
    int16_t flat[20];
    for (int i = 0; i < 20; i++) flat[i] = (int16_t)(-60 + ((i % 3) - 1) * 2);
    loc_estimate(flat, 20, scratch, &st);
    CHECK(st.se >= 1 && st.se <= 2, "se=%d, mad=%d, 期望 1..2", st.se, st.mad);

    /* 真实斜率 -3dB/10样本应显著; 噪声更大的序列, 置信半宽应更大 */
    int ci_small = loc_trend_ci(t, 40, scratch);
    /* 样本少 + 抖得厉害时半宽必须变大: 16 个点、±8dB, k=4, span=12
     * se = 1.253*mad*sqrt(2/4)*10/12, mad≈4 -> 半宽约 6dB */
    int16_t noisy[16];
    for (int i = 0; i < 16; i++) noisy[i] = (int16_t)(-50 + ((i * 37) % 17) - 8);
    int ci_big = loc_trend_ci(noisy, 16, scratch);
    CHECK(ci_small <= 1, "干净慢变序列的半宽 %d 应 ≤1", ci_small);
    CHECK(ci_big >= 3, "16 点 ±8dB 的半宽只有 %d, 明显偏小", ci_big);
    CHECK(abs(tr) > ci_small || ci_small == 0, "趋势 %d 应超过半宽 %d", tr, ci_small);
}

/* ---------- locate_est: 拐点检测 ---------- */

static unsigned rnd_state = 12345;
static int rnd(void)
{
    /* xorshift32: 简单 lcg 的低位质量太差, Box-Muller 会有可见的周期纹 */
    unsigned x = rnd_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rnd_state = x;
    return (int)(x & 0x7fffffff);
}

/* 高斯白噪声 (Box-Muller, 统计品质够用) */
static float gauss(float sigma)
{
    float u1 = (rnd() + 1) / 2147483648.0f, u2 = (rnd() + 1) / 2147483648.0f;
    return sigma * sqrtf(-2.0f * logf(u1)) * cosf(6.2832f * u2);
}

/* 合成循迹序列: d = |d0 - v*t|, RSSI = A - 25*log10(d) + 噪声, 可选衰落.
 * 返回真峰的样本序号. 2Hz 采样, 与 scripts/loc_turn_sim.py 同一模型. */
static int make_walk(int16_t *x, int n, float d0, float v, float sigma, float fade_p)
{
    int peak = -1;
    float fade_db = 0.0f;
    int fade_left = 0;
    for (int t = 0; t < n; t++) {
        float d = d0 - v * t * 0.5f;
        if (d < 0) d = -d;
        if (d < 0.3f) d = 0.3f;
        if (fade_left > 0) {
            fade_left--;
        } else {
            fade_db = 0.0f;
            if ((rnd() / 2147483648.0f) < fade_p) {
                fade_left = (rnd() & 1);
                fade_db = -(6.0f + 8.0f * (rnd() / 2147483648.0f));
            }
        }
        if (peak < 0 && d0 - v * t * 0.5f <= 0) peak = t;
        x[t] = (int16_t)(45.0f - 25.0f * log10f(d) + gauss(sigma) + fade_db);
    }
    return peak;
}

/* 喂完整条序列, 返回是否开火 (开火即停止喂) */
static int feed_turn(const int16_t *v, int n, loc_turn_t *st, int16_t *scratch, int *fire_t)
{
    loc_turn_reset(st);
    *fire_t = -1;
    for (int t = 1; t < n; t++) {
        if (loc_turn_update(st, v, t + 1, scratch)) {
            *fire_t = t;
            return 1;
        }
    }
    return 0;
}

static void test_turn(void)
{
    int16_t v[130];
    int16_t scratch[LOC_TURN_SCR];
    loc_turn_t st;
    int ft;

    /* 场景 1: 快步接近后越过 (10m, 1m/s, 峰在样本 20) */
    int fires = 0, delay_ok = 0, peak_ok = 0;
    for (int r = 0; r < 50; r++) {
        int peak = make_walk(v, 120, 10.0f, 1.0f, 3.0f, 0.10f);
        if (feed_turn(v, 120, &st, scratch, &ft)) {
            fires++;
            if (ft - peak <= 30) delay_ok++;
            if (st.p_lock > -60 && st.p_lock < 60) peak_ok++;   /* 电平要合理 */
        }
    }
    CHECK(fires >= 35, "快步通过 50 局只检出 %d, 应 >=35", fires);
    CHECK(delay_ok == fires, "检出里 %d/%d 延迟超过 15s", fires - delay_ok, fires);
    CHECK(peak_ok == fires, "锁定峰值电平 %d/%d 合理", fires - peak_ok, fires);

    /* 场景 2: 缓步接近后越过 (6m, 0.5m/s, 峰在样本 24) */
    fires = 0;
    for (int r = 0; r < 50; r++) {
        int peak = make_walk(v, 120, 6.0f, 0.5f, 3.0f, 0.10f);
        if (feed_turn(v, 120, &st, scratch, &ft)) {
            fires++;
            if (ft - peak > 30) { g_fail++; printf("FAIL 缓步延迟 %d (峰 %d)\n", ft - peak, peak); }
        }
    }
    CHECK(fires >= 45, "缓步通过 50 局只检出 %d, 应 >=45", fires);

    /* 场景 3: 静止 (5m 不动): 误报要稀少, 50 局 <= 3 */
    fires = 0;
    for (int r = 0; r < 50; r++) {
        (void)make_walk(v, 120, 5.0f, 0.0f, 3.0f, 0.10f);
        if (feed_turn(v, 120, &st, scratch, &ft)) fires++;
    }
    CHECK(fires <= 3, "静止 50 局误报 %d, 应 <=3", fires);

    /* 场景 4: 一直远离 (从 1m 走远): 报"已越过"没有意义, 50 局 <= 3 */
    fires = 0;
    for (int r = 0; r < 50; r++) {
        (void)make_walk(v, 120, 1.0f, 0.5f, 3.0f, 0.10f);
        if (feed_turn(v, 120, &st, scratch, &ft)) fires++;
    }
    CHECK(fires <= 3, "远离 50 局误报 %d, 应 <=3", fires);

    /* 历史不足时不能开火, 也不能把状态搞挂 */
    loc_turn_reset(&st);
    for (int t = 1; t <= LOC_TURN_MIN_N - 1; t++) {
        v[t] = -60;
        CHECK(loc_turn_update(&st, v, t + 1, scratch) == 0, "n=%d 不应开火", t + 1);
    }
}

/* ---------- csi_det ---------- */

static void test_csi(void)
{
    csi_det_t d;
    csi_det_reset(&d);

    /* 静止: 120 个样本围绕 1.0 抖动 ±2%, 不应报动作 */
    int fp = 0;
    for (int i = 0; i < 120; i++) {
        float m = 1.0f + ((i % 5) - 2) * 0.01f;
        if (csi_det_update(&d, m)) fp++;
    }
    CHECK(fp == 0, "静止场景误报 %d 次", fp);

    /* 持续动作: 先静止 40 个样本把基线学稳, 再持续抬高 60% 共 200 个样本.
     * 必须从头报到尾 (旧判据十秒内就会把动作学成背景, 之后一直不报). */
    csi_det_reset(&d);
    for (int i = 0; i < 40; i++) csi_det_update(&d, 1.0f + ((i % 5) - 2) * 0.01f);
    int hit = 0, total = 0;
    for (int i = 0; i < 200; i++) {
        float m = 1.60f + ((i % 3) - 1) * 0.02f;
        total++;
        if (csi_det_update(&d, m)) hit++;
    }
    CHECK(total > 0 && hit * 10 >= total * 9, "持续动作只报 %d/%d", hit, total);

    /* 动作结束要能退出, 不能一直挂着 */
    int still = 0;
    for (int i = 0; i < 30; i++) {
        if (csi_det_update(&d, 1.0f)) still++;
    }
    /* 退出要满足 hold>=CSI_DET_HOLD_N 个样本才落回, 前几个样本仍报是设计 */
    CHECK(still <= CSI_DET_HOLD_N, "动作结束后仍报了 %d 次 (允许 %d)",
          still, CSI_DET_HOLD_N);
}


static void test_coherence(void)
{
    /* 门控把"微波炉"和"有人走动"分开: 合成分真时前者一致率 0.49~0.53,
     * 后者 0.80~0.88, 而两者的幅度指标只差 1.5 倍. */
    enum { N = 32 };
    int16_t cur[N];
    float   ref[N];

    /* 1) 两帧完全一样: 无证据, 必须回 0.5 (回 0 会让静止环境永远被门控挡住) */
    for (int i = 0; i < N; i++) { cur[i] = 1000; ref[i] = 1000.0f / 1000.0f; }
    NEAR(csi_coherence(cur, ref, N, 1.0f / 1000.0f), 0.5, 1e-6, "全同帧应为 0.5");

    /* 2) 残差同号 (真实运动: 整条路径相位旋转, 频率轴上连续同向) */
    for (int i = 0; i < N; i++) {
        ref[i] = 0.5f;
        cur[i] = (int16_t)((0.5f + 0.002f * (i + 1)) * 1000.0f);
    }
    NEAR(csi_coherence(cur, ref, N, 1.0f / 1000.0f), 1.0, 1e-6, "单调残差应全同向");

    /* 3) 残差交替变号 (窄带干扰之外的白噪声就是这种) */
    for (int i = 0; i < N; i++) {
        ref[i] = 0.5f;
        cur[i] = (int16_t)((0.5f + ((i & 1) ? 0.002f : -0.002f)) * 1000.0f);
    }
    NEAR(csi_coherence(cur, ref, N, 1.0f / 1000.0f), 0.0, 1e-6, "交替残差应全反向");

    /* 4) 单个子载波跳变, 其余不动: 微波炉的样子, 一致率必须低到门限以下 */
    for (int i = 0; i < N; i++) {
        ref[i] = 0.5f;
        cur[i] = (int16_t)(0.5f * 1000.0f);
    }
    cur[7] = 900;
    float c = csi_coherence(cur, ref, N, 1.0f / 1000.0f);
    CHECK(c < CSI_DET_COH_MIN, "单点跳变的一致率 %.2f 不应过门限 %.2f", c, CSI_DET_COH_MIN);

    /* 5) 样本太少 / 缩放非法: 回中性值, 不能让调用方拿到 NaN */
    NEAR(csi_coherence(cur, ref, 2, 1.0f), 0.5, 1e-6, "n<3 应为 0.5");
    NEAR(csi_coherence(cur, ref, N, 0.0f), 0.5, 1e-6, "inv_norm=0 应为 0.5");

    /* 6) 门控本身: 内部判定为动作但一致率不够时不报, 一致率够了照报 */
    csi_det_t d;
    csi_det_reset(&d);
    for (int i = 0; i < 40; i++) csi_det_update(&d, 1.0f);
    CHECK(!csi_det_update_coh(&d, 1.9f, 0.5f), "一致率 0.50 时应被门控挡住");
    CHECK(csi_det_update_coh(&d, 1.9f, 0.9f), "一致率 0.90 时应放行");
}

int main(void)
{
    test_dwell_opt();
    test_residual();
    test_dwell_sat();
    test_psd_order();
    test_locate();
    test_turn();
    test_csi();
    test_coherence();
    printf("\n=== 结果: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
