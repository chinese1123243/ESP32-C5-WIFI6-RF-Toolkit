#include "locate_est.h"

#include <math.h>
#include <stddef.h>
#include <string.h>
#ifdef LOC_TURN_DEBUG
#include <stdio.h>
#endif

static void sort_i16(int16_t *a, int n)
{
    /* 插入排序: n<=300, 每 2 秒一次, 不值得上快排的复杂度 */
    for (int i = 1; i < n; i++) {
        int16_t v = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > v) { a[j + 1] = a[j]; j--; }
        a[j + 1] = v;
    }
}

/* 中位数: 偶数个取中间两个的均值(向下取整), 不引入小数 */
static int median_of(const int16_t *sorted, int n)
{
    if (n <= 0) return 0;
    if (n & 1) return sorted[n / 2];
    return (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
}

void loc_estimate(const int16_t *v, int n, int16_t *scratch, loc_stat_t *out)
{
    if (!out) return;
    out->median = out->trimmed = out->mean = out->mad = 0;
    out->n = n;
    if (!v || !scratch || n <= 0) return;

    int sum = 0;
    for (int i = 0; i < n; i++) {
        scratch[i] = v[i];
        sum += v[i];
    }
    out->mean = sum / n;

    sort_i16(scratch, n);
    out->median = median_of(scratch, n);

    /* 截尾均值: 两端各去掉 20% (至少保留一半样本) */
    int cut = n / 5;
    if (cut * 2 >= n) cut = 0;
    int acc = 0, cnt = 0;
    for (int i = cut; i < n - cut; i++) { acc += scratch[i]; cnt++; }
    out->trimmed = cnt ? acc / cnt : out->median;

    /* MAD: 先算 |v - median|, 再取这些偏差的中位数 */
    for (int i = 0; i < n; i++) {
        int d = scratch[i] - out->median;
        scratch[i] = (int16_t)(d < 0 ? -d : d);
    }
    sort_i16(scratch, n);
    out->mad = median_of(scratch, n);

    /* 中位数的标准误: 1.253*mad/sqrt(n). 用整数算出"零点几 dB"再向上取整,
     * 免得 0.4dB 的误差被显示成 0 (那样看起来像"完全没有不确定度"). */
    if (n > 0) {
        float se = 1.253f * (float)out->mad / sqrtf((float)n);
        out->se = (int)(se + 0.5f);
    } else {
        out->se = 0;
    }
}

int loc_trend(const int16_t *v, int n, int16_t *scratch)
{
    if (!v || !scratch || n < 8) return 0;

    int k = n / 4;
    if (k < 4) k = 4;
    if (k * 2 > n) k = n / 2;

    for (int i = 0; i < k; i++) scratch[i] = v[i];                 /* 最早一段 */
    sort_i16(scratch, k);
    int first = median_of(scratch, k);

    for (int i = 0; i < k; i++) scratch[i] = v[n - k + i];         /* 最近一段 */
    sort_i16(scratch, k);
    int last = median_of(scratch, k);

    /* 换算成"每 10 个样本变化多少 dB": 两段中点相距 n-k 个样本 */
    int span = n - k;
    if (span <= 0) return 0;
    return (last - first) * 10 / span;
}


int loc_trend_ci(const int16_t *v, int n, int16_t *scratch)
{
    if (!v || !scratch || n < 8) return 0;
    int k = n / 4;
    if (k < 4) k = 4;
    if (k * 2 > n) k = n / 2;
    if (k < 2) return 0;

    /* 用整段样本的 mad 估计单点离散度, 再折算到"两段中位数之差" */
    loc_stat_t st;
    loc_estimate(v, n, scratch, &st);

    /* se(trend) = 1.253*mad*sqrt(2/k) * 10/(n-k) */
    float span = (float)(n - k);
    float se = 1.253f * (float)st.mad * sqrtf(2.0f / (float)k) * 10.0f / span;
    return (int)(1.96f * se + 0.5f);
}

/* 拐点检测 */

/* 阈值全部用半 dB 整数比较, 与仿真里的浮点门限一一对应:
 *   门 a  max(1.5σ, 4.0) -> max(3σ, 8)   x2
 *   门 b1 max(2.0σ, 5.5) -> max(4σ, 11)  x2
 *   门 b2 max(2.5σ, 7.0) -> max(5σ, 14)  x2
 *   下跌  max(3.0σ, 5.0) -> max(6σ, 10)  x2 */
#define TURN_X2(x) ((x) * 2)

static void isort(int16_t *a, int n)
{
    for (int i = 1; i < n; i++) {
        int16_t v = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > v) { a[j + 1] = a[j]; j--; }
        a[j + 1] = v;
    }
}

static int16_t med4(const int16_t *v)
{
    int16_t s[4];
    memcpy(s, v, sizeof(s));
    isort(s, 4);
    return (int16_t)((s[1] + s[2]) / 2);
}

static int16_t med3(int16_t *s)
{
    isort(s, 3);
    return s[1];
}

void loc_turn_reset(loc_turn_t *st)
{
    if (!st) return;
    st->phase = 0;
    st->p_lock = 0;
    st->lock_at = 0;
    st->cool_at = 0;
    st->votes = 0;
    st->t = 0;
}

int loc_turn_update(loc_turn_t *st, const int16_t *v, int n, int16_t *scratch)
{
    if (!st) return 0;
    st->t++;
    if (!v || !scratch || n < LOC_TURN_MIN_N) return 0;
    if ((st->t & 1) != 0) return 0;        /* 每 2 个样本评一次 */

    int t = n - 1;
    int B = LOC_TURN_B;

    /* sigma: |二阶差分| 的 q15, 见文件头注释. 与仿真一致, 满 32 个样本
     * (t>=34) 才开始评, 之前跳过不推进门控. */
    if (t < 34) return 0;
    int16_t *d2 = scratch;                 /* 32 个 */
    for (int i = 0; i < 32; i++) {
        int j = t - 31 + i;
        int d = (int)v[j] - 2 * (int)v[j - 1] + (int)v[j - 2];
        d2[i] = (int16_t)(d < 0 ? -d : d);
    }
    isort(d2, 32);
    int sigma_x2 = 2 * d2[4] * 216 / 100;  /* 2 * q15/0.463, 半 dB 单位 */
    if (sigma_x2 < 2) sigma_x2 = 2;

    /* 电平轨迹: back 越大越旧. 序列开头不足 2B+3 时只取已有的 back --
     * 仿真里这段部分窗是载荷-bearing 的: 快通过的武装发生在 t≈2B 附近,
     * 等全窗凑齐峰已经滑过, 之后再没有一把钥匙能开. */
    int oldest = (t - 3 >= 2 * B) ? 2 * B : t - 3;
    int avail = oldest - 3;                /* back 从 oldest 到 4 */
    if (avail < 12) return 0;
    int16_t *lv = scratch;                 /* 复用 d2 的空间, d2 已消费 */
    for (int i = 0; i < avail; i++) {
        int back = oldest - i;
        lv[i] = med4(&v[t - back - 3]);
    }

    if (st->phase == 0) {
        int n_older = oldest - B;          /* back oldest..B+1 */
        int n_newer = avail - n_older;     /* back B..4 */
        if (n_older < 8 || n_newer < 8) return 0;
        int16_t *older = scratch + avail;  /* 排序副本, 不动 lv */
        int16_t *newer = scratch + avail + n_older;
        memcpy(older, lv, n_older * sizeof(int16_t));
        memcpy(newer, lv + n_older, n_newer * sizeof(int16_t));
        isort(older, n_older);
        isort(newer, n_newer);

        int16_t *work = scratch + avail + n_older + n_newer;
        memcpy(work, lv, avail * sizeof(int16_t));
        isort(work, avail);
        int P = work[(avail - 1) * 80 / 100];      /* q80 */
        int m = (avail & 1) ? work[avail / 2]
                            : (work[avail / 2 - 1] + work[avail / 2]) / 2;
        int16_t head[3] = { lv[0], lv[1], lv[2] }; /* 窗头 = 最旧的 3 个电平 */
        int start = med3(head);

        /* 门 a: 双窗中位差, 抓进行中的坡; 远离场景为负 */
        int mo = (n_older & 1) ? older[n_older / 2]
                               : (older[n_older / 2 - 1] + older[n_older / 2]) / 2;
        int mn = (n_newer & 1) ? newer[n_newer / 2]
                               : (newer[n_newer / 2 - 1] + newer[n_newer / 2]) / 2;
        int rise = TURN_X2(mn - mo);
        /* 门 b: 宽窗 q80 - 中位, 且窗头要低 */
        int bump  = TURN_X2(P - m);
        int depth = TURN_X2(P - start);
        /* 阈值换算: 门限(dB) = max(k*sigma, floor), x2 单位 = max(k*sigma_x2, 2*floor).
         * sigma_x2 本身是 2*sigma, 所以 k*sigma = (k/2)*sigma_x2 -- 这里容易
         * 写成 k*sigma_x2 而全部翻倍, 曾经把四道门都放大成 2 倍 (检出延迟
         * 翻倍、慢通过漏检), 是靠同序列交叉验证抓出来的. */
        int ga_ok = rise >= (((3 * sigma_x2) / 2) > 8 ? (3 * sigma_x2) / 2 : 8);
        int gb_ok = bump  >= (2 * sigma_x2 > 11 ? 2 * sigma_x2 : 11) &&
                    depth >= (((5 * sigma_x2) / 2) > 14 ? (5 * sigma_x2) / 2 : 14);
#ifdef LOC_TURN_DEBUG
        printf("t=%d SEARCH rise=%d bump=%d depth=%d sx2=%d ga=%d gb=%d\n",
               t, rise, bump, depth, sigma_x2, ga_ok, gb_ok);
#endif
        if (ga_ok || gb_ok) {
            st->phase = 1;
            st->p_lock = P;
            st->lock_at = t;
            st->votes = 0;
#ifdef LOC_TURN_DEBUG
            printf("  ARMED P=%d\n", P);
#endif
        }
    } else if (st->phase == 1) {
        int16_t l3[3];
        l3[0] = med4(&v[t - 5]);   /* back 2 */
        l3[1] = med4(&v[t - 4]);   /* back 1 */
        l3[2] = med4(&v[t - 3]);   /* back 0 */
        int now = med3(l3);
        int df = 3 * sigma_x2 > 10 ? 3 * sigma_x2 : 10;
#ifdef LOC_TURN_DEBUG
        printf("t=%d ARMED P=%d now=%d dfx2=%d fallx2=%d votes=%d\n",
               t, st->p_lock, now, df, TURN_X2(st->p_lock - now), st->votes);
#endif
        if (TURN_X2(st->p_lock - now) >= df) {
            st->votes++;
            if (st->votes >= 2) {
                st->phase = 2;
                st->cool_at = t;
                st->votes = 0;
                return 1;
            }
        } else {
            st->votes = 0;
        }
        if (t - st->lock_at > LOC_TURN_TIMEOUT) {
            st->phase = 2;                 /* 武装失败同样冷却 */
            st->cool_at = t;
        }
    } else {
        if (t - st->cool_at > LOC_TURN_COOL) st->phase = 0;
    }
    return 0;
}
