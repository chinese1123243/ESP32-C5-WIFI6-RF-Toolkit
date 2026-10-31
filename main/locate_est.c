#include "locate_est.h"

#include <stddef.h>

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
