#pragma once

#include <stdint.h>

/* RSSI 的抗离群统计.
 *
 * 为什么不用算术平均: 多径深衰落会让个别样本掉 10~15dB, 算术平均被这些
 * 离群值拉低, 而且样本越多样本越"稳", 实际是往错误的方向稳. 中位数与
 * 截尾均值对离群值不敏感, MAD 还能给出一个抗污染的离散度.
 *
 * 纯函数, 排序用调用方给的 scratch (长度 n), 避免在大栈上再开一份.
 */
typedef struct {
    int median;
    int trimmed;     /* 去掉两端各 20% 后的均值 */
    int mean;
    int mad;         /* 中位绝对偏差, 抗离群 */
    int n;
} loc_stat_t;

void loc_estimate(const int16_t *v, int n, int16_t *scratch, loc_stat_t *out);

/* 趋势: 前 25% 与后 25% 的中位数之差, 换算成"每 10 个样本的 dB 变化".
 * 用中位数而不是均值, 同样是为了不被单点深衰落带跑. n < 8 返回 0. */
int loc_trend(const int16_t *v, int n, int16_t *scratch);
