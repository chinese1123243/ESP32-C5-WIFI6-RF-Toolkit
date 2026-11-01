#include "csi_det.h"

#include <math.h>

/* 基线跟随速率. 下行的 0.02 让背景在几十个样本内跟上环境变化 (开关门、
 * 有人坐下不走); 上行的 0.002 是"动作不许被学成背景", 否则持续动作 10 秒后
 * 基线就爬到动作电平, 检测器自己把自己关掉. */
#define BASE_DOWN 0.02f
#define BASE_UP   0.002f
#define MAD_RATE  0.05f
#define MAD_FLOOR 0.02f   /* 全静环境 mad 会趋近 0, 除法要有个地板 */

void csi_det_reset(csi_det_t *d)
{
    if (!d) return;
    d->base = 0.0f;
    d->mad = MAD_FLOOR;
    d->score = 0.0f;
    d->cusum = 0.0f;
    d->hold = 0;
    d->motion = false;
    d->init = false;
}

bool csi_det_update(csi_det_t *d, float metric)
{
    if (!d) return false;

    if (!d->init) {
        d->base = metric;
        d->mad = MAD_FLOOR;
        d->score = 0.0f;
            d->init = true;
        return false;
    }

    float dev = metric - d->base;
    d->score = dev / (d->mad + MAD_FLOOR);

    /* CUSUM: 只积正向偏差, 慢动作的瞬时 z 不高, 但会同号累积 */
    d->cusum += dev - CSI_DET_CUSUM_K * d->mad;
    if (d->cusum < 0.0f) d->cusum = 0.0f;
    /* 已经在动作态时累积和没有意义, 而且会一路涨到几百. 退出条件里带着
     * "累积和已泄掉", 不在这里清零的话, 动作结束要等几十个样本才退得出去. */
    if (d->motion) d->cusum = 0.0f;

    bool enter = (d->score > CSI_DET_ENTER_Z) ||
                 (d->cusum > CSI_DET_CUSUM_H * (d->mad + MAD_FLOOR));

    if (d->motion) {
        d->hold++;
        /* 退出要同时满足: 分数落回、累积和已泄掉、保持够久 */
        if (d->score < CSI_DET_EXIT_Z && d->cusum <= 0.0f &&
            d->hold >= CSI_DET_HOLD_N) {
            d->motion = false;
            d->hold = 0;
        }
    } else if (enter) {
        d->motion = true;
        d->hold = 0;
        d->cusum = 0.0f;
    }

    /* 基线/离散度最后更新: 判定用的是"更新前"的背景, 否则当前样本会先污染
     * 判据再被判据使用, 高 metric 会被自己的基线抬走.
     *
     * 增益取快/慢只看"当前是否判定为动作", 不看偏差的正负:
     *  - 按正负分快慢时, 平稳噪声会让基线单向爬到低分位, 之后噪声的上半部分
     *    全变成正偏差, 静止场景也持续报动作 (主机测试 120 个静止样本报 96 次).
     *  - 判定为动作期间用慢速率, 就是"不把当前电平学成背景". 之前用偏差的慢
     *    均值做这一步是徒劳的: 基线一旦追上去, 慢均值自己就归零了.
     * 动作结束、退出判定后回到快速率, 基线几秒内就能重新对齐环境. */
    d->base += (d->motion ? BASE_UP : BASE_DOWN) * dev;
    /* 离散度同理: 动作期间的偏差是信号本身, 拿它更新 mad 会让 z 分数自己
     * 稀释掉 (实测第 18 个样本 score 从 30 掉到 1.5, 检测器主动退出动作态).
     * mad 估计的是背景噪声, 只在非动作态更新. */
    if (!d->motion) {
        d->mad += MAD_RATE * (fabsf(dev) - d->mad);
        if (d->mad < MAD_FLOOR) d->mad = MAD_FLOOR;
    }

    return d->motion;
}

float csi_coherence(const int16_t *cur, const float *ref, int n, float inv_norm)
{
    if (!cur || !ref || n < 3 || inv_norm <= 0.0f) return 0.5f;
    int same = 0, opp = 0;
    float prev = (float)cur[0] * inv_norm - ref[0];
    for (int i = 1; i < n; i++) {
        float d = (float)cur[i] * inv_norm - ref[i];
        float p = d * prev;
        /* 全零残差 (两帧完全一样) 不投任何一票, 因此无证据时返回 0.5 而不是 0 */
        if (p > 0.0f) same++;
        else if (p < 0.0f) opp++;
        prev = d;
    }
    return (same + opp) ? (float)same / (float)(same + opp) : 0.5f;
}

bool csi_det_update_coh(csi_det_t *d, float metric, float coh)
{
    bool m = csi_det_update(d, metric);
    return m && coh >= CSI_DET_COH_MIN;
}
