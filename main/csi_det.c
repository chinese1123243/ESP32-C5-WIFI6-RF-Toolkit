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
     * 判据再被判据使用, 高 metric 会被自己的基线抬走. */
    if (dev < 0.0f) d->base += BASE_DOWN * dev;
    else            d->base += BASE_UP * dev;
    d->mad += MAD_RATE * (fabsf(dev) - d->mad);
    if (d->mad < MAD_FLOOR) d->mad = MAD_FLOOR;

    return d->motion;
}
