#pragma once

#include <stdbool.h>

/* CSI 动作检测器.
 *
 * 原判据是 `metric > 2×base && metric > 0.15`，三处会被现场否掉：
 *   1. base 用 0.02 的 EWMA 匀速跟随，人一直在动时 base 会爬到动作电平上，
 *      检测器把自己训练瞎了，表现为"动一会儿就不报了"
 *   2. 固定 2 倍门限不看噪声水平：多 AP 环境 metric 抖动本来就大，误报；
 *      安静房间抖动小，又漏报
 *   3. 没有滞回，指标在门限附近来回穿，输出跟着抖
 *
 * 这里改成：
 *   - 非对称基线：低于基线时按 0.02 跟随（背景要跟得上环境变化），
 *     高于基线时按 0.002（不许把动作学成背景）
 *   - 离散度 mad = EWMA(|metric-base|)，判据用 z 分数 (metric-base)/mad
 *   - 滞回：进 4σ，出 1.5σ，且至少保持 hold_min 个样本
 *   - CUSUM 兜底：慢动作的瞬时 z 分数不高，但偏差持续同号会累积到阈值
 *
 * 纯逻辑，不读全局，可在主机上喂合成序列。
 */
typedef struct {
    float base;        /* 背景基线 */
    float mad;         /* 背景离散度 */
    float score;       /* 最后一次的 z 分数 */
    float cusum;       /* 单边累积和 (只积正向偏差) */
    int   hold;        /* 进入动作后已保持的样本数 */
    bool  motion;      /* 当前判定 */
    bool  init;
} csi_det_t;

#define CSI_DET_ENTER_Z   4.0f   /* 进入: 4 倍离散度 */
#define CSI_DET_EXIT_Z    1.5f   /* 退出: 1.5 倍 */
#define CSI_DET_HOLD_N    5      /* 至少保持 5 个样本, 防止单点抖动 */
#define CSI_DET_CUSUM_K   0.5f   /* CUSUM 的松弛量, 单位是 mad */
#define CSI_DET_CUSUM_H   6.0f   /* CUSUM 触发阈值, 单位是 mad */

void csi_det_reset(csi_det_t *d);

/* 喂一个 metric, 返回是否处于动作状态. */
bool csi_det_update(csi_det_t *d, float metric);
