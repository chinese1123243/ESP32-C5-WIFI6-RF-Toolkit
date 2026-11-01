#pragma once

#include <stdbool.h>
#include <stdint.h>

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

/* 频率轴同向一致率: 相邻子载波残差同号的根数占比, 0.5 等于随机.

   为什么要这个量: 窄带干扰 (微波炉、蓝牙、单音) 只砸一两个子载波, 其余
   子载波的残差就是噪声, 符号随机; 真实运动是同一条路径的相位旋转, 在
   频率轴上连续同向.

   合成数据实测 (scripts/csi_sim.py, 6 径 400ns 时延扩展):
     场景     一致率中位   p10    p90
     静止       0.490     0.412  0.588
     窄带干扰    0.529     0.412  0.627
     走动       0.882     0.765  0.941     (25dB)
     走动       0.804     0.569  0.902     (15dB)

   也就是说单看这一个量就能把"微波炉"和"有人走动"分开, 而两者在幅度指标上
   只差 1.5 倍 (0.0079 vs 0.0371), 阈值稍微飘一点就分错. */
/* cur 是未归一化的 int16 幅度, inv_norm = 1/||cur||, ref 是已归一化的参考帧.
   这样调用方不必为了比较再造一份归一化拷贝 (CSI 任务栈只有 4096 字节).
   符号比较与尺度无关, 把 cur 乘上 inv_norm 就够了. */
float csi_coherence(const int16_t *cur, const float *ref, int n, float inv_norm);

#define CSI_DET_COH_MIN 0.65f

/* 带同向门控的判定: 内部状态照常推进, 只在一致率够高时才报动作.
   门控放在输出侧而不是缩放到 metric 上, 是为了不动已有的阈值标定:
   乘以系数会把静止时的 metric 压到 mad 地板以下, z 分数随之失效. */
bool csi_det_update_coh(csi_det_t *d, float metric, float coh);
