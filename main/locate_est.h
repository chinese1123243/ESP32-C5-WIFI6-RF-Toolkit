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
    int se;          /* 中位数的标准误 ≈ 1.253*mad/sqrt(n), 单位 dB */
    int n;
} loc_stat_t;

void loc_estimate(const int16_t *v, int n, int16_t *scratch, loc_stat_t *out);

/* 趋势: 前 25% 与后 25% 的中位数之差, 换算成"每 10 个样本的 dB 变化".
 * 用中位数而不是均值, 同样是为了不被单点深衰落带跑. n < 8 返回 0. */
int loc_trend(const int16_t *v, int n, int16_t *scratch);

/* 趋势的 95% 半宽, 单位与 loc_trend 相同 (每 10 个样本的 dB).
 * 两段各 k 个样本的中位数相减, 方差是各自的 2 倍, 于是
 *   se_diff ≈ 1.253*mad*sqrt(2/k) /10*10 ...
 * 这里直接用 mad 与 k 推, 不需要重算中位数.
 * 读数规则: |trend| <= ci 时应当读作"没有可分辨的趋势", 而不是"轻微移动". */
int loc_trend_ci(const int16_t *v, int n, int16_t *scratch);

/* 拐点检测 (循迹找源)
 *
 * 人拿着设备走向发信源, RSSI 一路涨, 越过最近点后一路跌; 检测"已越过"
 * 这个时刻. 参数与判据出自 scripts/loc_turn_sim.py 的定标 (300 局 x 7 场景):
 * 快步通过 (10m@1m/s) 检出 84%/延迟 10s, 缓步 (6m@0.5m/s) 99%/8s,
 * 静止与远离误报 <= 1.7% 每分钟, 4 倍衰落压力下 <= 5.3%.
 *
 * 结构是峰锁定状态机: SEARCHING 里用两把互补的钥匙找"看得见的峰"--
 *   门 a 双窗中位差, 抓进行中的坡 (斜坡的中位数落在窗口中央, 差值就是
 *        升程, 与峰在哪个窗里无关; 远离场景为负, 天然抑制);
 *   门 b 宽窗 q80 与窗头之差, 抓已完成的快通过 (峰滑出近窗后中位差归零,
 *        但 q80 仍贴着峰). 门 b 的"窗头要低"把远离与静止都挡住.
 * 锁定后 ARMED, 等当前电平跌破 P-max(3sigma,5dB); 3B 个样本没跌成说明
 * 峰过时了, 解锁冷却. 开火后冷却 2B, 用户折返再涨会重新武装.
 *
 * 阈值里的 sigma 用 |二阶差分| 的 q15 估计: 二阶差分消掉线性趋势, 峰区
 * 信号曲率会把 q25 都抬高约 2 倍 (窗内一半样本带曲率), q15 压住曲率也
 * 压住衰落. 归一化: |N(0,tau)| 的 q15 = 0.189*tau, tau=sqrt(6)*sigma,
 * 0.189*2.449 = 0.463. 不能用窗内 mad: 序列非平稳时长窗 mad 量到的是
 * 信号摆幅 (delta 被撑爆), 16 样本窗 mad 又随噪声平静期缩水 (误报从
 * 这条缝漏进来), 两条路都试过都被仿真否掉.
 */
#define LOC_TURN_B       16     /* 半窗: 锁定窗 = level[t-2B..t-3] */
#define LOC_TURN_TIMEOUT (3 * LOC_TURN_B)
#define LOC_TURN_COOL    (2 * LOC_TURN_B)
#define LOC_TURN_MIN_N   (LOC_TURN_B + 20)  /* sigma 满窗(35) 留 1 余量 */
#define LOC_TURN_SCR     96     /* scratch 需求 (int16 个数) */

typedef struct {
    int phase;      /* 0 SEARCH 1 ARMED 2 COOL */
    int p_lock;     /* 锁定的峰值电平, dB */
    int lock_at;    /* 锁定时最新样本的序号 (0 起) */
    int cool_at;
    int votes;
    int t;          /* 已喂入的样本数 */
} loc_turn_t;

void loc_turn_reset(loc_turn_t *st);

/* 每个新样本喂一次. v[0..n-1] 是最近的 RSSI 历史 (n >= LOC_TURN_MIN_N 时
 * 才可能开火, 更短只推进状态). scratch 长度 LOC_TURN_SCR.
 * 返回 1 = 报 "passed" (本次开火, 至多一次). */
int loc_turn_update(loc_turn_t *st, const int16_t *v, int n, int16_t *scratch);
