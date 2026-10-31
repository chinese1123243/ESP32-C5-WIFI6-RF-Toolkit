#pragma once

#include <stdint.h>

/* 自动信道轮询的驻留计算. 纯函数: 输入全部由调用方给出, 不读全局, 不碰原子量,
 * 因此可以在主机上用仿真数据喂, 也能与 chan_sim.py 的结果直接对照.
 *
 * 两个策略共用同一组硬边界, 改动时两边要一起看:
 *   下限  base/6, 不小于 60ms      防止空信道占满预算
 *   上限  2×base, 不大于 2000ms    防止虚假高值把射频钉在一个信道上
 */

#define CHAN_DWELL_FLOOR_MS 250u   /* PSD 的检出率下限: 首轮必须给足 */

/* 探测下限: 低于这个驻留时, beacon(102.4ms 间隔) 的检出率掉到 39% */
uint32_t chan_dwell_floor(void);

/* WR-λ: base × (rate+1)/(mean+1), rate = hits/listen 换算成帧/秒.
 * listen_ms < 100 时样本不足, 直接按均值算. */
uint32_t chan_dwell_wrl(uint32_t base_ms, uint32_t hits, uint32_t listen_ms,
                        uint32_t rate_mean);

/* PSD: 按"本信道发现了几台 AP"分配驻留, 热信道 base×sqrt(w/mean), 冷信道 60% 下限.
 * visits == 0 表示第一次接触, 一律给 base. */
uint32_t chan_dwell_psd(uint32_t base_ms, uint32_t found, uint32_t found_total,
                        uint32_t visits, uint32_t n_channels);

/* ADT: 按"已发现台数"反推还需要多少驻留.

 * 推导: 每台 AP 在驻留 d 内被发现的概率 1-exp(-d/bi), 多次驻留可把 d 相加,
 * 累计暴露 E 之后仍未发现某台的概率 exp(-E/bi). 已发现 k 台时, 要让
 * "还剩一台"的概率低于 eps, 需要 E >= bi*ln(k/eps).
 *   k=9, eps=5%   -> 532ms
 *   k=1, eps=5%   -> 307ms
 * 台数越多越值得多待, 只发现一台的信道不必陪跑.
 *
 * 返回本次还差的毫秒数, 夹到 [floor, 2×base]; 差额小于下限时返回 floor,
 * 表示"已经压满, 只做一次探测下限的回探". exposure_ms 是累计暴露, 不参与衰减.
 * eps_permille 用千分数, 50 表示 5%. */
uint32_t chan_dwell_adt(uint32_t base_ms, uint32_t found, uint32_t exposure_ms,
                        uint32_t eps_permille);

/* 按权重降序排信道. 稳定插入排序: 权重相同保持原顺序, 避免每轮来回抖.
 * weights 与 chans 等长, 结果写入 out. 返回信道数. */
int chan_psd_order(const uint8_t *chans, const uint16_t *weights, int n, uint8_t *out);
