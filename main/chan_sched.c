#include "chan_sched.h"

#include <math.h>

uint32_t chan_dwell_floor(void) { return CHAN_DWELL_FLOOR_MS; }

/* WR-λ 的硬边界. 下限 60ms 是"别在一个空信道上浪费超过 1/6 预算",
 * 上限 2000ms 是"再热也不许把射频钉死". */
static uint32_t wrl_clamp(uint32_t d, uint32_t base)
{
    uint32_t lo = base / 6;
    if (lo < 60) lo = 60;
    uint32_t hi = base * 2;
    if (hi > 2000) hi = 2000;
    if (hi < lo + 1) hi = lo + 1;      /* base 极小时保证区间非空 */
    if (d < lo) d = lo;
    if (d > hi) d = hi;
    return d;
}

uint32_t chan_dwell_wrl(uint32_t base_ms, uint32_t hits, uint32_t listen_ms,
                        uint32_t rate_mean)
{
    if (rate_mean < 2) return base_ms;            /* 样本不足, 先均匀扫一轮 */

    /* 收益率用帧/秒, 不能直接用帧数: 停留久的信道帧数天然多, 会形成正反馈 */
    uint32_t r = (listen_ms >= 100)
                 ? (uint32_t)((uint64_t)hits * 1000u / listen_ms)
                 : rate_mean;

    uint32_t d = (uint32_t)((uint64_t)base_ms * (r + 1) / (rate_mean + 1));
    return wrl_clamp(d, base_ms);
}

uint32_t chan_dwell_psd(uint32_t base_ms, uint32_t found, uint32_t found_total,
                        uint32_t visits, uint32_t n_channels)
{
    uint32_t floor_ms = CHAN_DWELL_FLOOR_MS;
    if (base_ms <= floor_ms) floor_ms = base_ms;   /* 用户把 base 压到下限以下才跟着降 */

    /* 第一次接触一律给 base: 首轮就压到下限以下会少发现约 1.3 台,
     * 便宜只用在"探过、确认是空的"信道上. */
    if (visits == 0) return base_ms;
    if (found == 0 || found_total == 0 || n_channels == 0) return floor_ms * 3 / 5;

    float mean = (float)found_total / (float)n_channels;
    if (mean <= 0.0f) return floor_ms * 3 / 5;

    /* 开方抑制独占: 线性分配时热信道会拿走 base 的 4 倍, 其它信道饿死 */
    uint32_t d = (uint32_t)((float)base_ms * sqrtf((float)found / mean));

    uint32_t hi = base_ms * 2;
    if (hi > 2000) hi = 2000;
    if (d < floor_ms) d = floor_ms;
    if (d > hi) d = hi;
    return d;
}

int chan_psd_order(const uint8_t *chans, const uint16_t *weights, int n, uint8_t *out)
{
    if (n <= 0 || !chans || !out) return 0;
    for (int i = 0; i < n; i++) out[i] = chans[i];

    for (int i = 1; i < n; i++) {
        uint8_t  v  = out[i];
        uint16_t wv = weights ? weights[v] : 0;
        int j = i - 1;
        while (j >= 0 && (weights ? weights[out[j]] : 0) < wv) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = v;
    }
    return n;
}
