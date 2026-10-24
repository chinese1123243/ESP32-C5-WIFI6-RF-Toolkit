"""信道调度策略的离线仿真.

为什么先仿真: 真机上跑一次 auto 要 45 秒, 一轮 41 个信道 × 300ms 就是 12 秒,
能拿到的样本太少, 分成两组比不出差异. 仿真里可以跑几千次, 把"策略"和"环境
噪声"分开, 再拿真实环境验证结论.

模型 (与固件的实际行为对齐):
  · 信道表: 2.4G 1-13 + 5G 28 个, 与 main/wifi_attack.c 的 s_channels_* 一致
  · 每个 AP 周期性发 beacon (默认 102.4ms), 有的还带数据帧
  · 驻留 d 毫秒: 该信道上每个 AP 至少发来 1 个 beacon 的概率 = 1-exp(-d/bi),
    命中过就算"发现"; 帧数按泊松(rate*d) 累加, 供速率类策略使用
  · 切信道固定开销 (默认 20ms), 这段时间不产帧也不发现任何 AP

策略:
  uniform  固定驻留, 轮完所有信道
  wrl      现固件的 WR-λ: dwell = base*(rate/mean), 夹在 [base/6, 2base],
           每轮命中与驻留时长同时减半 (指数遗忘)
  psd      本次设计: 有先验按先验分配, 无先验按探测下限轮询, 冷信道指数退避

用法:
    python scripts/chan_sim.py                     # 默认 300 局
    python scripts/chan_sim.py --episodes 1000 --horizon 60
"""

import argparse
import math
import random
import statistics

CH_2G = list(range(1, 14))
CH_5G = [36, 40, 44, 48, 52, 56, 60, 64,
         100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
         149, 153, 157, 161, 165, 169, 173, 177]
CHANNELS = CH_2G + CH_5G

SWITCH_MS = 20.0          # 切信道开销, 可被 --switch 覆盖
BASE_DWELL = 300.0
DET_FLOOR = 250.0         # 探测下限: 覆盖 2.4 个 beacon 周期, 漏检率 <9%
BEACON_MS = 102.4


class AP:
    __slots__ = ("ch", "bi", "rate", "found", "t_found", "t_appear")

    def __init__(self, ch, bi, rate, t_appear=0.0):
        self.ch = ch
        self.bi = bi
        self.rate = rate
        self.found = False
        self.t_found = None
        self.t_appear = t_appear


def make_env(rng, hot=None, n_cold_aps=0, late_5g=0, arrivals=0,
             busy_ch=None, busy_rate=40.0):
    """按实测分布铺 AP.

    hot       静态热区, 默认与现场一致 (1/6/11 上 7/9/5 台, 36 上一台)
    late_5g   把若干 AP 放到扫描顺序靠后的 5G 信道 (149 之后), 考验轮询顺序
    arrivals  运行中才上线的 AP 数, 出现时刻在 [3s, horizon) 内随机
    busy_ch   指定一个信道塞一个高流量 AP (视频类), 用来测"按帧率调度"会不会被它带跑
    """
    hot = hot or {1: 7, 6: 9, 11: 5, 36: 1}
    aps = []
    for ch, n in hot.items():
        for _ in range(n):
            bi = BEACON_MS if rng.random() < 0.8 else BEACON_MS * 2
            rate = rng.choice([0.5, 0.5, 2.0, 8.0, 25.0])
            aps.append(AP(ch, bi, rate))
    for _ in range(n_cold_aps):
        ch = rng.choice(CHANNELS)
        bi = BEACON_MS if rng.random() < 0.8 else BEACON_MS * 2
        aps.append(AP(ch, bi, rng.choice([0.5, 1.0])))
    for _ in range(late_5g):
        ch = rng.choice([149, 153, 157, 161, 165, 169, 173, 177])
        bi = BEACON_MS if rng.random() < 0.8 else BEACON_MS * 2
        aps.append(AP(ch, bi, rng.choice([0.5, 1.0])))
    for _ in range(arrivals):
        ch = rng.choice(CHANNELS)
        aps.append(AP(ch, BEACON_MS, rng.choice([0.5, 1.0]),
                      t_appear=rng.uniform(3000, 40000)))
    if busy_ch:
        aps.append(AP(busy_ch, BEACON_MS, busy_rate))
    return aps


class World:
    """一次驻留的物理结果."""

    def __init__(self, aps, rng, switch_ms=SWITCH_MS):
        self.aps = aps
        self.by_ch = {}
        for a in aps:
            self.by_ch.setdefault(a.ch, []).append(a)
        self.rng = rng
        self.switch_ms = switch_ms

    def drain(self, ch, dwell_ms, now):
        """在 ch 上驻留 dwell_ms, 返回 (新增发现数, 帧数)."""
        new = 0
        frames = 0
        for a in self.by_ch.get(ch, ()):
            if a.t_appear > now:          # 还没上线, 扫不到
                continue
            if not a.found:
                if self.rng.random() < 1.0 - math.exp(-dwell_ms / a.bi):
                    a.found = True
                    a.t_found = now + self.rng.uniform(0, dwell_ms)
                    new += 1
            frames += poisson(self.rng, a.rate * dwell_ms / 1000.0)
        return new, frames


def poisson(rng, lam):
    if lam <= 0:
        return 0
    if lam > 30:                      # 正态近似, 省时间
        return max(0, int(rng.gauss(lam, math.sqrt(lam))))
    L = math.exp(-lam)
    k, p = 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= L:
            return k - 1


def run_uniform(world, horizon, base=BASE_DWELL, **kw):
    """horizon 单位毫秒."""
    t = 0.0
    while t < horizon:
        for ch in CHANNELS:
            if t >= horizon:
                break
            world.drain(ch, base, t)
            t += base + world.switch_ms
    return t


def run_wrl(world, horizon, base=BASE_DWELL, **kw):
    """复刻固件: hits/listen 记速率, 每轮减半, dwell 按速率比加权并夹紧."""
    hits = {c: 0.0 for c in CHANNELS}
    listen = {c: 0.0 for c in CHANNELS}
    mean = 0.0
    t = 0.0
    while t < horizon:
        rate_mean = mean
        for ch in CHANNELS:
            if t >= horizon:
                break
            if rate_mean < 2:
                dwell = base
            else:
                r = (hits[ch] * 1000.0 / listen[ch]) if listen[ch] >= 100 else rate_mean
                dwell = base * (r + 1) / (rate_mean + 1)
                lo = max(base / 6, 60)
                hi = min(base * 2, 2000)
                dwell = min(max(dwell, lo), hi)
            _new, frames = world.drain(ch, dwell, t)
            t += dwell + world.switch_ms
            hits[ch] += frames
            listen[ch] += dwell
        # 一轮结束: 指数遗忘 + 重算均值
        s, n = 0.0, 0
        for ch in CHANNELS:
            hits[ch] *= 0.5
            listen[ch] *= 0.5
            if listen[ch] >= 150 and hits[ch] > 0:
                s += hits[ch] * 1000.0 / listen[ch]
                n += 1
        mean = s / n if n else 0.0
    return t


def run_psd(world, horizon, base=BASE_DWELL, prior=None,
            floor=DET_FLOOR, backoff=True, backoff_cap=4, cold_factor=0.6, **kw):
    """先验 + 探测下限 + 冷信道指数退避.

    权重来自"这一轮在该信道上新发现了几个 AP"(先验给首轮用), 每轮重算.
    空信道连空 2 轮后改成一轮探一次, 每再空 2 轮翻倍间隔, 上限 8 轮.
    这样 38 个空信道每轮只花 1/8 的成本, 时间留给真有 AP 的信道.
    """
    prior = prior or {}
    new_last = {c: 0 for c in CHANNELS}
    empty_streak = {c: 0 for c in CHANNELS}
    since_visit = {c: 0 for c in CHANNELS}
    w = {c: float(prior.get(c, 0)) for c in CHANNELS}
    t = 0.0
    round_no = 0
    while t < horizon:
        # 本轮的访问顺序: 权重高的先走, 空的按退避跳过
        order = []
        for ch in CHANNELS:
            if backoff and empty_streak[ch] >= 2:
                gap = 1 << min(3, empty_streak[ch] // 2)   # 1,2,4,8 轮
                gap = min(gap, backoff_cap)
                if since_visit[ch] < gap:
                    continue
            order.append(ch)
        order.sort(key=lambda c: -w[c])
        if not order:                 # 全在退避里 (理论上不会), 强制探一遍
            order = list(CHANNELS)
        tot = sum(w[c] for c in order) or 1.0
        for ch in order:
            if t >= horizon:
                break
            share = w[ch] / tot
            dwell = base * (share * len(order)) ** 0.5     # 开方, 抑制独占
            lo = floor if (w[ch] > 0 or cold_factor >= 1.0) else floor * cold_factor
            dwell = min(max(dwell, lo), base * 2)
            before = sum(1 for a in world.by_ch.get(ch, ()) if a.found)
            new, frames = world.drain(ch, dwell, t)
            t += dwell + world.switch_ms
            new_last[ch] = new
            since_visit[ch] = 0
            if new == 0 and not any(a.found for a in world.by_ch.get(ch, ())):
                empty_streak[ch] += 1
            elif new == 0:
                empty_streak[ch] = min(empty_streak[ch], 1)
            else:
                empty_streak[ch] = 0
            del before
        # 每轮: 权重 = 本轮新发现 + 已有存量的一半 (存量代表"这里还有货")
        for ch in CHANNELS:
            have = sum(1 for a in world.by_ch.get(ch, ()) if a.found)
            w[ch] = new_last[ch] + 0.5 * have
            since_visit[ch] += 1
        round_no += 1
    return t



def run_cov(world, horizon, base=BASE_DWELL, prior=None,
            floor=DET_FLOOR, bi_est=BEACON_MS, **kw):
    """覆盖感知调度: 按"估计还有几台没被发现"分配驻留.

    每台 AP 每次驻留被看到的概率 p = 1-exp(-d/bi). 访问 v 次后仍漏掉某台的概率
    是 (1-p)^v, 于是该信道的 AP 总数估计
        n_hat = k / (1 - (1-p)^v)
    k 是已经发现的台数, v 是访问次数. 剩余 = n_hat - k, 按剩余量排序分配时间.
    与"按发现数加权"的区别: 只发现过 1 台的信道, 如果访问次数少, 修正后可能
    还有不少没露面; 反过来, 访问很多次仍然只有 1 台的信道, 修正后剩余接近 0,
    就不该再花时间. 这一条正是 WR-λ 看不出来的.
    """
    prior = prior or {}
    visits = {c: 0 for c in CHANNELS}
    dwell_sum = {c: 0.0 for c in CHANNELS}
    t = 0.0
    while t < horizon:
        # 估计每台信道的剩余未发现数
        rem = {}
        for ch in CHANNELS:
            k = sum(1 for a in world.by_ch.get(ch, ()) if a.found)
            v = visits[ch]
            if v == 0:
                rem[ch] = float(prior.get(ch, 0)) + 1.0     # 没去过, 先按有货处理
                continue
            d = dwell_sum[ch] / v
            p = 1.0 - math.exp(-d / bi_est)
            miss = (1.0 - p) ** v
            n_hat = k / (1.0 - miss) if miss < 0.999 else float(k)
            rem[ch] = max(0.0, n_hat - k)
        order = [c for c in CHANNELS if rem[c] > 0.05]
        if not order:                                  # 全估完了, 巡检一遍
            order = list(CHANNELS)
        order.sort(key=lambda c: -rem[c])
        tot = sum(rem[c] for c in order) or 1.0
        for ch in order:
            if t >= horizon:
                break
            share = rem[ch] / tot
            dwell = base * (share * len(order)) ** 0.5
            dwell = min(max(dwell, floor), base * 2)
            world.drain(ch, dwell, t)
            t += dwell + world.switch_ms
            visits[ch] += 1
            dwell_sum[ch] += dwell
    return t



def run_band(world, horizon, base=BASE_DWELL, prior=None, floor=DET_FLOOR,
             band_probe=3, **kw):
    """PSD + 频段级退避: 5G 连续两轮没有新发现就只每 3 轮探一次.

    5G 的信道数是 2.4G 的两倍多 (28 vs 13), 而现实里 5G 的 AP 密度往往低一个
    量级. 逐信道退避不解决问题: 28 个空信道各自退避, 一轮仍要走 28 次.
    按频段整体退避, 一轮成本直接砍掉 2/3, 2.4G 的 revisit 频率翻三倍.
    """
    prior = prior or {}
    new_last = {c: 0 for c in CHANNELS}
    visits = {c: 0 for c in CHANNELS}
    dwell_sum = {c: 0.0 for c in CHANNELS}
    t = 0.0
    round_no = 0
    skip_5g = 0
    while t < horizon:
        use5g = (skip_5g == 0)
        order = [c for c in CHANNELS if use5g or c in CH_2G]
        order.sort(key=lambda c: -new_last[c])
        for ch in order:
            if t >= horizon:
                break
            w = sum(1 for a in world.by_ch.get(ch, ()) if a.found)
            if visits[ch] == 0:
                dwell = floor
            elif w == 0:
                dwell = floor * 0.6
            else:
                d = dwell_sum[ch] / visits[ch]
                dwell = min(max(base * (w / 2.0) ** 0.5, floor), base * 2)
            world.drain(ch, dwell, t)
            t += dwell + world.switch_ms
            visits[ch] += 1
            dwell_sum[ch] += dwell
        new5g = sum(1 for ch in CH_5G
                    for a in world.by_ch.get(ch, ())
                    if a.found and a.t_found is not None and a.t_found >= t - base * 60)
        if skip_5g > 0:
            skip_5g -= 1
        elif new5g == 0:
            skip_5g = max(1, band_probe - 1)
        round_no += 1
    return t


POLICIES = {"uniform": run_uniform, "wrl": run_wrl, "psd": run_psd,
            "cov": run_cov, "band": run_band}


def episode(policy, seed, horizon, n_cold_aps=0, **kw):
    rng = random.Random(seed)
    env_kw = {k: kw.pop(k) for k in ("late_5g", "arrivals", "busy_ch", "busy_rate")
              if k in kw}
    aps = make_env(rng, n_cold_aps=n_cold_aps, **env_kw)
    world = World(aps, rng, switch_ms=kw.pop("switch_ms", SWITCH_MS))
    fn = POLICIES[policy]
    fn(world, horizon, **kw)
    return aps


def summarize(aps_list, marks):
    out = {}
    n = len(aps_list[0])
    for m in marks:
        vals = [sum(1 for a in aps if a.found and a.t_found <= m * 1000.0)
                for aps in aps_list]
        out[m] = (statistics.median(vals), min(vals), max(vals))
    # 中途上线那批 AP 的发现延迟: 策略卡在某个信道时, 这里的尾巴会很长
    lat = []
    missed = 0
    for aps in aps_list:
        for a in aps:
            if a.t_appear <= 0:
                continue
            if a.found and a.t_found >= a.t_appear:
                lat.append((a.t_found - a.t_appear) / 1000.0)
            else:
                missed += 1
    if lat:
        lat.sort()
        out["lat"] = (statistics.median(lat),
                      lat[int(len(lat) * 0.9) - 1],
                      max(lat), missed)
    return out, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=300)
    ap.add_argument("--horizon", type=float, default=45.0)
    ap.add_argument("--switch", type=float, default=SWITCH_MS)
    ap.add_argument("--cold-aps", type=int, default=0,
                    help="在随机冷信道上额外播这么多台 AP, 用来测漏检")
    ap.add_argument("--policies", default="uniform,wrl,psd")
    ap.add_argument("--late-5g", type=int, default=0,
                    help="把 N 台 AP 放到 149 之后的高信道")
    ap.add_argument("--arrivals", type=int, default=0,
                    help="运行中随机上线 N 台 AP")
    ap.add_argument("--busy-ch", type=int, default=None,
                    help="在该信道放一台高流量 AP (只在 wrl 占便宜的诱惑)")
    ap.add_argument("--floor", type=float, default=DET_FLOOR,
                    help="探测下限毫秒 (psd/cov 用)")
    ap.add_argument("--backoff-cap", type=int, default=4,
                    help="冷信道退避的最大轮数 (0=关闭退避)")
    args = ap.parse_args()

    marks = [t for t in (10, 20, 30, 45, 60) if t <= args.horizon]
    if marks[-1] != args.horizon:
        marks.append(int(args.horizon))

    print("=== 信道调度仿真 ===")
    print("信道 %d 个, 冷信道 %d, 高信道 %d, 中途上线 %d, 忙信道 %s, "
          "切换 %.0fms, %d 局/策略, 视界 %.0fs"
          % (len(CHANNELS), args.cold_aps, args.late_5g, args.arrivals,
             args.busy_ch, args.switch, args.episodes, args.horizon))
    header = "%-8s" % "策略" + "".join("%14s" % ("t=%ds" % m) for m in marks)
    print(header)

    lat_rows = []
    for pol in args.policies.split(","):
        aps_list = [episode(pol, seed, args.horizon * 1000.0, args.cold_aps,
                            switch_ms=args.switch,
                            late_5g=args.late_5g, arrivals=args.arrivals,
                            busy_ch=args.busy_ch,
                            backoff=args.backoff_cap > 0,
                            backoff_cap=max(1, args.backoff_cap),
                            floor=args.floor)
                    for seed in range(args.episodes)]
        stats, total = summarize(aps_list, marks)
        row = "%-8s" % pol
        for m in marks:
            med, lo, hi = stats[m]
            row += "%14s" % ("%d(%d-%d)" % (med, lo, hi))
        print(row)
        if "lat" in stats:
            lat_rows.append((pol, stats["lat"]))
    print("\n总 AP 数 %d, 单元格式: 中位数(最小-最大)" % total)
    if lat_rows:
        print("中途上线 AP 的发现延迟 (秒):")
        for pol, (med, p90, mx, miss) in lat_rows:
            print("  %-8s 中位 %.1f  p90 %.1f  最大 %.1f  漏检 %d"
                  % (pol, med, p90, mx, miss))


if __name__ == "__main__":
    main()
