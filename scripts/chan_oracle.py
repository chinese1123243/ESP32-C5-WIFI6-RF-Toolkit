"""信道调度的 oracle 参照: 找齐全部 AP 需要多久.

AGENTS.md: 自研算法先给 oracle 上界作参照, 达不到 90% 说明思路有问题.

上界是 clairvoyant 的: 假定已知每台 AP 在哪条信道、beacon 间隔多少, 只解
"总时间怎么分". 现实策略不知道这些, 差距就是探索的代价. 因此这个比值不是
"策略好不好"的绝对评分, 而是"探索还要花多少冤枉时间".

为什么用"找齐时间"而不是"固定视界内的发现数": 45 秒视界下所有策略都能找齐
22 台, 发现数指标全饱和, 什么也分不出来. 找齐时间在 8~20 秒区间里对调度
差异最敏感.

用法:
  python scripts/chan_oracle.py                     # 默认场景, 300 局
  python scripts/chan_oracle.py --cold-aps 20       # 冷信道加压
  python scripts/chan_oracle.py --horizon 20 --episodes 500
"""

import argparse
import math
import os
import random
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chan_sim as cs


def oracle_alloc(aps, horizon_ms, switch_ms=cs.SWITCH_MS, step_ms=5.0):
    """把 horizon 按边际收益分给各信道, 返回 (期望发现数, 用掉的时间).

    每个信道的收益 sum(1-exp(-d/bi)) 是凹的, 按"每毫秒边际收益"贪心分配.
    首次访问某信道要付一次 switch_ms 固定费用, 这让问题不再是严格凹;
    20ms 相对 15000ms 是 0.13%, 贪心偏差在容差内.
    """
    by_ch = {}
    for a in aps:
        if a.t_appear > 0:
            continue          # 中途上线的不在 v1 范围内, 与默认场景一致
        by_ch.setdefault(a.ch, []).append(a)

    dwell = {c: 0.0 for c in by_ch}
    opened = set()
    budget = float(horizon_ms)
    total = 0.0
    used = 0.0

    while budget > 0:
        best = None
        for c, group in by_ch.items():
            d = dwell[c]
            gain = 0.0
            for a in group:
                gain += math.exp(-d / a.bi) - math.exp(-(d + step_ms) / a.bi)
            if gain <= 0:
                continue
            cost = step_ms + (switch_ms if c not in opened else 0.0)
            if cost > budget:
                continue
            score = gain / cost
            if best is None or score > best[1]:
                best = (c, score, cost, gain)
        if best is None:
            break
        c, _score, cost, gain = best
        opened.add(c)
        dwell[c] += step_ms
        budget -= cost
        used += cost
        total += gain

    return total, used


def oracle_time_to(aps, target, switch_ms=cs.SWITCH_MS):
    """找齐 target 台 AP 的最短时间 (毫秒). 达不到返回 None."""
    lo, hi = 0.0, 600000.0
    if oracle_alloc(aps, hi, switch_ms)[0] < target:
        return None
    for _ in range(40):
        mid = (lo + hi) / 2
        if oracle_alloc(aps, mid, switch_ms)[0] >= target:
            hi = mid
        else:
            lo = mid
    return hi


def policy_find_time(policy, seed, horizon_ms, n_aps, **kw):
    """一局里找齐 n_aps 台用的时间 (ms). 没找齐返回 None."""
    aps = cs.episode(policy, seed, horizon_ms, kw.pop("n_cold_aps", 0), **kw)
    ts = [a.t_found for a in aps if a.t_appear <= 0]
    if any(t is None for t in ts):
        return None
    return max(ts)


SUITE = [
    ("默认",          dict()),
    ("冷信道40",       dict(n_cold_aps=40)),
    ("高信道8",        dict(late_5g=8)),
    ("中途上线6",      dict(arrivals=6)),
    ("忙信道6",        dict(busy_ch=6, busy_rate=40.0)),
    ("冷信道80",       dict(n_cold_aps=80)),
]


def suite(args):
    """多场景对照: 视界内找到多少台, 以及找齐与否.

    冷信道场景里"找齐"不可达 (几十台 AP 散在 78 条信道上, 20 秒扫不完),
    所以主指标用"找到比例", 找齐时间只在能找齐的场景里读.
    """
    prior = {1: 7, 6: 9, 11: 5, 36: 1}
    print("=== 多场景对照 (视界 %.0fs, %d 局/格) ===" % (args.horizon, args.episodes))
    print("%-12s %-6s %8s %8s %7s" % ("场景", "策略", "找到比例", "中位台数", "找齐率"))
    for name, env_kw in SUITE:
        for pol in args.policies.split(","):
            hit, n_tot, allc = [], 0, 0
            for seed in range(args.episodes):
                aps = cs.episode(pol, seed, args.horizon * 1000.0,
                                 env_kw.get("n_cold_aps", 0),
                                 prior=prior if pol == "adt3" else None,
                                 **{k: v for k, v in env_kw.items()
                                    if k != "n_cold_aps"})
                got = sum(1 for a in aps if a.found)
                hit.append(got)
                n_tot = len(aps)
                allc += 1 if got == len(aps) else 0
            print("%-12s %-6s %7.1f%% %8.1f %6.0f%%"
                  % (name, pol, 100.0 * statistics.fmean(hit) / n_tot,
                     statistics.median(hit), 100.0 * allc / len(hit)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=300)
    ap.add_argument("--horizon", type=float, default=20.0)
    ap.add_argument("--cold-aps", type=int, default=0)
    ap.add_argument("--policies", default="uniform,wrl,psd,cov,band")
    ap.add_argument("--switch", type=float, default=cs.SWITCH_MS)
    ap.add_argument("--floor", type=float, default=cs.DET_FLOOR)
    ap.add_argument("--suite", action="store_true", help="多场景对照")
    args = ap.parse_args()

    if args.suite:
        suite(args)
        return

    horizon_ms = args.horizon * 1000.0
    base_aps = cs.make_env(random.Random(0), n_cold_aps=args.cold_aps)
    n_ap = len(base_aps)
    oracle_ms = oracle_time_to(base_aps, n_ap - 0.5, args.switch)

    print("=== oracle 参照 (找齐时间) ===")
    print("场景: %d 台 AP, 冷信道 %d 台, 视界 %.0fs, 切信道 %.0fms"
          % (n_ap, args.cold_aps, args.horizon, args.switch))
    if oracle_ms is None:
        print("全知上界: 视界内找不齐, 请加 --horizon")
        return
    print("全知上界: %.1fs 找齐 %d 台\n" % (oracle_ms / 1000.0, n_ap))

    print("%-8s %10s %10s %9s %9s" % ("策略", "中位时间", "p90", "找齐率", "效率"))
    for pol in args.policies.split(","):
        ts = [policy_find_time(pol, seed, horizon_ms, n_ap,
                               n_cold_aps=args.cold_aps,
                               switch_ms=args.switch, floor=args.floor)
              for seed in range(args.episodes)]
        got = [t for t in ts if t is not None]
        rate = len(got) / len(ts)
        if not got:
            print("%-8s %10s %10s %8.0f%% %9s" % (pol, "-", "-", 100 * rate, "-"))
            continue
        med = statistics.median(got)
        p90 = statistics.quantiles(got, n=10)[8] if len(got) > 9 else max(got)
        # 效率 = 上界时间 / 实际时间. 只有找齐的那批参与比较, 所以找齐率必须一起看.
        eff = oracle_ms / med
        print("%-8s %9.1fs %9.1fs %8.0f%% %8.0f%%"
              % (pol, med / 1000.0, p90 / 1000.0, 100 * rate, 100 * eff))


if __name__ == "__main__":
    main()
