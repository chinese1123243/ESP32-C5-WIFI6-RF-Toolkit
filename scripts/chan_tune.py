"""SACS 的参数坐标下降寻优.

为什么坐标下降: 五个参数全网格要 243 组 x 3 场景 x N 局, 太慢; 参数之间
基本可分 (首探长度只影响前期覆盖, q0 只影响空信道后验), 一次调一个足够.

目标函数 = 中位找齐 + p90 + 40*未找齐比例, 三个场景取平均. 权重 40 是按
"漏一台等于多等 40 秒"折的: 扫描器最怕的是漏, 不是慢几秒.

用法: python scripts/chan_tune.py [--episodes 45]
"""

import argparse
import statistics
import sys

import chan_sim as S

SCENES = [("default", {}), ("cold", {"n_cold_aps": 20}), ("late5g", {"late_5g": 8}),
          ("arrive", {"arrivals": 6})]

GRIDS = {
    "sacs": ({"probe": 120.0, "renew_thresh": 0.5, "thresh": 0.45,
              "q0": 0.35, "prior_rem": 1.2},
             {"probe": [90.0, 120.0, 150.0], "renew_thresh": [0.5, 0.8, 1.2],
              "thresh": [0.3, 0.45, 0.7], "q0": [0.2, 0.35, 0.5],
              "prior_rem": [0.8, 1.2, 1.8]}),
    "adtx": ({"probe": 60.0, "gap": 2, "sat_eps": 0.05, "growth": 1.0, "empty_stop": 2},
             {"probe": [40.0, 60.0, 80.0, 100.0], "gap": [1, 2, 3],
              "sat_eps": [0.0, 0.05, 0.1, 0.2], "growth": [0.0, 1.0],
              "empty_stop": [2, 3]}),
}


def score(policy, params, episodes, horizon=45.0):
    rows = []
    for name, kw in SCENES:
        ttfs, miss = [], 0
        for seed in range(episodes):
            aps = S.episode(policy, seed, horizon * 1000.0,
                            n_cold_aps=kw.get("n_cold_aps", 0),
                            late_5g=kw.get("late_5g", 0),
                            arrivals=kw.get("arrivals", 0), **params)
            if all(a.found for a in aps):
                ttfs.append(max(a.t_found for a in aps) / 1000.0)
            else:
                miss += 1
                ttfs.append(horizon)
        ttfs.sort()
        rows.append((statistics.median(ttfs), ttfs[int(len(ttfs) * 0.9) - 1],
                     miss / episodes))
    med = statistics.mean(r[0] for r in rows)
    p90 = statistics.mean(r[1] for r in rows)
    m = statistics.mean(r[2] for r in rows)
    return med + p90 + 40 * m, med, p90, m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=45)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--policy", default="sacs")
    args = ap.parse_args()

    cur, GRID = GRIDS[args.policy]
    cur = dict(cur)
    best, med, p90, m = score(args.policy, cur, args.episodes)
    print(f"起点 {cur} -> 目标 {best:.2f} (中位 {med:.1f} p90 {p90:.1f} 漏 {m*100:.0f}%)")

    for rnd in range(args.rounds):
        for k, vals in GRID.items():
            local = None
            for v in vals:
                if v == cur[k]:
                    continue
                trial = dict(cur)
                trial[k] = v
                sc, md, p9, mm = score(args.policy, trial, args.episodes)
                if local is None or sc < local[0]:
                    local = (sc, v, md, p9, mm)
            if local and local[0] < best - 1e-9:
                best, _, med, p90, m = local
                cur[k] = local[1]
                print(f"  第{rnd+1}轮 {k:12s} -> {local[1]:<6} 目标 {best:.2f} "
                      f"(中位 {med:.1f} p90 {p90:.1f} 漏 {m*100:.0f}%)")
    print("\n最优参数:", cur)
    print(f"目标 {best:.2f} 中位 {med:.1f} p90 {p90:.1f} 漏 {m*100:.0f}%")


if __name__ == "__main__":
    sys.exit(main())
