"""信道调度策略的统一评测: 找齐时间 / 找齐率 / 分位窗口内的发现数.

为什么不用"固定视界内的发现数"当主指标: 45 秒视界下所有策略都饱和, 分不出来.
主指标取"找齐全部 AP 的时间", 次指标取 p90 与找齐率.

用法:
    python scripts/chan_eval.py                       # 默认四策略, 三个场景
    python scripts/chan_eval.py --policies sacs,adt3 --episodes 400
"""

import argparse
import statistics
import sys

import chan_sim as S


SCENES = {
    "default": {},
    "cold":    {"n_cold_aps": 20},
    "late5g":  {"late_5g": 8},
    "arrive":  {"arrivals": 6},
    "busy":    {"busy_ch": 6, "busy_rate": 60.0},
}


def run(policy, scene, episodes, horizon, **kw):
    aps_list = []
    for seed in range(episodes):
        aps = S.episode(policy, seed, horizon * 1000.0,
                        n_cold_aps=SCENES[scene].get("n_cold_aps", 0),
                        late_5g=SCENES[scene].get("late_5g", 0),
                        arrivals=SCENES[scene].get("arrivals", 0),
                        busy_ch=SCENES[scene].get("busy_ch"),
                        busy_rate=SCENES[scene].get("busy_rate", 40.0),
                        **kw)
        aps_list.append(aps)

    # 找齐时间: 最后一台被发现的时刻; 没找齐的按视界算, 单独计漏检
    ttfs, miss = [], 0
    marks = [5, 8, 10, 20, 45]
    at = {m: [] for m in marks}
    for aps in aps_list:
        total = len(aps)
        if all(a.found for a in aps):
            ttfs.append(max(a.t_found for a in aps) / 1000.0)
        else:
            miss += 1
            ttfs.append(horizon)
        for m in marks:
            at[m].append(sum(1 for a in aps if a.found and a.t_found <= m * 1000.0))
    ttfs.sort()
    p90 = ttfs[int(len(ttfs) * 0.9) - 1]
    return {
        "med": statistics.median(ttfs), "p90": p90, "miss": miss / len(aps_list),
        "n": len(aps_list[0]),
        "at": {m: statistics.median(v) for m, v in at.items()},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies", default="psd,adt,adt3,sacs")
    ap.add_argument("--scenes", default="default,cold,late5g,arrive,busy")
    ap.add_argument("--episodes", type=int, default=300)
    ap.add_argument("--horizon", type=float, default=45.0)
    ap.add_argument("--probe", type=float, default=None, help="覆盖首探毫秒")
    args = ap.parse_args()

    pols = [x.strip() for x in args.policies.split(",") if x.strip()]
    kw = {}
    if args.probe is not None:
        kw["probe"] = args.probe

    scenes = [x.strip() for x in args.scenes.split(",") if x.strip()]
    res = {(sc, p): run(p, sc, args.episodes, args.horizon, **kw)
           for sc in scenes for p in pols}

    print(f"{args.episodes} 局/策略/场景, 视界 {args.horizon:.0f}s")
    print(f"{'场景':<9}" + "".join(f"{p:>22}" for p in pols))
    for sc in scenes:
        row = f"{sc:<9}"
        for p in pols:
            r = res[(sc, p)]
            row += f"{r['med']:>10.1f}/{r['p90']:<5.1f}{r['miss']*100:>4.0f}%"
        print(row)
    print("\n每格: 中位找齐时间(s) / p90 / 未找齐比例")

    print(f"\n{'窗口内发现数':<9}" + "".join(f"{p:>18}" for p in pols))
    for sc in scenes:
        for m in (5, 8, 20):
            row = f"{sc + '@' + str(m) + 's':<9}"
            for p in pols:
                r = res[(sc, p)]
                row += f"{r['at'][m]:>10.1f}/{r['n']:<7}"
            print(row)
    print("\n每格: 中位发现数 / 总台数")


if __name__ == "__main__":
    sys.exit(main())
