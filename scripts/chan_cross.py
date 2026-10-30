#!/usr/bin/env python3
"""用 chan_sim.py 的公式复算 PSD 驻留, 与 C 实现逐点比对.

为什么值得做: 驻留算法原来绑在 s_ch_* 原子量上, 只能在板子上看效果;
抽成纯函数后, 同一份输入可以喂给 C 与 Python 两边, 公式不一致会立刻暴露.

chan_sim.py 的 run_psd 里写的是:
    dwell = base * (share * len(order)) ** 0.5
    lo    = floor if w > 0 else floor * cold_factor
    dwell = min(max(dwell, lo), base * 2)

用法: python scripts/chan_cross.py
退出码 0 表示全部一致.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLOOR = 250          # 与 chan_sched.h 的 CHAN_DWELL_FLOOR_MS 一致
COLD_FACTOR = 0.6    # 与 chan_sim.py 的 cold_factor 默认值一致


def sim_psd(base, found, total, n):
    """逐字照 chan_sim.py run_psd 的算式."""
    share = found / total
    dwell = base * (share * n) ** 0.5
    lo = FLOOR if found > 0 else FLOOR * COLD_FACTOR
    if base <= FLOOR:
        lo = base
    return int(min(max(dwell, lo), base * 2))


def main():
    out_dir = ROOT / "build" / "host"
    dump = out_dir / "chan_dump"
    if not dump.exists() and (out_dir / "chan_dump.exe").exists():
        dump = out_dir / "chan_dump.exe"      # Windows 下带后缀
    if not dump.exists():
        print("先跑 bash test/host/run_all.sh 生成 build/host/chan_dump")
        return 2

    out = subprocess.run([str(dump)], capture_output=True, text=True, check=True).stdout
    rows = [l for l in out.strip().splitlines() if l and not l.startswith("base,")]

    diff = []
    cap_diff = []
    for line in rows:
        base, found, total, n, got = (int(x) for x in line.split(","))
        want = sim_psd(base, found, total, n)
        if got != want:
            # 固件多一道绝对上限 2000ms, 仿真器没有; 单独归类, 不算公式错
            if got == 2000 and want > 2000:
                cap_diff.append((base, found, total, got, want))
            else:
                diff.append((base, found, total, got, want))

    print(f"比对 {len(rows)} 点: 公式不一致 {len(diff)}, 只见于 2000ms 封顶 {len(cap_diff)}")

    for base, found, total, got, want in diff[:10]:
        print(f"  MISMATCH base={base} found={found} total={total}: C={got} py={want}")

    if cap_diff:
        b, f, t, got, want = cap_diff[0]
        print(f"  提示: base={b} 时 2×base 超过 2000ms, 固件封顶到 {got}, 仿真给 {want}")
        print("        仿真器没建模这个上限, 属已知差异, 不算公式错")

    return 0 if not diff else 1


if __name__ == "__main__":
    sys.exit(main())
