"""信道调度策略的真机 A/B.

两件事必须做对, 否则测出来的是噪声:
  1. 每次试验前清空 AP 表, 否则上一轮留下的 30 多台 AP 让两条曲线都直接封顶
  2. 两种策略交替跑, 而不是先跑完 A 再跑完 B. 无线环境随时在变 (有人开关热点),
     分组跑会把环境变化算成策略差异

指标是"冷启动后 T 秒内发现了多少台 AP". 采样点在试验过程中取, 不用等到结束.

用法:
    python scripts/chan_ab.py COM4 --trials 12 --dur 15
    python scripts/chan_ab.py COM4 --trials 8 --dur 20 --dwell 500
"""

import argparse
import random
import re
import statistics
import sys
import time

import serial

STATUS = re.compile(r"META,WIFI,STATUS,state,(\w+),channel,(\d+),auto_ch,(\d+),"
                    r"sniff_total,(\d+),inject_total,\d+,aps,(\d+)")
AUTO_CH = re.compile(r"META,WIFI,AUTO,CH,(\d+),hits,(\d+),dwell,(\d+),found,(\d+)")


class Dev:
    def __init__(self, port):
        # 不动 DTR/RTS: 这块板的桥把两线接到 EN/IO0, 一动就复位
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.buf = ""

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            c = self.s.read(4096)
            if c:
                self.buf += c.decode("utf-8", "replace")

    def cmd(self, line, wait=0.4):
        self.buf = ""
        self.s.write((line + "\r\n").encode())
        self.s.flush()
        self.pump(wait)
        return self.buf

    def sync(self):
        self.buf = ""
        t0 = time.time()
        while time.time() - t0 < 20:
            self.pump(0.2)
            if "rftool> " in self.buf:
                break
        self.pump(0.3)
        self.buf = ""

    def aps(self):
        self.buf = ""
        self.s.write(b"status\r\n")
        self.s.flush()
        t0 = time.time()
        while time.time() - t0 < 3:
            self.pump(0.1)
            m = STATUS.search(self.buf)
            if m:
                return int(m.group(5))
        return None

    def alloc(self):
        self.buf = ""
        self.s.write(b"status\r\n")
        self.s.flush()
        self.pump(1.0)
        return [(int(a), int(d), int(f)) for a, _h, d, f in AUTO_CH.findall(self.buf)]


def trial(dev, policy, dur, dwell, marks):
    dev.cmd("stop", 0.5)
    dev.cmd("dump clear", 0.8)
    dev.cmd("sniff auto --dwell %d --policy %s" % (dwell, policy), 0.5)
    t0 = time.time()
    got = {}
    alloc = []
    for m in marks:
        while time.time() - t0 < m:
            dev.pump(0.05)
        got[m] = dev.aps()
        if m == marks[-1]:
            alloc = dev.alloc()        # 必须在 stop 之前取, 停了就没有 AUTO,CH 了
    dev.cmd("stop", 0.6)
    while time.time() - t0 < dur:      # 补足时长, 保证每条曲线采样窗口一致
        dev.pump(0.05)
    return got, alloc


def boot_ci(a, b, n=2000, seed=0):
    """两组差的 bootstrap 95% 区间. 样本少时比 t 检验诚实."""
    rng = random.Random(seed)
    diffs = []
    for _ in range(n):
        ra = [rng.choice(a) for _ in a]
        rb = [rng.choice(b) for _ in b]
        diffs.append(statistics.mean(rb) - statistics.mean(ra))
    diffs.sort()
    return diffs[int(n * 0.025)], diffs[int(n * 0.975)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port")
    ap.add_argument("--trials", type=int, default=12, help="每种策略的试验次数")
    ap.add_argument("--dur", type=float, default=15.0, help="单次试验时长(秒)")
    ap.add_argument("--dwell", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--marks", default="",
                    help="采样点秒数, 逗号分隔; 默认 5,10,dur")
    ap.add_argument("--policies", default="wrl,psd",
                    help="两条策略, 逗号分隔 (wrl|psd|adt)")
    args = ap.parse_args()

    pols = [x.strip() for x in args.policies.split(",") if x.strip()]
    if len(pols) != 2:
        print("--policies 必须是两条, 例如 psd,adt"); return 2
    marks = ([int(x) for x in args.marks.split(",") if x.strip()]
             if args.marks else [5, 10, int(args.dur)])
    marks = [m for m in marks if m <= args.dur] or [int(args.dur)]
    dev = Dev(args.port)
    dev.sync()

    order = []
    for i in range(args.trials):
        order += pols if i % 2 == 0 else list(reversed(pols))
    random.Random(args.seed).shuffle(order)
    # 洗牌后仍要保证两种策略次数相同 (上面已经配平, 洗牌不改变计数)

    res = {p: {m: [] for m in marks} for p in pols}
    allocs = {p: [] for p in pols}
    print("每组 %d 次, 单次 %.0fs, dwell %dms, 采样点 %s"
          % (args.trials, args.dur, args.dwell, marks))
    for i, pol in enumerate(order, 1):
        got, alloc = trial(dev, pol, args.dur, args.dwell, marks)
        for m in marks:
            if got.get(m) is not None:
                res[pol][m].append(got[m])
        allocs[pol].append(alloc)
        print("  [%2d/%d] %-3s  %s" % (i, len(order), pol,
              "  ".join("t=%ds:%s" % (m, got.get(m)) for m in marks)))

    print("\n=== 发现数（中位数, 最小-最大）===")
    print("%-6s" % "策略" + "".join("%16s" % ("t=%ds" % m) for m in marks))
    for pol in pols:
        row = "%-6s" % pol
        for m in marks:
            v = res[pol][m]
            row += "%16s" % ("%.0f (%d-%d)" % (statistics.median(v), min(v), max(v))
                             if v else "-")
        print(row)

    print("\n=== %s - %s 的差（bootstrap 95%% 区间）===" % (pols[1], pols[0]))
    for m in marks:
        a, b = res[pols[0]][m], res[pols[1]][m]
        if len(a) < 3 or len(b) < 3:
            continue
        lo, hi = boot_ci(a, b)
        diffs = statistics.mean(b) - statistics.mean(a)
        verdict = "显著" if lo > 0 or hi < 0 else "不显著"
        print("  t=%-3ds  %+5.1f 台   区间 [%+.1f, %+.1f]   %s"
              % (m, diffs, lo, hi, verdict))

    print("\n=== 末轮驻留分配（信道:dwell:发现数, 只列前 8）===")
    for pol in pols:
        rows = allocs[pol][-1] if allocs[pol] else []
        print("  %-4s %s" % (pol, " ".join("%d:%d:%d" % r for r in rows[:8]) or "-"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
