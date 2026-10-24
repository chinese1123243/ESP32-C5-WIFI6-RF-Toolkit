"""按功能族做内存归因 + 随机对抗浸泡.

和 test_sweep 的分工:
    test_sweep  问"每条命令会不会把板子打死", 一次性, 不看长期趋势
    stress      问"哪一族操作会把内部 RAM 吃掉 / 碎片化", 同一族反复启停,
                跑完等它回到空闲再采样, 这样测到的差值才是"留下来的", 不是"在用中的"

为什么盯 internal 的 largest block:
    free 总量看不出"一次最多能要到多少". 实测把 largest 压到 1344 字节, BLE 仍能
    起扫描 (NimBLE 的池在 host init 时就分好了), 但那是靠运气: 门户起 AP、新建
    HTTP 会话、临时要 4KB 缓冲, 任何一条都会失败. largest 掉下去时 free 往往还
    很富裕, 所以两条一起看.

用法:
    python scripts/stress.py COM4 --rounds 3 --label before
    python scripts/stress.py COM4 --rounds 3 --label after --compare logs/stress-before.json

输出:
    logs/stress-<label>.json   每次采样 + 每族差值, 供 --compare 用
    控制台                      每族归因表与每轮汇总
"""

import argparse
import json
import os
import re
import statistics
import sys
import time

import serial

BOOT = re.compile(r"ESP-ROM|Booting ESP|rst:0x|invalid segment|Guru Meditation")
FATAL = re.compile(r"abort\(\)|assert failed|Guru Meditation|META,\w+,ERR[^\n]*no_mem")
HEALTH = re.compile(r'\{"ok":true[^\n]*\}')

# 每族: 名字, 单次动作, 重复次数, 说明
# 动作列表里的元素是 (命令, 等待秒数); 结束时统一 stop, 确保回到空闲再采样.


class Dev:
    def __init__(self, port):
        # 不动 DTR/RTS: 这块板的桥把两线接到 EN/IO0, 一动就把板子复位
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.buf = ""
        self.raw = []

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            c = self.s.read(4096)
            if c:
                t = c.decode("utf-8", "replace")
                self.raw.append(t)
                self.buf += t

    def wait_re(self, pat, timeout):
        end = time.time() + timeout
        while time.time() < end:
            m = pat.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            self.pump(0.05)
        return None

    def sync(self, timeout=20):
        """等到 REPL 提示符. 板子刚重启时也能等到."""
        self.buf = ""
        if not self.wait_re(re.compile(r"rftool> "), timeout):
            raise RuntimeError("REPL 未就绪")
        self.pump(0.3)
        self.buf = ""
        self.raw = []

    def cmd(self, line, wait=0.35, until=None, timeout=12):
        self.s.write((line + "\r\n").encode())
        self.s.flush()
        if until is None:
            self.pump(wait)
            return None
        return self.wait_re(until, timeout)

    def health(self):
        self.buf = ""
        self.s.write(b"health --json\r\n")
        self.s.flush()
        m = self.wait_re(HEALTH, 5)
        if not m:
            return None
        try:
            d = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        return {
            "internal_free":    d["internal_free"],
            "internal_largest": d["internal_largest"],
            "psram_free":       d["psram_free"],
            "psram_largest":    d["psram_largest"],
            "heap_total":       d["heap_total"],
            "heap_min":         d["heap_min"],
            "tasks":            d["tasks"],
        }

    def take(self):
        """取走本轮原始输出, 统计重启与致命行."""
        text = "".join(self.raw)
        self.raw = []
        return text


def run_family(dev, name, steps, repeat):
    for _ in range(repeat):
        for line, wait in steps:
            dev.cmd(line, wait)
    # 收尾: 停掉一切, 等射频与任务退出, 再采样
    dev.cmd("stop", 0.4)
    dev.cmd("phish stop", 0.4)
    dev.cmd("eviltwin stop", 0.3)
    dev.cmd("cap stop", 0.4)
    dev.cmd("blescan stop", 0.3)
    dev.cmd("zbsniff stop", 0.3)
    dev.pump(0.8)


# 动作表. 参数里带 $AP 的会被换成库里的第一台 AP 的 BSSID.
FAMILIES = {
    "query": [
        ("status", 0.25), ("health", 0.4), ("help", 0.3),
        ("dump aps", 0.9), ("dump clients", 0.7), ("events 10", 0.3),
    ],
    "sniff": [
        ("sniff 6 -n 150", 2.2),
    ],
    "inject": [
        ("deauth -b $AP -n 5 -i 50 --yes", 1.0),
        ("probeflood -n 10 -i 20 --yes", 0.9),
        ("beaconflood -p ST -n 20 -i 20 --yes", 1.0),
    ],
    "apmode": [
        ("phish start StressAP", 2.2),
        ("phish stop", 0.8),
        ("http start", 1.6),
        ("http stop", 0.6),
    ],
    "eviltwin": [
        ("eviltwin clone $AP --yes", 2.6),
        ("eviltwin stop", 0.8),
    ],
    "capture": [
        ("cap start key", 0.9),
        ("sniff 6 -n 80", 1.6),
        ("cap stop", 0.8),
        ("cap clear", 0.6),
    ],
    "switch": [
        # 模式切换风暴: 泄漏最容易藏在这里, 上一个作业还没退干净就起下一个
        ("sniff 6", 0.5), ("deauth -b $AP -n 3 -i 30 --yes", 0.5),
        ("sniff 6", 0.4), ("beaconflood -p ST -n 10 -i 20 --yes", 0.5),
        ("stop", 0.4),
    ],
    "ble": [
        # BLE 侧反复重开. 起扫描要一块连续内部 RAM, 这里失败就是
        # "BLE 内存不足" 的现场: 面板上 free 还很多, 但最大块不够.
        ("blescan start", 1.2),
        ("blescan stop", 0.6),
        ("bleadv eddystone https://example.com/x", 1.0),
        ("bleadv stop", 0.6),
    ],
    "invalid": [
        ("sniff 999", 0.3), ("deauth", 0.3), ("beaconflood --yes", 0.3),
        ("config get nokey", 0.3), ("raw tx", 0.3), ("nosuchcmd", 0.3),
        ("dump nothing", 0.3), ("export xml", 0.3),
    ],
}


def first_ap(dev):
    dev.buf = ""
    dev.s.write(b"dump aps\r\n")
    dev.s.flush()
    m = dev.wait_re(re.compile(r"AP,([0-9a-fA-F:]{17})"), 6)
    dev.pump(0.6)
    dev.take()
    return m.group(1) if m else "00:11:22:33:44:55"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--repeat", type=int, default=3, help="每族重复次数")
    ap.add_argument("--label", default="run")
    ap.add_argument("--families", default="", help="逗号分隔, 只跑这几族")
    ap.add_argument("--compare", default="", help="与已有 json 对比")
    ap.add_argument("--max-leak", type=int, default=256,
                    help="单族永久占用超过这个字节数就判失败 (默认 256)")
    ap.add_argument("--min-largest", type=int, default=16384,
                    help="尾部最大连续块低于这个值就判失败 (默认 16384)")
    args = ap.parse_args()

    dev = Dev(args.port)
    dev.sync()
    dev.cmd("stop", 0.4)

    # 每次跑之前清干净: 上一轮留下的库/日志/落盘数据会污染基线
    for c in ("dump clear", "hs clear", "cap clear", "karma clear",
              "blescan clear", "log clear", "phish stop", "eviltwin stop"):
        dev.cmd(c, 0.35)
    dev.take()

    ap_bssid = first_ap(dev)
    dev.cmd("stop", 0.4)
    dev.pump(1.0)
    dev.take()

    base = dev.health()
    if not base:
        print("拿不到 health, 检查串口")
        return 1
    print("基线: internal free %d / largest %d / psram free %d / tasks %d"
          % (base["internal_free"], base["internal_largest"],
             base["psram_free"], base["tasks"]))

    names = [n for n in (args.families.split(",") if args.families else FAMILIES)]
    unknown = [n for n in names if n not in FAMILIES]
    if unknown:
        print("未知功能族:", unknown)
        return 1

    result = {"label": args.label, "port": args.port, "rounds": [],
              "baseline": base, "ap": ap_bssid, "families": names}

    for r in range(args.rounds):
        print("\n===== 第 %d 轮 =====" % (r + 1))
        rounds = {"family": [], "reboots": 0, "fatals": 0, "errors": 0}
        for fam in names:
            steps = [(c.replace("$AP", ap_bssid), w) for c, w in FAMILIES[fam]]
            h0 = dev.health()
            t0 = time.time()
            run_family(dev, fam, steps, args.repeat)
            h1 = dev.health()
            text = dev.take()
            boots = len(BOOT.findall(text))
            fatals = len(FATAL.findall(text))
            errs = len(re.findall(r"META,\w+,ERR", text))
            rounds["reboots"] += boots
            rounds["fatals"] += fatals
            rounds["errors"] += errs
            if not (h0 and h1):
                print("  %-9s 采样失败" % fam)
                continue
            d_int = h1["internal_free"] - h0["internal_free"]
            d_big = h1["internal_largest"] - h0["internal_largest"]
            d_task = h1["tasks"] - h0["tasks"]
            row = {
                "family": fam, "dt": round(time.time() - t0, 1),
                "before": h0, "after": h1,
                "d_internal_free": d_int, "d_internal_largest": d_big,
                "d_tasks": d_task, "reboots": boots, "fatals": fatals,
            }
            rounds["family"].append(row)
            print("  %-9s %5.1fs  int free %+6d  largest %+6d  tasks %+d"
                  "  reboot=%d fatal=%d"
                  % (fam, row["dt"], d_int, d_big, d_task, boots, fatals))
        rounds["end"] = dev.health()
        result["rounds"].append(rounds)

    # 汇总: 每族跨轮的中位数, 比单次更能说明问题
    print("\n===== 归因（跨轮中位数）=====")
    print("%-9s %8s %8s %7s" % ("族", "内部Δfree", "内部Δlargest", "Δtasks"))
    summary = {}
    for fam in names:
        rows = [f for r in result["rounds"] for f in r["family"] if f["family"] == fam]
        if not rows:
            continue
        med_free = int(statistics.median([x["d_internal_free"] for x in rows]))
        med_big = int(statistics.median([x["d_internal_largest"] for x in rows]))
        med_task = int(statistics.median([x["d_tasks"] for x in rows]))
        summary[fam] = {"d_internal_free": med_free, "d_internal_largest": med_big,
                        "d_tasks": med_task, "runs": len(rows)}
        print("%-9s %+8d %+8d %+7d" % (fam, med_free, med_big, med_task))
    result["summary"] = summary

    tail = result["rounds"][-1]["end"]
    result["tail"] = tail
    if tail:
        print("\n最终: internal free %d / largest %d / psram free %d / tasks %d"
              % (tail["internal_free"], tail["internal_largest"],
                 tail["psram_free"], tail["tasks"]))
        print("相对基线: free %+d, largest %+d"
              % (tail["internal_free"] - base["internal_free"],
                 tail["internal_largest"] - base["internal_largest"]))
    total_boot = sum(r["reboots"] for r in result["rounds"])
    total_fatal = sum(r["fatals"] for r in result["rounds"])
    print("重启 %d, 致命 %d, ERR 行 %d"
          % (total_boot, total_fatal, sum(r["errors"] for r in result["rounds"])))

    os.makedirs("logs", exist_ok=True)
    path = "logs/stress-%s.json" % args.label
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print("已写入", path)

    if args.compare:
        with open(args.compare, encoding="utf-8") as f:
            old = json.load(f)
        print("\n===== 对比 %s -> %s =====" % (old["label"], args.label))
        print("%-9s %14s %14s %10s" % ("族", "Δfree 前", "Δfree 后", "改善"))
        for fam in names:
            o = old["summary"].get(fam)
            n = summary.get(fam)
            if not o or not n:
                continue
            print("%-9s %+14d %+14d %+10d"
                  % (fam, o["d_internal_free"], n["d_internal_free"],
                     n["d_internal_free"] - o["d_internal_free"]))
        ob, nb = old["tail"], tail
        if ob and nb:
            print("尾部 largest: %d -> %d (%+d)"
                  % (ob["internal_largest"], nb["internal_largest"],
                     nb["internal_largest"] - ob["internal_largest"]))

    ok = total_boot == 0 and total_fatal == 0

    # 闸门: 只看两条能证伪的线, 别的一律不判
    leaks = {f: s for f, s in summary.items() if s["d_internal_free"] < -args.max_leak}
    if leaks:
        ok = False
        print("\n泄漏超限 (阈值 %d B):" % args.max_leak)
        for f, s in sorted(leaks.items(), key=lambda x: x[1]["d_internal_free"]):
            print("  %-9s %+d B  跨 %d 轮中位" % (f, s["d_internal_free"], s["runs"]))
    if tail and tail["internal_largest"] < args.min_largest:
        ok = False
        print("\n最大连续块 %d B 低于阈值 %d B"
              % (tail["internal_largest"], args.min_largest))
    if not ok:
        print("\n判定: FAIL")
    else:
        print("\n判定: PASS")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
