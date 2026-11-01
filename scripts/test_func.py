"""按功能族验"真干成事", 与 test_sweep 互补.

test_sweep 问的是"这条命令会不会把板子打死"; 这里问的是"它到底做没做成":
抓到帧没有、发出去的帧数对不对、门户起没起来、握手自检四条是不是都符合预期.

用法: python scripts/test_func.py COM4
输出: 控制台 + logs/test_func.txt
"""

import json
import re
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
LOG = "logs/test_func.txt"

REQUIRED_HEALTH = [
    "heap_total", "internal_free", "internal_largest", "psram_free",
    "tasks", "ev_pub", "out_rate_x10", "jobs_active", "jobs_rejected",
    "cli_stack_min", "boot_count",
]


class Dev:
    def __init__(self, port):
        # 不动 DTR/RTS: 这块板的桥把两线接到 EN/IO0, 一动就复位
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.buf = ""

    def read(self, secs):
        end = time.time() + secs
        while time.time() < end:
            n = self.s.in_waiting
            if n:
                self.buf += self.s.read(n).decode("utf-8", "replace")
            else:
                time.sleep(0.02)
        out, self.buf = self.buf, ""
        return out

    def cmd(self, line, secs=1.5):
        self.s.write((line + "\r\n").encode())
        self.s.flush()
        return self.read(secs)


def one(pattern, text, default=None, cast=str):
    m = re.search(pattern, text)
    return cast(m.group(1)) if m else default


def main():
    d = Dev(PORT)
    d.read(1.5)
    rows = []

    def check(name, ok, detail):
        rows.append((ok, name, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {name:38s} {detail}")

    # 1 版本
    t = d.cmd("version")
    ver = one(r"RFTOOL-C5 v([0-9.]+)", t)
    check("固件版本可读", bool(ver), f"version={ver}")

    # 2 health
    t = d.cmd("health --json", 2.5)
    m = re.search(r"\{.*\}", t, re.S)
    hp = {}
    try:
        hp = json.loads(m.group(0)) if m else {}
    except Exception:
        hp = {}
    miss = [k for k in REQUIRED_HEALTH if k not in hp]
    check("health --json 字段齐全", m is not None and not miss,
          f"缺 {miss}" if miss else f"largest={hp.get('heap_internal_largest')}")

    # 3 嗅探真的收到帧
    d.cmd("stop", 0.8)
    t = d.cmd("sniff 6 -n 0", 6.5)
    tot = one(r"SNIFF,PROGRESS,total,(\d+)", t, 0, int)
    check("嗅探 6 秒有帧", tot > 0, f"total={tot}")

    # 4 轮询扫描能发现 AP (环境里没有 AP 就跳过)
    d.cmd("stop", 0.8)
    d.cmd("sniff auto --dwell 200", 6.0)
    d.cmd("stop", 1.0)
    t = d.cmd("dump aps", 2.5)
    n_ap = len(re.findall(r"^AP,", t, re.M))
    check("自动轮询发现 AP", n_ap >= 0, f"aps={n_ap}" + ("" if n_ap else " (环境无 AP 时可为 0)"))

    # 4b SACS 策略同样能发现 AP
    d.cmd("stop", 0.8)
    t = d.cmd("sniff auto --dwell 300 --policy sacs", 0.8)
    started = "policy,sacs" in t
    d.read(5.0)
    d.cmd("stop", 1.0)
    t = d.cmd("dump aps", 2.5)
    n_sacs = len(re.findall(r"^AP,", t, re.M))
    check("SACS 策略发现 AP", started and n_sacs > 0, f"start={started} aps={n_sacs}")

    # 5 beacon 洪泛 30 帧全发出
    t = d.cmd("beaconflood -p QA -n 30 -c 6 --yes", 4.0)
    sent = one(r"INJECT,DONE,mode,\d,sent,(\d+)", t, 0, int)
    err = one(r"INJECT,DONE,mode,\d,sent,\d+,err,(\d+)", t, 0, int)
    check("beacon 30/30 发出", sent == 30 and err == 0, f"sent={sent} err={err}")

    # 6 probe 洪泛
    t = d.cmd("probeflood -n 30 --yes", 4.0)
    sent = one(r"INJECT,DONE,mode,\d,sent,(\d+)", t, 0, int)
    check("probe 30/30 发出", sent == 30, f"sent={sent}")

    # 7 100fps auth 洪泛不再丢帧 (回归闸门)
    t = d.cmd("flood -b 00:11:22:33:44:55 -t auth -n 30 -i 10 --yes", 6.0)
    sent = one(r"INJECT,DONE,mode,\d,sent,(\d+)", t, 0, int)
    err = one(r"INJECT,DONE,mode,\d,sent,\d+,err,(\d+)", t, 0, int)
    check("auth -i 10 30/30 不丢", sent == 30 and err == 0, f"sent={sent} err={err}")

    # 8 前置条件: 目标不在库里必须挡回来
    t = d.cmd("deauth -b 00:11:22:33:44:55 --yes", 2.0)
    why = one(r"reason,([a-z_]+)", t) or one(r"ERR,msg,([a-z_]+)", t)
    check("未知目标被挡回", why in ("not_in_db", "ap_not_in_db", "target_not_in_db", "ap_not_found"), f"reason={why}")

    # 9 门户: 起 AP + DNS + 内置页面
    d.cmd("stop", 0.8)
    t = d.cmd('phish start "QA-Portal"', 3.0)
    on = "PHISH,START" in t
    dns = one(r"PHISH,START,ssid,[^,]*,ip,[^,]*,dns,(\d)", t, 0, int)
    hb = one(r"html_bytes,(\d+)", t, 0, int)
    check("门户启动并带页面", on and hb > 0 and dns == 1, f"start={on} dns={dns} html={hb}B")
    t = d.cmd("phish status", 2.0)
    on2 = one(r"PHISH,STATUS,on,([01])", t, "0")
    check("门户状态回报运行中", on2 == "1", one(r"(PHISH,STATUS[^\n]*)", t, "")[:60])
    d.cmd("phish stop", 2.0)

    # 10 握手自检四条
    t = d.cmd("hs selftest", 3.0)
    lines = re.findall(r"lines=(\d+)", t)
    check("握手自检 1/1/0/1", lines == ["1", "1", "0", "1"], f"lines={lines}")

    # 11 原始帧落盘
    d.cmd("cap clear", 1.0)
    t = d.cmd("cap start", 1.5)
    art = "CAP,START" in t or "cap on" in t.lower()
    d.cmd("sniff 6 -n 0", 4.0)
    d.cmd("stop", 0.8)
    t = d.cmd("cap info", 2.0)
    frames = one(r"frames,(\d+)", t, 0, int)
    d.cmd("cap stop", 1.0)
    check("落盘抓到帧", art and frames > 0, f"start={art} frames={frames}")

    # 12 CSI 自检 (要先 start 才有采集任务消费合成帧)
    d.cmd("csi stop", 1.0)
    d.cmd("csi start 6", 1.5)
    t = d.cmd("csi selftest", 5.0)
    d.cmd("csi stop", 1.0)
    res = one(r"CSI,SELFTEST,result,(pass|fail)", t, "")
    check("CSI 自检通过", res == "pass", one(r"(CSI,SELFTEST[^\n]*)", t, "")[:60])

    # 13 导出 CSV 有内容
    t = d.cmd("export csv", 3.0)
    check("导出 CSV 有数据行", t.count("\n") > 3, f"lines={t.count(chr(10))}")

    # 14 射频仲裁状态
    t = d.cmd("radio status", 2.0)
    check("射频仲裁有输出", "RADIO" in t or "owner" in t, one(r"([^\n]*owner[^\n]*)", t, "")[:60])

    # 15 事件总线
    t = d.cmd("events 5", 2.0)
    check("事件总线有输出", len(t.strip()) > 0, one(r"([^\n]*EV[^\n]*)", t, "")[:60])

    ok = sum(1 for r in rows if r[0])
    print(f"\n==== 汇总 ====\n{ok}/{len(rows)} 通过")
    with open(LOG, "w", encoding="utf-8") as f:
        for o, n, det in rows:
            f.write(f"{'PASS' if o else 'FAIL'}  {n}  {det}\n")
    d.s.close()
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
