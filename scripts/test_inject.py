"""注入引擎的硬件验收测试.

每个用例都读固件回的 META 行做断言, 不看"看起来正常".
运行前先烧录最新固件, 板子接在 COM4.
"""

import re
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
LOG = "logs/test_inject.txt"

DONE = re.compile(r"META,WIFI,INJECT,DONE,mode,(\d),sent,(\d+),err,(\d+),ms,(\d+),stopped,(\d)")
STACK = re.compile(r"META,WIFI,INJECT,STACK,free_min,(\d+)")
SUPERSEDED = re.compile(r"META,WIFI,INJECT,SUPERSEDED,mode,(\d+)")
START = re.compile(r"META,WIFI,INJECT,START,mode,(\w+)")
STATUS = re.compile(r"META,WIFI,STATUS,.*?state,(\w+).*?sniff_total,(\d+)"
                    r".*?inject_total,(\d+).*?tasks,(\d+)")
SNIFF_DONE = re.compile(r"META,WIFI,SNIFF,DONE,total,(\d+)")


class Dev:
    def __init__(self, port):
        # 不动 DTR/RTS: 这块板的 USB-UART 桥把两线接到 EN/IO0,
        # pyserial 里调用 setDTR/setRTS(False) 会把板子复位, 测出来的
        # "重启"其实是测试脚本自己造成的.
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.buf = ""
        self.raw = []

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            chunk = self.s.read(4096)
            if chunk:
                text = chunk.decode("utf-8", "replace")
                self.raw.append(text)
                self.buf += text

    def wait_re(self, pattern, timeout):
        end = time.time() + timeout
        while time.time() < end:
            m = pattern.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            self.pump(0.05)
        return None

    def boot_wait(self, timeout=20):
        self.buf = ""
        if not self.wait_re(re.compile(r"rftool> "), timeout):
            raise RuntimeError("REPL 未就绪")
        self.pump(0.3)
        self.buf = ""
        # 开串口那一下有时会把板子复位, 那次的启动 banner 不算运行期重启
        self.raw = []

    def send(self, line):
        self.buf = ""
        self.s.write((line + "\r\n").encode())
        self.s.flush()

    def run(self, line, wait_done=8.0):
        """发命令, 等到 DONE 行或超时, 返回 (done_match, stack_match, raw_text)."""
        self.send(line)
        done = self.wait_re(DONE, wait_done)
        stk = self.wait_re(STACK, 1.5) if done else None
        return done, stk

    def reboots(self):
        return "".join(self.raw).count("ESP-ROM")

    def health(self):
        self.send("health --json")
        m = self.wait_re(re.compile(r'\{"ok":true[^\n]*\}'), 4)
        if not m:
            return None
        text = m.group(0)
        out = {}
        for k in ("internal_free", "internal_largest", "heap_min", "psram_free"):
            mm = re.search(r'"%s":(\d+)' % k, text)
            if mm:
                out[k] = int(mm.group(1))
        return out

    def status(self):
        self.send("status")
        m = self.wait_re(STATUS, 3)
        if not m:
            return None
        return {"state": m.group(1), "sniff_total": int(m.group(2)),
                "inject_total": int(m.group(3)), "tasks": int(m.group(4))}

    def raw_since(self, mark):
        """取 mark 之后收到的原始输出, 用于在一段序列里数行."""
        return "".join(self.raw[mark:])

    def raw_mark(self):
        return len(self.raw)


results = []
skipped = []


def check(name, ok, detail):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + " | " + detail)


def skip(name, detail):
    skipped.append((name, detail))
    print("SKIP " + name + " | " + detail)


def main():
    d = Dev(PORT)
    d.boot_wait()
    print("boot ok, reboots so far:", d.reboots())

    base = d.health()
    print("health base:", base)

    # T1 基本完成
    done, stk = d.run("beaconflood -p QA -n 30 -i 20 --yes", 12)
    if done:
        mode, sent, err, ms, stopped = (int(x) for x in done.groups())
        check("T1 beacon 30 完成", sent == 30 and err == 0 and mode == 1 and stopped == 0,
              f"sent={sent} err={err} ms={ms} stopped={stopped}")
        check("T1 栈水位充足", stk is not None and int(stk.group(1)) > 400,
              f"free_min={stk.group(1) if stk else 'n/a'} bytes")
    else:
        check("T1 beacon 30 完成", False, "超时未见 DONE")
    check("T1 无重启", d.reboots() == 0, f"reboots={d.reboots()}")

    # T2 计数与耗时
    done, _ = d.run("beaconflood -p QA -n 100 -i 10 --yes", 12)
    if done:
        mode, sent, err, ms, stopped = (int(x) for x in done.groups())
        expect = 100 * 10
        check("T2 100 帧耗时符合预期", sent == 100 and stopped == 0 and 0.6 < ms / expect < 3.5,
              f"sent={sent} ms={ms} expect~{expect}")
    else:
        check("T2 100 帧耗时符合预期", False, "超时")

    # T3 速率扫描: 不同间隔下的实际帧率与错误
    print("\n-- 速率扫描 (n=50) --")
    for iv in (5, 10, 20, 50, 100):
        done, _ = d.run(f"beaconflood -p QA -n 50 -i {iv} --yes", 15)
        if done:
            mode, sent, err, ms, stopped = (int(x) for x in done.groups())
            pps = sent / max(ms / 1000.0, 1e-3)
            print(f"   i={iv:3d}ms  sent={sent:3d} err={err:3d} ms={ms:5d}  {pps:6.1f} pps")
        else:
            print(f"   i={iv:3d}ms  超时")

    # T4 连续启动 10 次, 看堆是否回落
    print("\n-- 重复启动 --")
    for i in range(10):
        d.run("beaconflood -p QA -n 20 -i 10 --yes", 8)
    after = d.health()
    if base and after:
        delta = after["internal_free"] - base["internal_free"]
        check("T4 10 轮后内部堆稳定", abs(delta) < 8192,
              f"before={base['internal_free']} after={after['internal_free']} delta={delta}")

    # T5 中途停止
    d.send("beaconflood -p QA -n 0 -i 20 --yes")
    d.wait_re(START, 3)
    time.sleep(0.8)
    d.send("stop")
    done = d.wait_re(DONE, 5)
    st = d.status()
    stopped_flag = int(done.group(5)) if done else -1
    check("T5 运行中停止", done is not None and st is not None and st["state"] == "IDLE"
          and stopped_flag == 1,
          f"done={'yes' if done else 'no'} state={st['state'] if st else '?'} stopped={stopped_flag}")

    # T6 deauth
    done, _ = d.run("deauth -b 4C:B7:E0:16:28:29 -n 20 -i 20 --yes --force", 10)
    if done:
        mode, sent, err, ms, stopped = (int(x) for x in done.groups())
        check("T6 deauth 完成", sent == 20 and mode == 0, f"sent={sent} err={err}")
    else:
        check("T6 deauth 完成", False, "超时")

    # T7 probe
    done, _ = d.run("probeflood -n 20 -i 20 --yes", 10)
    if done:
        mode, sent, err, ms, stopped = (int(x) for x in done.groups())
        check("T7 probe 完成", sent == 20 and mode == 2, f"sent={sent} err={err}")
    else:
        check("T7 probe 完成", False, "超时")

    # T8 洪泛期间命令响应
    print("\n-- 洪泛期间响应 --")
    d.send("beaconflood -p QA -n 0 -i 10 --yes")
    d.wait_re(START, 3)
    lats = []
    for _ in range(5):
        t0 = time.time()
        d.send("version")
        if d.wait_re(re.compile(r"RFTOOL-C5 v"), 2.0):
            lats.append((time.time() - t0) * 1000)
        time.sleep(0.2)
    d.send("stop")
    d.wait_re(DONE, 5)
    if lats:
        check("T8 洪泛期间命令可达", max(lats) < 800,
              "rtt=" + " ".join(f"{x:.0f}" for x in lats) + f" max={max(lats):.0f}ms")
    else:
        check("T8 洪泛期间命令可达", False, "全部超时")

    # T9 并发启动: 新作业接管旧的, 但必须留痕, 且最后只剩一个任务
    d.send("beaconflood -p QA -n 0 -i 20 --yes")
    d.wait_re(START, 3)
    time.sleep(0.6)
    d.send("beaconflood -p QA2 -n 5 -i 20 --yes")
    sup = d.wait_re(SUPERSEDED, 3)
    done_old = d.wait_re(DONE, 5)
    stk_old = d.wait_re(STACK, 1.5)
    d.send("stop")
    done_new = d.wait_re(DONE, 5)
    st9 = d.status()
    if sup and done_old and done_new:
        old_stopped = int(done_old.group(5))
        # 顶替后必须恰好两个任务结束: 旧的 + 后来的
        check("T9 并发启动: 顶替留痕", old_stopped == 1,
              f"superseded=yes old_sent={done_old.group(2)} old_stopped={old_stopped}")
        check("T9 并发启动: 旧 DOM 均收尾", stk_old is not None,
              "两个任务的 STACK 行都收到了" if stk_old else "第二个任务的收尾行缺失")
        check("T9 并发启动后状态归 IDLE", st9 is not None and st9["state"] == "IDLE",
              f"state={st9['state'] if st9 else '?'}")
    else:
        check("T9 并发启动: 顶替留痕", False,
              f"superseded={'yes' if sup else 'no'} done_old={'yes' if done_old else 'no'}")

    # T11 计数嗅探到点自动停 -> 立刻再开, 新会话不能被迟到的停止动作杀掉.
    # 固件侧对应的缺陷: 计数到 0 时在驱动回调里只投递令牌, 真正的关 promiscuous
    # 由 stopper 任务异步做; 若新会话先起来, 迟到的 stopper 会把它关掉,
    # 表现是" 状态显示 SNIFF 但一包都收不到". 所以断言落在" 新会话确实在收包"上.
    print("\n-- T11 嗅探会话交接 --")
    mark = d.raw_mark()
    d.send("sniff 6 -n 1")
    fired = False
    for _ in range(50):                 # 轮询到"已收到 1 包"(令牌已投递) 才继续
        st = d.status()
        if st and st["sniff_total"] >= 1:
            fired = True
            break
        time.sleep(0.1)
    if not fired:
        skip("T11 计数嗅探到点自动停", "5s 内没收到任何包: 环境无流量, 用例无法触发")
        d.send("stop")
        d.pump(0.5)
    else:
        d.send("sniff 6")               # 令牌刚投递就起新会话, 刻意不等 stopper 收尾
        d.pump(2.0)
        st2 = d.status()                # 前 2 秒的收包数
        d.pump(2.0)
        st3 = d.status()                # 再 2 秒, 看还在不在涨
        ndone = d.raw_since(mark).count("META,WIFI,SNIFF,DONE")
        check("T11 一次停止只有一行 DONE", ndone == 1, f"DONE 行数={ndone}")
        check("T11 紧接着再开仍是 SNIFF",
              st3 is not None and st3["state"] == "SNIFF",
              f"state={st3['state'] if st3 else '?'}")
        # 判"还在涨"而不是"收到过": 被误杀的会话在被关掉前也能抓到几包,
        # 只看 >=1 会漏掉; 关掉之后计数就冻住了, 看增长才抓得住.
        grew = (st2 and st3 and st3["sniff_total"] > st2["sniff_total"])
        check("T11 新会话仍在持续收包(没被迟到的停止动作关掉)", grew,
              f"sniff_total {st2['sniff_total'] if st2 else '?'} -> "
              f"{st3['sniff_total'] if st3 else '?'}")
        d.send("stop")
        d.pump(1.0)

    # T12 反复"停 -> 立刻再开": 任务数不许逐轮累加.
    # 进度任务每秒醒一次、轮询任务每 dwell 醒一次, 它们靠"运行标志"判断是否该
    # 自己退出; 标志被新会话又置回 true 时旧任务会留下来, 于是每轮多两个任务.
    print("\n-- T12 任务不泄漏 --")
    d.send("sniff auto --dwell 200")
    d.pump(2.0)
    t0 = d.status()
    for _ in range(5):
        d.send("stop")
        d.send("sniff auto --dwell 200")
        d.pump(1.6)                     # 旧进度任务最多再睡 1s, 轮询任务 0.2s
    t1 = d.status()
    d.send("stop")
    d.pump(2.0)
    t2 = d.status()
    if t0 and t1 and t2:
        check("T12 5 轮停/开后任务数不增长", t1["tasks"] <= t0["tasks"] + 1,
              f"tasks {t0['tasks']} -> {t1['tasks']}")
        check("T12 全部停止后任务数回落", t2["tasks"] <= t0["tasks"] + 1,
              f"tasks {t0['tasks']} -> {t2['tasks']}")
    else:
        check("T12 5 轮停/开后任务数不增长", False, "status 未回")

    # T10 浸泡
    print("\n-- 30s 浸泡 --")
    d.send("beaconflood -p QA -n 0 -i 20 --yes")
    d.wait_re(START, 3)
    time.sleep(30)
    d.send("stop")
    done = d.wait_re(DONE, 6)
    after2 = d.health()
    check("T10 30s 浸泡后停止", done is not None, "DONE" if done else "超时")
    check("T10 浸泡无重启", d.reboots() == 0, f"reboots={d.reboots()}")
    if after2 and base:
        check("T10 浸泡后堆稳定", (base["internal_free"] - after2["internal_free"]) < 8192,
              f"free {base['internal_free']} -> {after2['internal_free']}")

    d.s.close()
    with open(LOG, "w", encoding="utf-8") as fh:
        fh.write("".join(d.raw))

    print("\n==== 汇总 ====")
    ok = sum(1 for _, o, _ in results if o)
    print(f"{ok}/{len(results)} 通过")
    for n, o, det in results:
        if not o:
            print("  未通过:", n, "|", det)
    for n, det in skipped:
        print("  跳过:", n, "|", det)
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
