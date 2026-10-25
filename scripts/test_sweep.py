"""全命令冒烟测试: 每条命令都真实下发, 之后探活, 记录任何重启或错误行.

目的不是"功能正确", 而是找出会打板 / 会卡住 / 会泄漏资源的命令.
判断依据全部来自固件回报的输出, 不靠人工看串口.

用法: python scripts/test_sweep.py COM4
输出: 控制台 + logs/test_sweep.txt
"""

import re
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
LOG = "logs/test_sweep.txt"

BOOT = re.compile(r"ESP-ROM|Booting ESP|rst:0x|invalid segment")

# 错误行分三类, 混在一起统计就没法看了:
# 扫全跑 73 条命令, 每条后面都发一次 stop, 光 nothing_running 就能刷出七十多行,
# 真正的失败全被埋掉.
#
# FATAL  : 软硬件真的没干成事 (起不来 / 没内存 / 写失败). 这些才是要报的.
# REJECT : 入参校验把命令挡回去了. 扫全里有一批用例是故意喂非法参数的,
#          它们"报错"恰恰说明校验在工作. 不算失败, 但要计数 (看覆盖到没有).
# 剩下的 : 没见过的消息. 单独列出来, 逼着人去给它归类, 别让它悄悄溜过去.
# 标签不能写死成 WIFI|BLE|SYS: 固件里还有 RAW / KARMA / CLI / BLESCAN /
# EVILTWIN 等, 写死的话这些模块的错误行一条都统计不到, 之前就是这么漏掉
# `META,RAW,TX,ok,0,...` 那类"成功 Tag 报失败"的.
# 只把"软件真的挂了"算致命: 断言 / abort / Guru / 没内存.
# 其余 META ERR 行一律算"命令被挡回来了": 这类通常是入参非法或前置条件
# 没满足 (比如没先 scan), 是预期行为, 不该判失败.
FATAL = re.compile(
    r"META,[A-Za-z0-9_]+,ERR[^\n]*no_mem"
    r"|abort\(\)|assert failed|Guru Meditation"
)
# 模块名可以是多段: META,ZB,TX,ERR 与 META,WIFI,ERR 都是合法格式,
# 单段正则会把前者整个漏掉, 表现为"非法参数被接受了".
REJECT = re.compile(r"META,[A-Za-z0-9_]+(?:,[A-Za-z0-9_]+)*,ERR[^\n]*")
REJECT_MSG = re.compile(r"META,[A-Za-z0-9_]+(?:,[A-Za-z0-9_]+)*,ERR[^\n]*?,msg,([a-z_0-9]+)")

# 固件里目前存在的入参校验消息. 不在表里的消息会被当成"未知"单独报出来,
# 提示去补表, 而不是默默当它不存在.
KNOWN_REJECT = {
    "nothing_running", "not_running", "bad_channel", "bad_option", "bad_bssid",
    "bad_mac", "bad_station", "bad_target", "bad_format", "bad_subcmd",
    "bad_html_subcmd", "need_ssid", "no_ssid", "need_hex", "need_target",
    "need_bssid", "need_url", "need_off_len", "need_size", "need_html_subcmd",
    "ssid_hidden", "ap_not_found", "ap_not_in_db", "target_not_in_db",
    "usage_raw_assoc_bssid_ssid", "only_http_supported", "rollback_disabled",
    # 参数解析失败: 以前 argtable 的错误只打到 stderr, 不在 META 协议里,
    # App 发出命令后等不到任何回应, 也就是"设备无响应". 现在统一走这里.
    "arg_parse_failed",
    # 下面是扫全实际跑出来的, 逐个核过语义后才归类
    "need_confirm",           # 危险命令缺 --yes: 固件不接受, 调用方要弹窗后重发
    "unknown_command",        # 固件没有这条命令
    "empty_prefix",           # beaconflood -p "" : 入参校验
    "need_key", "need_key_value", "set_failed", "bad_subcmd",
    "start_failed",           # 起不来: 多为前置/配置不满足, 不是崩溃
    "no_ssid", "target_not_in_db", "need_html_subcmd", "bad_subcmd",
    # zbtx (802.15.4 发送)
    "need_channel", "bad_frame", "no_such_entry", "bad_payload_hex",
    "build_failed", "tx_start_failed", "flood_start_failed",
}


class Dev:
    def __init__(self, port):
        # 不动 DTR/RTS: 这块板的 USB-UART 桥把两线接到 EN/IO0,
        # pyserial 里调用 setDTR/setRTS(False) 会把板子复位, 测出来的
        # "重启"其实是测试脚本自己造成的.
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.raw = []
        self.buf = ""
        self.alltext = []   # 只增不减, 落盘用; shot() 会清 raw 但不碰这里

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

    def boot_wait(self, timeout=25):
        self.buf = ""
        if not self.wait_re(re.compile(r"rftool> "), timeout):
            raise RuntimeError("REPL 未就绪")
        self.pump(0.4)
        self.buf = ""
        self.raw = []

    def alive(self, timeout=2.5):
        """探活: 能回 version 就是活的."""
        self.buf = ""
        self.s.write(b"version\r\n")
        self.s.flush()
        return self.wait_re(re.compile(r"RFTOOL-C5 v"), timeout) is not None

    def flush_rx(self, secs=0.3):
        """丢弃还在路上的输出.

        上一条用例末尾那条 stop 的响应不一定在 0.3s 内到齐, 迟到部分会落进
        下一条用例的窗口, 被误判成"下一条命令被拒了". 发命令前先清一遍.
        """
        self.pump(secs)
        self.raw = []
        self.buf = ""

    def shot(self):
        """抓一次 snapshot: (重启数, 致命错误行, 入参拒绝行)."""
        text = "".join(self.raw)
        self.alltext.append(text)
        self.raw = []
        boots = len(BOOT.findall(text))
        fatals = FATAL.findall(text)
        # 拒绝行里扣掉已经是致命的那些, 避免同一行被数两次
        rejects = [ln for ln in REJECT.findall(text)
                   if ln.strip() not in fatals]
        return boots, fatals, rejects

    def health_snapshot(self):
        self.buf = ""
        self.s.write(b"health --json\r\n")
        self.s.flush()
        m = self.wait_re(re.compile(r'\{"ok":true[^\n]*\}'), 4)
        if not m:
            return None
        mm = re.search(r'"internal_free":(\d+)', m.group(0))
        return int(mm.group(1)) if mm else None

    def send(self, line, settle=0.4):
        self.s.write((line + "\r\n").encode())
        self.s.flush()
        self.pump(settle)


# (命令, 需要的事后清理, 说明, 期望)
# 期望 = None    : 正常执行, 不该出 ERR
# 期望 = "reject": 故意喂非法参数, 固件必须挡回去; 没挡住就是测试失败.
#                  这一条很重要: 之前只写了"应当被拒"的注释, 却没有断言,
#                  非法参数真被接受时扫全照样全绿.
CASES = [
    ("help",                          None, None, None),
    ("version",                       None, None, None),
    ("nosuchcmd",                     None, "未知命令: 应当被拒 (unknown_command)", "reject"),
    ("status",                        None, None, None),
    ("health",                        None, None, None),
    ("events 5",                      None, None, None),
    ("log clear",                     None, None, None),

    ("config list",                   None, None, None),
    ("config get tx_power",           None, None, None),
    ("config set tx_power 20",        None, None, None),
    ("config get tx_power",           None, None, None),

    ("ble power",                     None, None, None),
    ("ble power 10",                  None, None, None),
    ("ble power",                     None, None, None),
    ("blescan start",                 "blescan stop", None, None),
    ("blescan clear",                 None, None, None),

    ("bleadv eddystone",              "bleadv stop", None, None),
    ("bleadv ibeacon 426C7565-4368-6172-6D42-6561636F6E00 1 1 3",
                                      None, None, None),

    ("sniff 6",                       "stop", "2.4G 定信道", None),
    ("sniff auto",                    "stop", "自动跳信道", None),
    ("sniff 36",                      "stop", "5G 信道", None),
    ("sniff 177",                     "stop", "上边界", None),
    ("sniff 0",                       None, "非法信道: 应当被拒", "reject"),
    ("sniff 15",                      None, "非法信道: 应当被拒", "reject"),

    ("airtime --ch 6 --dwell 60",     None, "单信道短窗口 (会报 dwell_short)", None),
    ("airtime --ch 999",              None, "非法信道: 应当被拒", "reject"),
    ("airtime --bogus",               None, "未知参数: 应当被拒", "reject"),

    ("beaconflood -p SW -n 30 -i 20 --yes", None, None, None),
    ("beaconflood -p SW -n 30 -c 11 --yes", None, "带信道参数", None),
    ("beaconflood -p SW -n 30 -c 0 --yes",  None, "信道 0 回落到当前", None),
    ("beaconflood -p '' --yes",             None, "单引号不是空前缀(是字面 ''), 见下一条", None),
    ("beaconflood -p \"\" --yes",           None, "空前缀: 应当被拒", "reject"),
    ("beaconflood --yes",                   None, "缺 -p: 应当被拒", "reject"),
    ("beaconflood -p",                      None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),
    ("probeflood -n 30 -i 20 --yes",        None, None, None),
    ("probeflood -n 5",                     None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),
    ("deauth -b 00:11:22:33:44:55 -n 5 -i 20 --yes --force", None, None, None),
    ("deauth -b 00:11:22:33:44:55 -n 5",    None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),
    ("deauth -b 00:11:22:33:44:55 -s 00:00:00:00:00:00 -n 5 -i 20 --yes --force",
                                            None, "广播目标", None),

    ("raw beacon TESTSW 6",      None, "单帧构造", None),
    ("raw csa 00:11:22:33:44:55 1", None, "缺 --yes: 应当被拒", "reject"),
    ("raw csa 00:11:22:33:44:55 1 1 --ssid TESTSW --ch 6 --dry", None, "只组帧不发射", None),
    ("raw tx 00",                     None, "hex 太短: 应当被拒", "reject"),
    ("raw tx 0011223344",             None, "5 字节太短: 应当被拒", "reject"),

    ("cap info",                      None, None, None),
    ("cap clear",                     None, None, None),
    ("hs selftest",                   None, None, None),
    ("hs complete",                   None, None, None),
    ("hs clear",                      None, None, None),
    ("hs 22000",                      None, None, None),

    ("karma clear",                   None, None, None),
    ("karma follow 3",                "stop", "前置: 需先嗅探收集 SSID", "reject"),
    # 注意: follow <n> 的 n 是"取第 n 个已收集 SSID"的下标, 不是次数.
    # 空环境下它会因没收集到 SSID 而报 no_ssid, 那是环境所致,
    # 不代表 0 这个参数非法, 别把它当"非法参数"用例.
    ("karma follow 0",                None, "前置: 需先嗅探收集 SSID", "reject"),

    ("dump aps",                      None, None, None),
    ("dump clients",                  None, None, None),
    ("dump eapols",                   None, None, None),
    ("dump all",                      None, None, None),
    ("dump clear",                    None, None, None),

    ("pmkid watch 6",                 "stop", None, None),
    ("pmkid status",                  None, None, None),
    ("pmkid clear",                   None, None, None),
    ("pmkid active 00:11:22:33:44:55 --yes", None, "前置: 目标需先扫描入库", "reject"),
    ("pmkid active 20:87:ec:0f:4e:82",       None, "缺 --yes: 应当被拒", "reject"),
    ("cap hex 0 32",                  None, "串口自检: pcap 头十六进制回显", None),

    ("locate 00:11:22:33:44:55 2",    None, "前置: 目标需先扫描入库", "reject"),
    ("locate status",                 None, None, None),
    ("locate export",                 None, None, None),

    ("http start",                    "http stop", None, None),
    ("http status",                   None, None, None),

    ("phish status",                  None, None, None),
    ("phish stations",                None, None, None),
    ("phish creds",                   None, None, None),
    ("phish html size",               None, None, None),

    ("eviltwin clone 00:11:22:33:44:55", None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),
    ("eviltwin stop",                 None, None, None),

    ("downgrade list",                None, "只读查询: 不需要 --yes", None),
    ("wifi6",                         None, "BSS Color / TWT / RNR 一览", None),
    ("csi start 6",                    "csi stop", "CSI 采样", None),
    ("csi stats",                      None, None, None),
    ("csi selftest",                   None, "合成序列自检", None),
    ("csi stop",                       None, "重复停止: 应当被拒", "reject"),
    ("downgrade TestSSID",            None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),

    ("ftm range 00:11:22:33:44:55 6 2", None, None, None),

    ("zbsniff 11",                    "zbsniff stop", None, None),
    ("zbsniff status",                None, None, None),
    ("zbsniff clear",                 None, None, None),
    ("zbsniff 30",                    None, "非法信道: 应当被拒", "reject"),
    ("zbsniff stop",                  None, "重复停止: 应当被拒", "reject"),

    # zbtx: 全部走 --dry, 不在扫全里真的往空口打 802.15.4 帧
    ("zbtx beacon 11 0x1a2b --dry",   None, None, None),
    ("zbtx beaconreq 11 --dry",       None, None, None),
    ("zbtx data 11 0x1234 0x0001 0x0002 deadbeef --dry", None, None, None),
    ("zbtx beacon 30 --dry",          None, "非法信道: 应当被拒", "reject"),
    ("zbtx raw 01 --dry",             None, "长度不符: 应当被拒", "reject"),
    ("zbtx raw 0a88435cffffffff341207 --dry", None, None, None),
    ("zbtx replay 0 --dry",           None, "空表: 应当被拒", "reject"),
    ("zbtx stats",                    None, None, None),
    ("zbtx stop",                     None, "未启动: 应当被拒", "reject"),
    ("zbtx beacon 11",                None, "缺 --yes: 应当被拒 (need_confirm)", "reject"),

    ("scenario survey 2",             None, None, None),
    ("scenario status",               None, None, None),

    ("export csv",                    None, None, None),
    ("export json",                   None, None, None),

    ("ota status",                    None, None, None),

    # ==== 缺参数: 这些以前只在 stderr 打一句人话, META 协议里一个字都没有,
    #      App 发出去等不到回应 == 设备无响应. 现在必须给出 META ERR 行. ====
    ("sniff",                         None, "缺信道: 应当被拒", "reject"),
    ("http",                          None, "缺子命令: 应当被拒", "reject"),
    ("dump",                          None, "缺目标: 应当被拒", "reject"),
    ("export",                        None, "缺格式: 应当被拒", "reject"),
    # 注意: blescan 不带子命令是"列出已发现设备", 不是错误, 别当拒绝用例
    ("raw tx",                        None, "缺 hex: 应当被拒", "reject"),
    ("config get",                    None, "缺键名: 应当被拒", "reject"),

    # 空闲时敲 stop 必然报 nothing_running, 这是刻意的行为, 不是故障
    ("stop",                          None, "空闲时停止: 应当被拒但不崩", "reject"),
    ("stop",                          None, "重复停止: 应当被拒但不崩", "reject"),
]


def main():
    d = Dev(PORT)
    d.boot_wait()

    failures = []
    boots_total = 0
    fatal_total = 0
    reject_total = 0
    unknown = set()

    start = d.health_snapshot()

    for cmd, cleanup, note, expect in CASES:
        # 上一条用例末尾那条 stop 的响应可能还在路上, 先丢掉再发本条,
        # 否则它的 nothing_running 会被算到本条命令头上.
        d.flush_rx(0.35)
        # 命令窗口和清理窗口也要分开取快照, 理由同上.
        d.send(cmd, 0.5)
        boots, fatals, rejs = d.shot()

        if cleanup:
            d.send(cleanup, 0.6)
            cb, cf, _cr = d.shot()
            boots += cb
            fatals += cf          # 清理阶段的致命错误一样算失败, 拒绝行不算

        ok = d.alive()
        db, df, dr = d.shot()     # 探活窗口单独丢弃, 不参与判定
        boots += db
        fatals += df

        boots_total += boots
        fatal_total += len(fatals)
        reject_total += len(rejs)

        bad = []
        if not ok:
            bad.append("无响应")
        if boots:
            bad.append(f"重启x{boots}")
        for e in fatals:
            bad.append("致命:" + e.strip()[:60])
        # 标了"应当被拒"的必须真被拒, 否则等于没测
        if expect == "reject" and not rejs:
            bad.append("非法参数被接受了(应当拒绝)")
        # 没标的反而不该出拒绝行
        if expect is None and rejs:
            bad.append("意外拒绝:" + rejs[0].strip()[:60])
        if bad:
            failures.append((cmd, "; ".join(bad)))

        msgs = {m for ln in rejs for m in REJECT_MSG.findall(ln)}
        unknown |= msgs - KNOWN_REJECT

        flag = "OK " if not bad else "BAD"
        print(f"{flag} {cmd[:52]:54s} alive={int(ok)} boots={boots} "
              f"rej={len(rejs)} {('| ' + note) if note else ''}"
              + (f"  <== {'; '.join(bad)}" if bad else ""))

        # 每条命令后都强制回 IDLE, 避免状态串到下一条.
        # 它产生的 nothing_running 是预期的, 单独丢弃, 不进本条统计.
        d.send("stop", 0.3)
        d.shot()
        d.buf = ""

    end = d.health_snapshot()

    print("\n==== 汇总 ====")
    print(f"用例数          : {len(CASES)}")
    print(f"累计重启        : {boots_total}")
    print(f"致命错误行      : {fatal_total}")
    print(f"入参拒绝行      : {reject_total}  (扫全末尾的 stop 不计入)")
    print(f"异常/失败       : {len(failures)}")
    for c, why in failures:
        print(f"   {c[:50]:52s} {why}")
    if unknown:
        print(f"未归类的 ERR 消息: {sorted(unknown)}  <== 去 KNOWN_REJECT 补表")
    if start and end:
        print(f"堆 before/after: {start} / {end}")

    with open(LOG, "w", encoding="utf-8") as fh:
        fh.write("".join(d.alltext))

    return 0 if (not failures and boots_total == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
