# -*- coding: utf-8 -*-
"""
rftool monitor: 读取固件控制台输出, 重组 pcap + 实时摘要 + 统计.

固件输出约定:
  PKT,WIFI,<type>,<subtype>,<len>,<rssi>,<src_mac>,<dst_mac>,<bssid>,<ssid_or_->
  HEX,<hex bytes space-separated>   (raw 802.11 帧, 不含 FCS, 供 pcap 重组)
  META,WIFI,...                      (状态/错误)

本脚本:
  1. 写 pcap 全局头 (DLT_IEEE802_11=105)
  2. 收集连续的 PKT + HEX -> 组装一个 pcap 包记录 (ts 取 PKT 时的系统时间)
  3. 实时打印 PKT 摘要到 stderr (不污染 pcap 流)
  4. Ctrl+C 优雅关闭, 打印统计表

用法:
  python monitor.py <COMx> [-o capture.pcap]
  python monitor.py COM5 -o sniff_ch6.pcap
"""
import serial, sys, time, struct, argparse, signal
from collections import Counter

# ---- pcap 全局头 (24 字节) ----
PCAP_MAGIC   = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
PCAP_LINKTYPE_IEEE802_11 = 105  # DLT_IEEE802_11

def write_pcap_global_header(f):
    f.write(struct.pack("<IHHiIII",
        PCAP_MAGIC, PCAP_VERSION[0], PCAP_VERSION[1],
        0,  # thiszone
        0,  # sigfigs
        65535,            # snaplen
        PCAP_LINKTYPE_IEEE802_11))

def write_pcap_packet(f, ts_sec, ts_usec, raw):
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)))
    f.write(raw)

def parse_pkt_line(line):
    """PKT,WIFI,type,subtype,len,rssi,src,dst,bssid,ssid -> dict 或 None"""
    parts = line.strip().split(",")
    if len(parts) < 9 or parts[0] != "PKT":
        return None
    try:
        return {
            "type":    parts[2],
            "subtype": parts[3],
            "len":     int(parts[4]),
            "rssi":    int(parts[5]),
            "src":     parts[6],
            "dst":     parts[7],
            "bssid":   parts[8],
            "ssid":    parts[9] if len(parts) > 9 else "-",
        }
    except (ValueError, IndexError):
        return None

def parse_hex_line(line):
    """HEX,xx xx xx -> bytes 或 None"""
    line = line.strip()
    if not line.startswith("HEX,"):
        return None
    hexstr = line[4:].strip()
    if not hexstr:
        return b""
    try:
        return bytes.fromhex(hexstr.replace(" ", ""))
    except ValueError:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", help="COMx 或 /dev/ttyUSBx")
    ap.add_argument("-o", "--out", default="capture.pcap", help="输出 pcap 文件")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    args = ap.parse_args()

    port = args.port
    if port.upper().startswith("COM") and not port.startswith("\\\\"):
        port_raw = r"\\.\%s" % port
    else:
        port_raw = port

    # 打开 pcap 文件 (增量写)
    pcap = open(args.out, "wb")
    write_pcap_global_header(pcap)
    print("[*] pcap -> %s (DLT=105 IEEE802_11)" % args.out, file=sys.stderr)

    stats = Counter()
    pending = None   # 最近一个 PKT 的元信息, 等待配对的 HEX
    total_pkts = 0

    def open_serial():
        return serial.Serial(port_raw, args.baud, timeout=0.3,
                              dsrdtr=False, rtscts=False, write_timeout=5)

    s = open_serial()
    print("[*] 监听 %s @ %d baud, Ctrl+C 停止" % (port_raw, args.baud), file=sys.stderr)
    print("[*] 固件命令示例: sniff 6 10 / deauth -b <mac> / beaconflood -p TEST", file=sys.stderr)

    def cleanup(*_):
        print("\n[*] 关闭...", file=sys.stderr)
        try: s.close()
        except: pass
        pcap.close()
        print("\n========== 统计 ==========", file=sys.stderr)
        print("总帧数: %d" % total_pkts, file=sys.stderr)
        for (typ, sub), n in sorted(stats.items(), key=lambda x: -x[1]):
            print("  %-8s %-14s %d" % (typ, sub, n), file=sys.stderr)
        print("pcap 已写: %s" % args.out, file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    buf = b""
    while True:
        try:
            chunk = s.read(1024)
        except (serial.SerialException, OSError) as e:
            print("[!] 串口异常: %s, 尝试重开..." % e, file=sys.stderr)
            time.sleep(0.5)
            try: s.close()
            except: pass
            for _ in range(20):
                try:
                    s = open_serial(); break
                except Exception:
                    time.sleep(0.5)
            else:
                print("[!] 重开失败, 退出", file=sys.stderr); cleanup()
            continue
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                line_s = line.decode("utf-8", errors="replace")
            except Exception:
                continue
            line_s = line_s.rstrip("\r")
            if line_s.startswith("PKT,"):
                pending = parse_pkt_line(line_s)
                if pending:
                    total_pkts += 1
                    stats[(pending["type"], pending["subtype"])] += 1
                    # 实时摘要到 stderr
                    print("[#%d] %s/%s len=%d rssi=%d %s->%s %s" % (
                        total_pkts, pending["type"], pending["subtype"],
                        pending["len"], pending["rssi"],
                        pending["src"], pending["dst"],
                        pending["ssid"] if pending["ssid"] != "-" else ""),
                        file=sys.stderr, flush=True)
            elif line_s.startswith("HEX,"):
                raw = parse_hex_line(line_s)
                if raw is not None and pending is not None:
                    now = time.time()
                    ts_sec = int(now)
                    ts_usec = int((now - ts_sec) * 1e6)
                    write_pcap_packet(pcap, ts_sec, ts_usec, raw)
                    pcap.flush()
                    pending = None
            elif line_s.startswith("META,"):
                # 状态行透传到 stderr
                print("[meta] %s" % line_s[5:], file=sys.stderr, flush=True)
            # 其他行 (REPL 提示/启动横幅) 忽略, 不污染 pcap

if __name__ == "__main__":
    main()
