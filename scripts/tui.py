#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rftool TUI — 交互式终端控制工具

功能:
  - readline 命令历史 (↑↓) + 行编辑 (←→)
  - 实时彩色格式化 PKT/META/HEX 输出
  - 自动 pcap 写入 (DLT=105 IEEE802_11)
  - 底部状态栏: 状态/信道/帧数统计
  - Ctrl+C 退出时打印统计

用法:
  python tui.py <COMx> [-o capture.pcap]
  python tui.py COM4
  python tui.py COM4 -o sniff.pcap

依赖: pyserial (pip install pyserial)
"""
import serial, sys, os, time, struct, signal, threading, argparse

# Windows 终端 UTF-8 输出 (解决中文乱码)
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from collections import Counter
from datetime import datetime

try:
    import readline
except ImportError:
    readline = None  # Windows 可能无 readline, 用 input() 降级

# ==================== 颜色 ====================
class C:
    R   = "\033[31m"
    G   = "\033[32m"
    Y   = "\033[33m"
    B   = "\033[34m"
    M   = "\033[35m"
    CY  = "\033[36m"
    W   = "\033[37m"
    DIM = "\033[2m"
    BOLD= "\033[1m"
    RST = "\033[0m"

# 帧类型 -> 颜色
TYPE_COLOR = {
    "BEACON":     C.DIM + C.CY,
    "PROBE_REQ":  C.Y,
    "PROBE_RESP": C.CY,
    "DEAUTH":     C.R + C.BOLD,
    "DISASSOC":   C.R,
    "AUTH":       C.G,
    "ASSOC_REQ":  C.G,
    "ASSOC_RESP": C.G,
    "DATA":       C.DIM,
    "DATA_QOS":   C.DIM,
}

def color_for_type(ftype, fsub):
    return TYPE_COLOR.get(fsub, C.W)

# ==================== pcap ====================
PCAP_MAGIC   = 0xA1B2C3D4
PCAP_LINKTYPE = 105  # DLT_IEEE802_11

def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, PCAP_LINKTYPE))

def write_pcap_packet(f, ts_sec, ts_usec, raw):
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)))
    f.write(raw)

# ==================== 全局状态 ====================
class State:
    def __init__(self):
        self.running = True
        self.ser = None
        self.pcap_file = None
        self.pcap_path = None
        self.stats = Counter()
        self.total_pkts = 0
        self.total_inject = 0
        self.pending_pkt = None  # 等待 HEX 配对
        self.fw_state = "IDLE"
        self.fw_channel = 0
        self.lock = threading.Lock()

st = State()

# ==================== 串口读取线程 ====================
def parse_pkt_line(line):
    parts = line.strip().split(",")
    if len(parts) < 9 or parts[0] != "PKT":
        return None
    try:
        return {
            "type": parts[2], "subtype": parts[3],
            "len": int(parts[4]), "rssi": int(parts[5]),
            "src": parts[6], "dst": parts[7],
            "bssid": parts[8],
            "ssid": parts[9] if len(parts) > 9 else "-",
        }
    except (ValueError, IndexError):
        return None

def parse_hex_line(line):
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

def format_pkt(pkt):
    col = color_for_type(pkt["type"], pkt["subtype"])
    ssid_str = f' "{pkt["ssid"]}"' if pkt["ssid"] != "-" else ""
    rssi_col = C.G if pkt["rssi"] > -60 else (C.Y if pkt["rssi"] > -75 else C.R)
    return (f"  {col}{pkt['type']}/{pkt['subtype']:<12}{C.RST} "
            f"len={pkt['len']:<4} rssi={rssi_col}{pkt['rssi']}{C.RST} "
            f"{C.DIM}{pkt['src']}{C.RST} -> {C.DIM}{pkt['dst']}{C.RST}{ssid_str}")

def serial_reader():
    buf = b""
    while st.running:
        try:
            if st.ser is None:
                time.sleep(0.1)
                continue
            chunk = st.ser.read(1024)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    line_s = line.decode("utf-8", errors="replace").rstrip("\r")
                except:
                    continue

                # 去掉行首的 rftool> 提示符 (固件可能在同一行输出 prompt + response)
                while line_s.startswith("rftool>"):
                    line_s = line_s[7:].lstrip()

                if line_s.startswith("PKT,"):
                    pkt = parse_pkt_line(line_s)
                    if pkt:
                        with st.lock:
                            st.total_pkts += 1
                            st.stats[(pkt["type"], pkt["subtype"])] += 1
                            st.pending_pkt = pkt
                        print(format_pkt(pkt), flush=True)
                        if st.total_pkts % 10 == 0:
                            maybe_print_status()
                elif line_s.startswith("HEX,"):
                    raw = parse_hex_line(line_s)
                    if raw is not None and st.pending_pkt is not None and st.pcap_file:
                        now = time.time()
                        ts_sec = int(now)
                        ts_usec = int((now - ts_sec) * 1e6)
                        write_pcap_packet(st.pcap_file, ts_sec, ts_usec, raw)
                        st.pcap_file.flush()
                        st.pending_pkt = None
                elif line_s.startswith("META,"):
                    # 解析状态行
                    parts = line_s[5:].split(",")
                    meta_col = C.B
                    # 高亮关键字
                    if "ERR" in line_s:
                        meta_col = C.R
                    elif "START" in line_s:
                        meta_col = C.G
                    elif "DONE" in line_s:
                        meta_col = C.CY
                    # 提取 state/channel (兼容多种 META 格式)
                    # 格式1: WIFI,STATUS,state,IDLE,channel,0,...
                    # 格式2: WIFI,SNIFF,START,channel,6,count,10
                    # 格式3: WIFI,SNIFF,DONE,total,10
                    # 格式4: WIFI,INJECT,START,...
                    # 格式5: WIFI,INJECT,DONE,...
                    if len(parts) >= 3:
                        action = parts[1]  # SNIFF / INJECT / STATUS / ERR
                        event  = parts[2]  # START / DONE / ...
                        if action == "SNIFF" and event == "START":
                            with st.lock:
                                st.fw_state = "SNIFF"
                            # 提取 channel (格式: WIFI,SNIFF,START,channel,6,count,10)
                            for i in range(3, len(parts)-1, 2):
                                if parts[i] == "channel":
                                    try:
                                        with st.lock:
                                            st.fw_channel = int(parts[i+1])
                                    except ValueError:
                                        pass
                                    break
                        elif action == "SNIFF" and event == "DONE":
                            with st.lock:
                                st.fw_state = "IDLE"
                        elif action == "INJECT" and event == "START":
                            with st.lock:
                                st.fw_state = "INJECT"
                        elif action == "INJECT" and event in ("DONE", "STOP"):
                            with st.lock:
                                st.fw_state = "IDLE"
                    for i in range(0, len(parts)-1, 2):
                        if parts[i] == "state":
                            with st.lock:
                                st.fw_state = parts[i+1]
                        elif parts[i] == "channel":
                            try:
                                with st.lock:
                                    st.fw_channel = int(parts[i+1])
                            except ValueError:
                                pass
                        elif parts[i] == "inject_total":
                            try:
                                with st.lock:
                                    st.total_inject = int(parts[i+1])
                            except ValueError:
                                pass
                    print(f"  {meta_col}[meta] {line_s[5:]}{C.RST}", flush=True)
                    maybe_print_status()
                elif "========================================" in line_s:
                    print(f"  {C.M}{line_s}{C.RST}", flush=True)
                elif "ESP32-C5" in line_s or "Authorized" in line_s or "ILLEGAL" in line_s:
                    print(f"  {C.M}{line_s}{C.RST}", flush=True)
                elif line_s.strip() == "Commands:":
                    # help 命令输出: 中英双语
                    print(f"  {C.BOLD}命令列表 / Commands:{C.RST}", flush=True)
                elif line_s.strip().startswith("help ") and "Show this help" in line_s:
                    print(f"  {line_s}  {C.DIM}# 显示帮助{C.RST}", flush=True)
                elif line_s.strip().startswith("status ") and "Show" in line_s:
                    print(f"  {line_s}  {C.DIM}# 显示状态和计数器{C.RST}", flush=True)
                elif line_s.strip().startswith("sniff ") and "Start" in line_s:
                    print(f"  {line_s}  {C.DIM}# 启动 Wi-Fi 混杂模式嗅探{C.RST}", flush=True)
                elif line_s.strip().startswith("stop ") and "Stop" in line_s:
                    print(f"  {line_s}  {C.DIM}# 停止当前嗅探/注入{C.RST}", flush=True)
                elif line_s.strip().startswith("deauth ") and "Deauth" in line_s:
                    print(f"  {line_s}  {C.DIM}# 构造 deauth 帧注入 (仅限授权使用){C.RST}", flush=True)
                elif line_s.strip().startswith("beaconflood ") and "Beacon" in line_s:
                    print(f"  {line_s}  {C.DIM}# 伪造 beacon 洪水 (仅限授权使用){C.RST}", flush=True)
                elif line_s.strip().startswith("probeflood ") and "Probe" in line_s:
                    print(f"  {line_s}  {C.DIM}# probe request 洪水{C.RST}", flush=True)
                elif line_s.strip().startswith("Usage:"):
                    print(f"  {C.DIM}{line_s}{C.RST}", flush=True)
                elif line_s.strip().startswith("Type '<cmd>"):
                    print(f"  {C.DIM}{line_s}  # 输入 '<cmd> --help' 查看详细参数{C.RST}", flush=True)
                elif line_s.strip():
                    # 其他输出 (启动日志等)
                    print(f"  {C.DIM}{line_s}{C.RST}", flush=True)
        except (serial.SerialException, OSError) as e:
            if st.running:
                print(f"  {C.R}[!] 串口异常: {e}, 重连...{C.RST}", flush=True)
                time.sleep(0.5)
                try:
                    if st.ser:
                        st.ser.close()
                except:
                    pass
                for _ in range(10):
                    if not st.running:
                        break
                    try:
                        port = st.ser.portstr if st.ser else None
                        baud = st.ser.baudrate if st.ser else 115200
                        st.ser = serial.Serial(port, baud, timeout=0.3)
                        print(f"  {C.G}[+] 串口重连成功{C.RST}", flush=True)
                        break
                    except:
                        time.sleep(0.5)
        except Exception as e:
            if st.running:
                print(f"  {C.R}[!] reader error: {e}{C.RST}", flush=True)

# ==================== 状态变化提示 ====================
_last_state = None
_last_count = 0

def maybe_print_status():
    """状态或帧数变化时打印一行 (不打扰 input 提示符)"""
    global _last_state, _last_count
    with st.lock:
        cur_state = st.fw_state
        cur_count = st.total_pkts
    if cur_state != _last_state:
        state_col = {"IDLE": C.B, "SNIFF": C.G, "INJECT": C.R}.get(cur_state, C.W)
        print(f"  {C.DIM}--- {state_col}{cur_state}{C.RST}{C.DIM} ch={st.fw_channel} pkts={st.total_pkts} ---{C.RST}", flush=True)
        _last_state = cur_state
    _last_count = cur_count

# ==================== 命令历史 ====================
HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".rftool_history")

def init_readline():
    if readline:
        try:
            readline.read_history_file(HISTORY_FILE)
        except (FileNotFoundError, IOError):
            pass
        readline.set_history_length(100)

def save_readline():
    if readline:
        try:
            readline.write_history_file(HISTORY_FILE)
        except:
            pass

# ==================== 命令补全 ====================
COMMANDS = ["help", "status", "sniff", "stop", "deauth", "beaconflood", "probeflood", "exit", "quit"]

def completer(text, state):
    matches = [c for c in COMMANDS if c.startswith(text)]
    if state < len(matches):
        return matches[state]
    return None

# ==================== 主循环 ====================
def cleanup():
    st.running = False
    time.sleep(0.2)
    print(f"\n\n  {C.BOLD}========== 统计 =========={C.RST}")
    print(f"  总帧数: {C.G}{st.total_pkts}{C.RST}")
    for (typ, sub), n in sorted(st.stats.items(), key=lambda x: -x[1]):
        print(f"    {typ:<8} {sub:<14} {n}")
    if st.pcap_file:
        st.pcap_file.close()
        print(f"  pcap: {st.pcap_path}")
    if st.ser:
        try:
            st.ser.close()
        except:
            pass
    save_readline()
    print(f"  {C.DIM}Bye.{C.RST}")

def signal_handler(sig, frame):
    raise KeyboardInterrupt

def main():
    signal.signal(signal.SIGINT, signal_handler)

    ap = argparse.ArgumentParser(description="rftool 交互式终端控制工具")
    ap.add_argument("port", help="COMx 或 /dev/ttyUSBx")
    ap.add_argument("-o", "--out", default=None, help="输出 pcap 文件 (不指定则不写 pcap)")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    args = ap.parse_args()

    port = args.port
    if port.upper().startswith("COM") and not port.startswith("\\\\"):
        port_raw = r"\\.\%s" % port
    else:
        port_raw = port

    # 打开串口
    try:
        st.ser = serial.Serial(port_raw, args.baud, timeout=0.3)
    except Exception as e:
        print(f"{C.R}[!] 无法打开 {port}: {e}{C.RST}")
        sys.exit(1)

    # 打开 pcap
    if args.out:
        st.pcap_path = args.out
        st.pcap_file = open(args.out, "wb")
        write_pcap_header(st.pcap_file)
        st.pcap_file.flush()
        print(f"  {C.CY}[*] pcap -> {args.out} (DLT=105){C.RST}")
    else:
        print(f"  {C.DIM}[*] 未指定 -o, 不写 pcap{C.RST}")

    print(f"  {C.G}[*] 连接 {port} @ {args.baud}{C.RST}")
    print(f"  {C.DIM}[*] 输入 help 查看命令, Ctrl+C 退出{C.RST}")
    print()

    # 启动串口读取线程
    reader_thread = threading.Thread(target=serial_reader, daemon=True)
    reader_thread.start()

    # 初始化 readline
    init_readline()
    if readline:
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    # 主循环: 读用户输入 -> 发命令
    while st.running:
        try:
            line = input(f"{C.G}rftool>{C.RST} ")
            if not line.strip():
                continue
            if line.strip() in ("exit", "quit"):
                raise KeyboardInterrupt
            # 发命令到固件
            st.ser.write((line + "\n").encode())
            time.sleep(0.05)  # 给固件一点处理时间
        except KeyboardInterrupt:
            break
        except EOFError:
            break
        except Exception as e:
            print(f"  {C.R}[!] {e}{C.RST}")
            break

    cleanup()

if __name__ == "__main__":
    main()