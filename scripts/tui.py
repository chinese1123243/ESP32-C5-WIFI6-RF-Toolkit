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
  - Ctrl+S 立即发送 stop (即使输入被顶掉也能停)
  - safe_print: 串口输出不覆盖用户正在输入的行

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

# Windows 键盘输入 (无缓冲, 支持 Ctrl+S 紧急停止)
try:
    import msvcrt
    HAVE_MSVCRT = True
except ImportError:
    HAVE_MSVCRT = False

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
        # TUI 扩展: export/dump 捕获
        self.capture_mode = None   # "json" / "csv" / "dump_aps" / ...
        self.capture_buf = []
        self.capture_save_path = None
        # HTTP 状态
        self.http_running = False
        self.http_ssid = ""
        self.http_ip = ""
        self.http_sta = 0
        # DB 计数缓存 (status 中解析)
        self.db_aps = 0
        self.db_clients = 0
        self.db_eapols = 0
        # 计数阈值
        self._dump_last_header = False

st = State()

# ==================== 安全打印 & 自定义输入 (解决输入被顶掉) ====================
# 全局输入缓冲 + 打印锁
_input_buf = ""          # 用户当前输入的内容
_input_prompt = ""       # 当前提示符 (含颜色)
_print_lock = threading.Lock()
_stop_pending = False    # Ctrl+S 触发的紧急停止标志

def _erase_current_line():
    """擦除当前光标所在行 (CR + 清行 + CR)"""
    # \r 回到行首, \033[2K 清除整行, 再 \r 回到行首
    sys.stdout.write("\r\033[2K\r")
    sys.stdout.flush()

def _redraw_input():
    """重新绘制当前输入行 (提示符 + 输入内容)"""
    if _input_prompt or _input_buf:
        sys.stdout.write(f"{_input_prompt}{_input_buf}")
        sys.stdout.flush()

def safe_print(*args, sep=" ", end="\n", flush=True):
    """线程安全的打印: 先擦除输入行, 打印内容, 再重绘输入行
    这样 serial_reader 线程的输出不会覆盖用户正在输入的内容
    """
    global _print_lock
    with _print_lock:
        # 1. 擦除当前输入行
        _erase_current_line()
        # 2. 打印实际内容
        text = sep.join(str(a) for a in args) + end
        sys.stdout.write(text)
        if flush:
            sys.stdout.flush()
        # 3. 重绘用户输入行 (如果有)
        _redraw_input()

def _send_stop_immediately():
    """立即向串口发送 stop 命令 (由 Ctrl+S 触发)"""
    if st.ser and st.running:
        try:
            st.ser.write(b"stop\n")
            st.ser.flush()
            safe_print(f"  {C.Y}{C.BOLD}[Ctrl+S] 已发送 stop{C.RST}")
        except Exception:
            pass

def custom_input(prompt):
    """自定义输入循环 (Windows 使用 msvcrt, 其他系统 fallback 到 input())
    特性:
      - 实时键盘响应, 不被串口输出阻塞
      - Ctrl+S 立即发送 stop (无需回车)
      - 支持退格, 回车提交, Ctrl+C 中断
      - ↑↓ 调用 readline 历史 (如果可用)
    """
    global _input_buf, _input_prompt, _stop_pending

    _input_prompt = prompt
    _input_buf = ""

    # Fallback: 非 Windows 或 msvcrt 不可用
    if not HAVE_MSVCRT:
        try:
            line = input(prompt)
            _input_prompt = ""
            _input_buf = ""
            return line
        finally:
            _input_prompt = ""
            _input_buf = ""

    # Windows msvcrt 自定义循环
    # 先画提示符
    with _print_lock:
        sys.stdout.write(prompt)
        sys.stdout.flush()

    history_idx = -1  # readline 历史索引, -1 = 当前输入

    while True:
        try:
            if not msvcrt.kbhit():
                # 检查是否有 Ctrl+S 待处理 (由其他线程设置)
                if _stop_pending:
                    _stop_pending = False
                    _send_stop_immediately()
                time.sleep(0.01)
                continue

            ch = msvcrt.getwch()

            # --- 特殊键处理 ---
            if ch == "\x13":  # Ctrl+S -> 紧急 stop
                _send_stop_immediately()
                continue

            if ch == "\x03":  # Ctrl+C -> 抛出中断
                raise KeyboardInterrupt

            if ch == "\r":  # 回车 -> 提交
                line = _input_buf
                sys.stdout.write("\n")
                sys.stdout.flush()
                # 加入 readline 历史
                if readline and line.strip():
                    readline.add_history(line)
                _input_buf = ""
                _input_prompt = ""
                return line

            if ch == "\x08" or ch == "\x7f":  # 退格 (Backspace / DEL)
                if _input_buf:
                    _input_buf = _input_buf[:-1]
                    with _print_lock:
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                continue

            if ch == "\t":  # Tab -> 简单补全
                prefix = _input_buf
                # 从 COMMANDS 中找匹配
                matches = [c for c in COMMANDS if c.startswith(prefix)]
                if len(matches) == 1:
                    # 唯一匹配: 自动补全
                    new_text = matches[0]
                    with _print_lock:
                        # 擦除当前输入
                        erase = "\b" * len(_input_buf) + " " * len(_input_buf) + "\b" * len(_input_buf)
                        sys.stdout.write(erase)
                        _input_buf = new_text
                        sys.stdout.write(_input_buf)
                        sys.stdout.flush()
                elif len(matches) > 1:
                    # 多个匹配: 打印列表
                    safe_print(f"  {C.DIM}补全: {' '.join(matches)}{C.RST}")
                continue

            # --- 方向键: msvcrt 方向键是 2 字节序列, 首字节 0xE0 或 0x00 ---
            if ch in ("\xe0", "\x00"):
                ch2 = msvcrt.getwch()
                if ch2 == "H":  # ↑ 上一条历史
                    if readline:
                        try:
                            nh = readline.get_current_history_length()
                            if nh == 0:
                                continue
                            if history_idx == -1:
                                # 第一次按 ↑, 保存当前输入到临时变量
                                globals()["_history_saved"] = _input_buf
                                history_idx = nh - 1
                            elif history_idx > 0:
                                history_idx -= 1
                            line = readline.get_history_item(history_idx + 1) or ""
                            with _print_lock:
                                erase = "\b" * len(_input_buf) + " " * len(_input_buf) + "\b" * len(_input_buf)
                                sys.stdout.write(erase)
                                _input_buf = line
                                sys.stdout.write(_input_buf)
                                sys.stdout.flush()
                        except Exception:
                            pass
                    continue
                elif ch2 == "P":  # ↓ 下一条历史
                    if readline:
                        try:
                            nh = readline.get_current_history_length()
                            if history_idx == -1:
                                continue
                            if history_idx < nh - 1:
                                history_idx += 1
                                line = readline.get_history_item(history_idx + 1) or ""
                            else:
                                # 回到用户之前输入的内容
                                line = globals().get("_history_saved", "")
                                history_idx = -1
                            with _print_lock:
                                erase = "\b" * len(_input_buf) + " " * len(_input_buf) + "\b" * len(_input_buf)
                                sys.stdout.write(erase)
                                _input_buf = line
                                sys.stdout.write(_input_buf)
                                sys.stdout.flush()
                        except Exception:
                            pass
                    continue
                elif ch2 in ("K", "M"):  # ← → 暂时不支持光标移动, 忽略
                    continue
                else:
                    continue  # 其他特殊键忽略

            # --- 可打印字符 ---
            if ord(ch) >= 32:
                _input_buf += ch
                with _print_lock:
                    sys.stdout.write(ch)
                    sys.stdout.flush()

        except KeyboardInterrupt:
            _input_buf = ""
            _input_prompt = ""
            raise
        except Exception:
            # 任何异常都清空状态
            _input_buf = ""
            _input_prompt = ""
            raise

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
                        safe_print(format_pkt(pkt))
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
                        elif parts[i] == "aps":
                            try: st.db_aps = int(parts[i+1])
                            except ValueError: pass
                        elif parts[i] == "clients":
                            try: st.db_clients = int(parts[i+1])
                            except ValueError: pass
                        elif parts[i] == "eapols":
                            try: st.db_eapols = int(parts[i+1])
                            except ValueError: pass
                    # HTTP 状态解析
                    if len(parts) >= 2 and parts[0] == "HTTP":
                        act2 = parts[1] if len(parts) > 1 else ""
                        if act2 == "START":
                            st.http_running = True
                            for i in range(2, len(parts)-1, 2):
                                if parts[i] == "ssid": st.http_ssid = parts[i+1]
                                elif parts[i] == "ip": st.http_ip = parts[i+1]
                        elif act2 == "STOP":
                            st.http_running = False
                            st.http_ssid = ""
                            st.http_ip = ""
                    safe_print(f"  {meta_col}[meta] {line_s[5:]}{C.RST}")
                    # HTTP 启动提示
                    if line_s.startswith("META,HTTP,START"):
                        safe_print(f"  {C.G}{C.BOLD}    -> 连接 Wi-Fi: {st.http_ssid} / 密码: rftool1234{C.RST}")
                        safe_print(f"  {C.G}{C.BOLD}    -> 浏览器访问 http://{st.http_ip}/{C.RST}")
                    maybe_print_status()
                elif "========================================" in line_s:
                    safe_print(f"  {C.M}{line_s}{C.RST}")
                elif "ESP32-C5" in line_s or "Authorized" in line_s or "ILLEGAL" in line_s:
                    safe_print(f"  {C.M}{line_s}{C.RST}")
                elif line_s.strip() == "Commands:":
                    # help 命令输出: 中英双语
                    safe_print(f"  {C.BOLD}命令列表 / Commands:{C.RST}")
                elif line_s.strip().startswith("help ") and "Show this help" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 显示帮助{C.RST}")
                elif line_s.strip().startswith("status ") and "Show" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 显示状态和计数器{C.RST}")
                elif line_s.strip().startswith("sniff ") and "Start" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 启动 Wi-Fi 混杂模式嗅探{C.RST}")
                elif line_s.strip().startswith("stop ") and "Stop" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 停止当前嗅探/注入{C.RST}")
                elif line_s.strip().startswith("deauth ") and "Deauth" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 构造 deauth 帧注入 (仅限授权使用){C.RST}")
                elif line_s.strip().startswith("beaconflood ") and "Beacon" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 伪造 beacon 洪水 (仅限授权使用){C.RST}")
                elif line_s.strip().startswith("probeflood ") and "Probe" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# probe request 洪水{C.RST}")
                elif line_s.strip().startswith("http ") and "HTTP" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# HTTP REST API 远程控制面板{C.RST}")
                elif line_s.strip().startswith("export ") and "Export" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 导出数据 (TUI 自动保存本地文件){C.RST}")
                elif line_s.strip().startswith("dump ") and "Dump" in line_s:
                    safe_print(f"  {line_s}  {C.DIM}# 显示数据库表格 (TUI 彩色格式化){C.RST}")
                elif line_s.strip().startswith("Usage:"):
                    safe_print(f"  {C.DIM}{line_s}{C.RST}")
                elif line_s.strip().startswith("Type '<cmd>"):
                    safe_print(f"  {C.DIM}{line_s}  # 输入 '<cmd> --help' 查看详细参数{C.RST}")
                # ===== export/dump 捕获 =====
                # export json 开始: 以 { 开头 (非前面几种格式之一)
                elif st.capture_mode == "json" and (line_s.startswith("{") or st.capture_buf):
                    with st.lock:
                        st.capture_buf.append(line_s)
                    # 简易结束检测: 一行含 ]}
                    if line_s.rstrip().endswith("]}") or line_s.rstrip() == "}":
                        _finalize_capture()
                elif st.capture_mode == "csv" and ("," in line_s or st.capture_buf):
                    with st.lock:
                        st.capture_buf.append(line_s)
                    # csv 无明确结束符; 我们在用户 input 循环里检测到下一个命令前手动结束.
                    # 这里如果收到 rftool> 提示符就结束 (已经在开头 strip 处理了, 所以不会触发)
                # dump 表格捕获: AP,xx / CLIENT,xx / EAPOL,xx
                elif line_s.startswith("AP,") or line_s.startswith("CLIENT,") or line_s.startswith("EAPOL,") or                      (st.capture_mode and st.capture_mode.startswith("dump_") and line_s.startswith("type,")):
                    if line_s.startswith("type,") and not st.capture_buf:
                        # 打印表头
                        _print_dump_header(line_s)
                        st._dump_last_header = True
                    else:
                        _print_dump_row(line_s)
                    with st.lock:
                        st.capture_buf.append(line_s)
                elif line_s.strip():
                    # 其他输出 (启动日志等)
                    safe_print(f"  {C.DIM}{line_s}{C.RST}")
        except (serial.SerialException, OSError) as e:
            if st.running:
                safe_print(f"  {C.R}[!] 串口异常: {e}, 重连...{C.RST}")
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
                        safe_print(f"  {C.G}[+] 串口重连成功{C.RST}")
                        break
                    except:
                        time.sleep(0.5)
        except Exception as e:
            if st.running:
                safe_print(f"  {C.R}[!] reader error: {e}{C.RST}")

# ==================== Export/Dump 辅助函数 ====================
def _finalize_capture():
    """结束 capture, 保存文件"""
    with st.lock:
        mode = st.capture_mode
        data = list(st.capture_buf)
        save = st.capture_save_path
        st.capture_buf = []
        st.capture_mode = None
        st.capture_save_path = None
    if not data:
        return
    # 生成本地文件名
    if save is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if mode == "json" else ("csv" if mode == "csv" else "txt")
        save = f"rftool_{mode}_{ts}.{ext}"
    try:
        with open(save, "w", encoding="utf-8") as f:
            f.write(chr(10).join(data) + chr(10))
        nbytes = os.path.getsize(save)
        safe_print(f"  {C.G}{C.BOLD}[export] 已保存 -> {save} ({nbytes} bytes, {len(data)} 行){C.RST}")
    except Exception as e:
        safe_print(f"  {C.R}[export] 保存失败: {e}{C.RST}")

def _print_dump_header(line_s):
    """dump 表格表头 (type,bssid_or_mac,ssid,channel,rssi,...)"""
    cols = [s.strip() for s in line_s.split(",")]
    col_map = {c: i for i, c in enumerate(cols)}
    with st.lock:
        st._dump_cols = cols
        st._dump_colmap = col_map
    # 选择显示列
    show = ["type", "bssid_or_mac", "ssid", "channel", "rssi", "encryption", "vendor", "pmf", "pkt_count"]
    show_cols = [c for c in show if c in col_map]
    widths = []
    header = "  "
    for cname in show_cols:
        w = max(8, len(cname) + 2)
        widths.append(w)
        header += f"{cname.upper():<{w}}"
    safe_print(f"  {C.BOLD}{'─'*(sum(widths)+6)}{C.RST}")
    safe_print(f"{C.BOLD}{header}{C.RST}")
    safe_print(f"  {C.BOLD}{'─'*(sum(widths)+6)}{C.RST}")
    with st.lock:
        st._dump_showcols = show_cols
        st._dump_widths = widths

def _print_dump_row(line_s):
    """打印 dump 表格一行"""
    # 按逗号分隔 (注意 ssid 可能有引号)
    parts = []
    i = 0
    s = line_s
    while i < len(s):
        if s[i] == '"':
            j = s.find('"', i+1)
            if j < 0:
                parts.append(s[i+1:])
                break
            parts.append(s[i+1:j])
            i = j + 2
            if i < len(s) and s[i-1] == ',':
                pass
        else:
            j = s.find(',', i)
            if j < 0:
                parts.append(s[i:])
                break
            parts.append(s[i:j])
            i = j + 1
    try:
        with st.lock:
            show_cols = st._dump_showcols
            widths    = st._dump_widths
            col_map   = st._dump_colmap
    except AttributeError:
        # 无表头, 直接打印
        safe_print(f"  {C.DIM}{line_s}{C.RST}")
        return
    out = "  "
    for idx, cname in enumerate(show_cols):
        w = widths[idx]
        try: val = parts[col_map[cname]] if col_map[cname] < len(parts) else "-"
        except (KeyError, IndexError): val = "-"
        # 颜色
        col = C.W
        if cname == "rssi":
            try:
                rv = int(val)
                col = C.G if rv > -60 else (C.Y if rv > -75 else C.R)
            except: pass
        elif cname == "encryption":
            if   val == "OPEN": col = C.G
            elif val == "WEP":  col = C.R
            elif val.startswith("WPA"): col = C.Y
        elif cname == "type":
            if   val == "AP":     col = C.CY
            elif val == "CLIENT": col = C.M
            elif val == "EAPOL":  col = C.R + C.BOLD
        out += f"{col}{val:<{w}}{C.RST}"
    safe_print(out)

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
        safe_print(f"  {C.DIM}--- {state_col}{cur_state}{C.RST}{C.DIM} ch={st.fw_channel} pkts={st.total_pkts} ---{C.RST}")
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
COMMANDS = ["help", "status", "sniff", "stop", "deauth", "beaconflood", "probeflood", "export", "dump", "http", "exit", "quit"]

def completer(text, state):
    matches = [c for c in COMMANDS if c.startswith(text)]
    if state < len(matches):
        return matches[state]
    return None

# ==================== 主循环 ====================
def cleanup():
    global _input_buf, _input_prompt
    st.running = False
    time.sleep(0.2)
    _input_buf = ""
    _input_prompt = ""
    print(f"\n\n  {C.BOLD}========== 统计 =========={C.RST}")
    print(f"  总帧数:      {C.G}{st.total_pkts}{C.RST}")
    print(f"  注入帧数:    {C.R}{st.total_inject}{C.RST}")
    print(f"  DB-APs:      {C.CY}{st.db_aps}{C.RST}")
    print(f"  DB-Clients:  {C.CY}{st.db_clients}{C.RST}")
    print(f"  DB-EAPOLs:   {C.CY}{st.db_eapols}{C.RST}")
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
    if HAVE_MSVCRT:
        print(f"  {C.Y}{C.BOLD}[*] Windows 模式: 输入 stop 不被顶掉, Ctrl+S 立即发送 stop{C.RST}")
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
            line = custom_input(f"{C.G}rftool>{C.RST} ")
            if not line.strip():
                continue
            if line.strip() in ("exit", "quit"):
                raise KeyboardInterrupt
            # 如果 csv capture 模式还在进行, 这里结束它
            if st.capture_mode == "csv" and st.capture_buf:
                _finalize_capture()
            # 发命令到固件
            st.ser.write((line + "\n").encode())
            time.sleep(0.05)  # 给固件一点处理时间
        except KeyboardInterrupt:
            break
        except EOFError:
            break
        except Exception as e:
            safe_print(f"  {C.R}[!] {e}{C.RST}")
            break

    cleanup()

if __name__ == "__main__":
    main()
