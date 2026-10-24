#!/usr/bin/env python3
"""校验设备侧 pcap: 全局头 linktype + 每条记录的 radiotap 字段.

数据来源是 `cap hex <off> <len>` 的十六进制回显, 不依赖手机端.
用法:
    python scripts/pcap_check.py --port COM4 --len 2048
    python scripts/pcap_check.py --file dump.hex
"""
import argparse
import re
import struct
import sys

LINKTYPE_RADIOTAP = 127
PCAP_MAGIC = 0xA1B2C3D4


def read_hex_from_port(port, baud, off, length):
    import serial
    s = serial.Serial(port, baud, timeout=0.05)
    buf = ""
    s.write(b"cap hex %d %d\r\n" % (off, length))
    s.flush()
    deadline = __import__("time").time() + 6
    while __import__("time").time() < deadline:
        c = s.read(4096)
        if c:
            buf += c.decode("utf-8", "replace")
            if "META,CAP,HEX" in buf:
                break
    s.close()
    return buf


def extract_hex(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("META,"):
            continue
        if re.fullmatch(r"[0-9a-f]+", line) and len(line) % 2 == 0:
            out.append(line)
    return bytes.fromhex("".join(out))


def parse(data):
    if len(data) < 24:
        raise SystemExit("数据不足 24 字节, 拿不到 pcap 全局头")
    magic, vmaj, vmin, _, _, snaplen, link = struct.unpack("<IHHiIII", data[:24])
    if magic != PCAP_MAGIC:
        raise SystemExit("magic 不对: 0x%08x" % magic)
    print("pcap: v%d.%d snaplen=%d linktype=%d %s"
          % (vmaj, vmin, snaplen, link,
             "OK(radiotap)" if link == LINKTYPE_RADIOTAP else "!! 不是 radiotap"))

    off = 24
    n = 0
    rows = []
    while off + 16 <= len(data):
        ts_s, ts_us, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        if incl == 0 or off + 16 + incl > len(data):
            break
        rec = data[off + 16:off + 16 + incl]
        rt_len = struct.unpack("<H", rec[2:4])[0]
        present = struct.unpack("<I", rec[4:8])[0]
        if rt_len < 8 or rt_len > incl:
            print("!! 记录 %d radiotap 长度异常: %d (incl %d)" % (n, rt_len, incl))
            break
        # 本工程只写 flags/rate/channel/signal/noise 这一种组合
        if present & 0x6E != 0x6E:
            print("!! 记录 %d present=0x%08x 缺字段" % (n, present))
        o = 8
        flags = rec[o]; o += 1
        rate = rec[o]; o += 1
        freq, cflags = struct.unpack("<HH", rec[o:o + 4]); o += 4
        sig = struct.unpack("<b", rec[o:o + 1])[0]; o += 1
        noise = struct.unpack("<b", rec[o:o + 1])[0]; o += 1
        body = rec[rt_len:]
        ftype = (body[0] >> 2) & 3 if len(body) >= 2 else -1
        fsub = (body[0] >> 4) & 0xF if len(body) >= 2 else -1
        ssid = ""
        if ftype == 0 and fsub in (8, 5) and len(body) > 36:
            ie = body[36:]
            i = 0
            while i + 2 <= len(ie):
                eid, elen = ie[i], ie[i + 1]
                if i + 2 + elen > len(ie):
                    break
                if eid == 0:
                    ssid = ie[i + 2:i + 2 + elen].decode("utf-8", "replace")
                    break
                i += 2 + elen
        rows.append((n, ts_s, ts_us, incl, rt_len, freq, cflags, rate, sig, noise,
                     ftype, fsub, ssid, len(body)))
        off += 16 + ((incl + 3) & ~3)
        n += 1

    print("记录数 %d" % n)
    print("%3s %8s %7s %6s %6s %4s %5s %5s %-14s %s"
          % ("#", "ts", "incl", "freq", "rtlen", "rate", "sig", "noise", "type/sub", "ssid"))
    for r in rows[:12]:
        (i, ts_s, ts_us, incl, rt_len, freq, cflags, rate, sig, noise,
         ftype, fsub, ssid, blen) = r
        kind = {0: "mgmt", 1: "ctrl", 2: "data"}.get(ftype, "?")
        print("%3d %8d %7d %6d %6d %4d %5d %5d %-14s %s"
              % (i, ts_s, incl, freq, rt_len, rate, sig, noise,
                 "%s/%d" % (kind, fsub), ssid))
    if rows:
        freqs = sorted({r[5] for r in rows})
        sigs = [r[8] for r in rows]
        print("信道频率: %s   RSSI 范围: %d..%d dBm" % (freqs, min(sigs), max(sigs)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM4")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--off", type=int, default=0)
    ap.add_argument("--len", type=int, default=2048)
    ap.add_argument("--file", default="", help="从已保存的 hex 文本解析")
    args = ap.parse_args()

    if args.file:
        text = open(args.file, encoding="utf-8", errors="replace").read()
    else:
        text = read_hex_from_port(args.port, args.baud, args.off, args.len)
    data = extract_hex(text)
    if not data:
        raise SystemExit("没有拿到十六进制数据; 原文尾部: %r" % text[-200:])
    parse(data)


if __name__ == "__main__":
    main()
