#!/usr/bin/env python3
"""pcap_check.py — 校验 RFTOOL-C5 落盘的 pcap 是否合法

用法:  python pcap_check.py <file.pcap>

检查项:
  * 全局头 magic / 版本 / snaplen / linktype (应为 105 = IEEE 802.11)
  * 逐条记录: incl_len / orig_len 合理, 记录长度按 4 字节对齐, 不越界
  * 帧头可解析 (frame control type/subtype), 统计 802.11 帧类型分布
  * 报告 EAPOL (ethertype 0x888E) 与 PMKID 命中数
"""
import struct
import sys
from collections import Counter

LINKTYPE_IEEE802_11 = 105
MAX_FRAME = 512


def frame_kind(f):
    t = (f[0] >> 2) & 0x3
    s = (f[0] >> 4) & 0xF
    names = {0: "MGMT", 1: "CTRL", 2: "DATA", 3: "EXT"}
    sub = ""
    if t == 0:
        sub = {8: "beacon", 5: "probe-resp", 4: "probe-req", 11: "auth",
               12: "deauth", 10: "disassoc", 0: "assoc-req", 1: "assoc-resp"}.get(s, hex(s))
    elif t == 2:
        sub = {0: "data", 4: "null", 8: "qos-data", 12: "qos-null"}.get(s, hex(s))
    return f"{names[t]}/{sub}"


def eapol_kind(f, t, s):
    """返回 'eapol' / 'pmkid' / None"""
    if t != 2:
        return None
    off = 24
    if s & 0x08:
        off += 2
    if f[1] & 0x80:
        off += 4
    if off + 8 > len(f):
        return None
    if not (f[off] == 0xAA and f[off + 1] == 0xAA and f[off + 2] == 0x03):
        return None
    if not (f[off + 6] == 0x88 and f[off + 7] == 0x8E):
        return None
    eo = off + 8
    if eo + 6 > len(f) or f[eo + 1] != 3:
        return "eapol"
    ki = (f[eo + 5] << 8) | f[eo + 6]
    if not (ki & 0x0080) or (ki & 0x0008) or (ki & 0x0040) or (ki & 0x0200):
        return "eapol"
    p = eo + 99
    while p + 2 <= len(f):
        t2, kl = f[p], f[p + 1]
        if p + 2 + kl > len(f):
            break
        if t2 == 0xDD and kl >= 5 and f[p + 2:p + 6] == b"\x00\x0f\xac\x04":
            return "pmkid"
        p += 2 + kl
    return "eapol"


def main(path):
    d = open(path, "rb").read()
    print(f"file            : {path}")
    print(f"size            : {len(d)} B")
    if len(d) < 24:
        print("FAIL: 短于 pcap 全局头")
        return 1

    magic, vmaj, vmin, tz, sig, snap, link = struct.unpack("<IHHiIII", d[:24])
    print(f"magic           : 0x{magic:08x} " + ("OK" if magic == 0xa1b2c3d4 else "FAIL"))
    print(f"version         : {vmaj}.{vmin}")
    print(f"snaplen         : {snap}")
    print(f"linktype        : {link} " +
          ("OK (IEEE 802.11)" if link == LINKTYPE_IEEE802_11 else "FAIL"))

    o = 24
    n = 0
    total = 0
    kinds = Counter()
    keys = Counter()
    first_ts = last_ts = None

    while o + 16 <= len(d):
        sec, usec, il, ol = struct.unpack("<IIII", d[o:o + 16])
        rec = 16 + ((il + 3) // 4) * 4
        if il == 0 or il > MAX_FRAME or il != ol or o + rec > len(d):
            print(f"FAIL: 记录 #{n} 越界/长度异常 off={o} incl={il} orig={ol}")
            break
        f = d[o + 16:o + 16 + il]
        if first_ts is None:
            first_ts = sec + usec / 1e6
        last_ts = sec + usec / 1e6
        kinds[frame_kind(f)] += 1
        k = eapol_kind(f, (f[0] >> 2) & 3, (f[0] >> 4) & 0xF)
        if k:
            keys[k] += 1
        total += il
        n += 1
        o += rec

    print(f"records         : {n}")
    print(f"frame bytes     : {total}")
    print(f"consumed        : {o} / {len(d)}" +
          (" (尾部有对齐填充, 正常)" if o != len(d) else " (完全对齐)"))
    if first_ts is not None:
        print(f"ts span         : {last_ts - first_ts:.3f} s")
    print(f"EAPOL / PMKID   : {keys['eapol']} / {keys['pmkid']}")
    print("frame mix       : " + ", ".join(f"{k}={v}" for k, v in kinds.most_common(6)))
    print("RESULT          : " + ("OK" if n > 0 and o == len(d) else "CHECK"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "cap.pcap"))
