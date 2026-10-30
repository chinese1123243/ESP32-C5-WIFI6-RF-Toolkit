#!/usr/bin/env python3
"""
Batch 4 板级自检 (C-2/C-3/C-4/B-2/B-5/D-5/D-2 + OTA)
用法: python scripts/selftest_b4.py COM4
依赖: pyserial (pip install pyserial)
"""
import sys, time, serial
import re as _re
import pathlib as _pl

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
BAUD = 115200

# 版本号从 main/version.h 读, 硬编码会在每次升版后假失败 (曾停在 2.0.0 对不上 2.4.1)
_vh = _pl.Path(__file__).resolve().parent.parent / "main" / "version.h"
_m = _re.search(r'RFTOOL_VERSION\s+"([^"]+)"', _vh.read_text(encoding="utf-8"))
FW_VER = _m.group(1) if _m else ""

CMDS = [
    "version",
    "version --json",
    "status --json",
    "health --json",
    "ota status",
    "scenario status",
    "pmkid status",
    "locate status",
    "cap info",
    "events 3",
    "help",
]

def read_for(ser, secs):
    buf = b""
    end = time.time() + secs
    while time.time() < end:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk
    return buf.decode("utf-8", "replace")

def main():
    print(f"[*] open {PORT} @ {BAUD}")
    ser = serial.Serial(PORT, BAUD, timeout=0.2)
    time.sleep(0.3)
    banner = read_for(ser, 4.0)
    print("[banner]")
    print(banner[-1500:])

    out = {}
    for c in CMDS:
        ser.reset_input_buffer()
        ser.write((c + "\r\n").encode())
        ser.flush()
        out[c] = read_for(ser, 1.6)
        print(f"\n[>] {c}")
        print(out[c].strip()[:1200])

    ser.close()

    checks = [
        ("firmware " + FW_VER, FW_VER in out["version"]),
        ("version json",    '"version":"%s"' % FW_VER in out["version --json"]),
        ("status json",     '"state"' in out["status --json"] and '"locate"' in out["status --json"]),
        ("health json",     '"cap_segs"' in out["health --json"] and '"events"' in out["health --json"]),
        ("ota status",      "META,OTA,STATUS" in out["ota status"]),
        ("scenario status", "META,SCENARIO,STATUS" in out["scenario status"]),
        ("pmkid status",    "META,PMKID,STATUS" in out["pmkid status"]),
        ("locate status",   "META,LOCATE,STATUS" in out["locate status"]),
        ("cap info + seg",  "META,CAP,INFO" in out["cap info"] and ",seg," in out["cap info"]),
        ("events json",     '"events"' in out["events 3"]),
        ("help lists new",  all(k in out["help"] for k in ("scenario", "locate", "pmkid", "events"))),
        ("boot ok",         "rftool>" in (banner + out["version"])),
    ]

    print("\n==== SUMMARY ====")
    ok = 0
    for name, passed in checks:
        print(("PASS  " if passed else "FAIL  ") + name)
        ok += 1 if passed else 0
    print(f"{ok}/{len(checks)} passed")
    return 0 if ok == len(checks) else 1

if __name__ == "__main__":
    sys.exit(main())
