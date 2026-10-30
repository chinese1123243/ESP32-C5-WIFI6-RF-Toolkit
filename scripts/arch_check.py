#!/usr/bin/env python3
"""架构红线检查: 把「达成标准」里能用计数表达的几条固化成闸门.

为什么是棘轮而不是达标判定: 现在的欠账(2592 行的 cli.c、318 处 META、8 条反向依赖)
没法一天还清, 但可以保证不再变差. 每还掉一笔就下调对应的基线数字, 闸门跟着收紧.

口径:
  strict  = 必须为 0, 现在就失败        (命令名重复)
  ratchet = 不得超过基线, 只许降不许升  (行数 / META 处数 / 反向依赖)
  report  = 只报告不拦                   (趋势类, 见 --verbose)

用法:
  python scripts/arch_check.py            退出码 0=通过, 1=有新增欠账
  python scripts/arch_check.py --verbose  额外打印当前各项数值
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main"

# 基线取自 2026-10-31 实测. 只许下调.
BASELINE = {
    "cli_c_lines": 2592,
    "meta_printf": 318,
    "reverse_deps": 8,
    "max_file_lines": 2592,
}

# 已知的反向依赖: 领域层直接 include 传输层的文件.
# 这张表只能变短, 不许变长. 修好一条就删一行并把 BASELINE 减 1.
KNOWN_REVERSE = {
    # 7 个领域文件直接 include 传输层的 ble_cli.h (为了 raw_out 往手机回传)
    "ble_adv.c", "cap.c", "event_bus.c", "hs.c",
    "phish.c", "wifi_attack.c", "zbsniff.c",
    # 文档点名的第 3 条: 传输层反向依赖门户的数据上传槽
    "ble_cli.c",
}

TRANSPORT_HEADERS = ("ble_cli.h", "http_server.h")

# 接口层与传输层自身不算领域层: cli.c 是命令适配器, http_server.c 是 REST 适配器,
# ble_cli.c 就是那条传输通道, main.c 是入口. 它们引用传输头文件是正常方向.
NON_DOMAIN = {"cli.c", "main.c", "ble_cli.c", "http_server.c"}


def count_lines(p):
    return len(p.read_text(encoding="utf-8", errors="replace").splitlines())


def check_command_names():
    """g_cmds[] 里的命令名不能重复. 重复会让 help 输出两个同名条目,
    且第一个匹配生效, 后一个成为死代码."""
    text = (MAIN / "cli.c").read_text(encoding="utf-8", errors="replace")
    names = re.findall(r'^\s*\{\s*"([a-z0-9_]+)"\s*,', text, re.M)
    dup = sorted({n for n in names if names.count(n) > 1})
    return names, dup


def check_reverse_deps():
    """领域层不应 include 传输层. 命中返回 {文件名: [头文件]}.
    另含文档点名的一条特例: ble_cli.c -> phish.h, 传输层反向依赖门户的数据上传槽."""
    hits = {}
    for p in sorted(MAIN.glob("*.c")):
        if p.name in NON_DOMAIN:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for h in TRANSPORT_HEADERS:
            if re.search(r'^#include\s+"%s"' % re.escape(h), text, re.M):
                hits.setdefault(p.name, set()).add(h)
    if re.search(r'^#include\s+"phish\.h"', (MAIN / "ble_cli.c").read_text(encoding="utf-8", errors="replace"), re.M):
        hits.setdefault("ble_cli.c", set()).add("phish.h")
    return hits


def main():
    verbose = "--verbose" in sys.argv
    fails = []

    # 1) 命令名唯一性: strict
    names, dup = check_command_names()
    if dup:
        fails.append("命令名重复: " + ", ".join(dup))
    print(f"命令数 {len(names)}, 重名 {len(dup)}")

    # 2) 反向依赖: ratchet
    hits = check_reverse_deps()
    new = set(hits) - KNOWN_REVERSE
    fixed = KNOWN_REVERSE - set(hits)
    if new:
        for f in sorted(new):
            fails.append(f"新增反向依赖: main/{f} -> {', '.join(sorted(hits[f]))}")
    if len(hits) > BASELINE["reverse_deps"]:
        fails.append(f"反向依赖 {len(hits)} 条, 超过基线 {BASELINE['reverse_deps']}")
    print(f"反向依赖 {len(hits)} 条 (基线 {BASELINE['reverse_deps']})"
          + (f", 新修好 {len(fixed)} 条" if fixed else ""))

    # 3) 文件行数: ratchet, 只盯最大的那个与 cli.c
    cli_lines = count_lines(MAIN / "cli.c")
    if cli_lines > BASELINE["cli_c_lines"]:
        fails.append(f"cli.c {cli_lines} 行, 超过基线 {BASELINE['cli_c_lines']}")

    sizes = {p.name: count_lines(p) for p in MAIN.glob("*.c")}
    big = max(sizes.items(), key=lambda kv: kv[1])
    if big[1] > BASELINE["max_file_lines"]:
        fails.append(f"最大文件 {big[0]} {big[1]} 行, 超过基线 {BASELINE['max_file_lines']}")
    print(f"cli.c {cli_lines} 行 (基线 {BASELINE['cli_c_lines']}), "
          f"最大 {big[0]} {big[1]} 行")

    # 4) META 输出处数: ratchet, 目标 <50
    meta = 0
    for p in MAIN.glob("*.c"):
        meta += len(re.findall(r'printf\("META', p.read_text(encoding="utf-8", errors="replace")))
    if meta > BASELINE["meta_printf"]:
        fails.append(f"printf(\"META \" {meta} 处, 超过基线 {BASELINE['meta_printf']}")
    print(f"printf(\"META \" {meta} 处 (基线 {BASELINE['meta_printf']}, 目标 <50)")

    if verbose:
        print("\n各文件行数前五:")
        for name, n in sorted(sizes.items(), key=lambda kv: -kv[1])[:5]:
            print(f"  {n:5d}  {name}")

    if fails:
        print("\n架构红线失守:")
        for f in fails:
            print("  FAIL " + f)
        return 1
    print("\n架构红线通过 (无新增欠账)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
