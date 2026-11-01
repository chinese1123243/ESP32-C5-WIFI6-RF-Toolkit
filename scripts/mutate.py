"""变异测试: 故意把每个修复退回去, 确认主机测试会红.

"能过的测试不等于有效的测试"——一条断言只有在对应缺陷存在时失败, 才证明它
真的在检查那件事. 这里逐个退回关键实现, 期望测试失败, 然后还原.

用法: python scripts/mutate.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MUTATIONS = [
    ("CSI: 动作态不清 CUSUM (退出要等几十个样本)",
     "main/csi_det.c",
     "    if (d->motion) d->cusum = 0.0f;",
     "    /* mutated */"),
    ("CSI: 动作期不再冻结 mad (z 分数被自己稀释)",
     "main/csi_det.c",
     "    if (!d->motion) {\n        d->mad += MAD_RATE * (fabsf(dev) - d->mad);\n        if (d->mad < MAD_FLOOR) d->mad = MAD_FLOOR;\n    }",
     "    d->mad += MAD_RATE * (fabsf(dev) - d->mad);\n    if (d->mad < MAD_FLOOR) d->mad = MAD_FLOOR;"),
    ("CSI: 基线按偏差正负分快慢 (静止场景误报)",
     "main/csi_det.c",
     "    d->base += (d->motion ? BASE_UP : BASE_DOWN) * dev;",
     "    d->base += (dev < 0.0f ? BASE_DOWN : BASE_UP) * dev;"),
    ("SACS: 剩余量不夹上界 (零曝光时除出 inf)",
     "main/chan_sched.c",
     "    if (s > 0.999f) s = 0.999f;",
     "    /* mutated */"),
    ("CSI: 一致率门控被摘掉 (窄带干扰直接报成动作)",
     "main/csi_det.c",
     "    return m && coh >= CSI_DET_COH_MIN;",
     "    return m;"),
    ("CSI: 全零残差被算成同号 (静止帧一致率变 1.0)",
     "main/csi_det.c",
     "        if (p > 0.0f) same++;",
     "        if (p >= 0.0f) same++;"),
    ("locate: 截尾比例取 0 (退化成算术均值)",
     "main/locate_est.c",
     "    int cut = n / 5;",
     "    int cut = 0;"),
]


def run_tests():
    r = subprocess.run(["bash", "tests/host/run.sh"], cwd=ROOT,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    rc, out = run_tests()
    if rc != 0:
        print("基线就没过, 先修测试:\n", out[-800:])
        return 2

    bad = 0
    for name, rel, old, new in MUTATIONS:
        p = ROOT / rel
        src = p.read_text(encoding="utf-8", newline="")
        crlf = "\r\n" in src
        o = old.replace("\n", "\r\n") if crlf else old
        n = new.replace("\n", "\r\n") if crlf else new
        if o not in src:
            print(f"SKIP  {name}  (找不到片段)")
            bad += 1
            continue
        backup = src
        p.write_text(src.replace(o, n, 1), encoding="utf-8", newline="")
        try:
            rc, out = run_tests()
        finally:
            p.write_text(backup, encoding="utf-8", newline="")
        if rc == 0:
            print(f"BAD   {name}  —— 缺陷退回去了测试居然还是绿的")
            bad += 1
        else:
            fails = [l for l in out.splitlines() if l.startswith("FAIL")]
            print(f"OK    {name}  -> {fails[0][:80] if fails else 'rc=%d' % rc}")

    rc, _ = run_tests()
    print(f"\n还原后基线: {'绿' if rc == 0 else '红!'}")
    print(f"变异体 {len(MUTATIONS) - bad}/{len(MUTATIONS)} 被测试抓到")
    return 0 if bad == 0 and rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
