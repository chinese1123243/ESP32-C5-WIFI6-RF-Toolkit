"""握手捕获率: 信道轮转 × 检测触发延长.

问题
----
4-way 握手七帧 (探测/认证/关联 + M1..M4) 总跨度只有 30~60ms, 而 78 条信道按
300ms 驻留轮一遍要 25 秒. 单次握手被完整捕获的概率 = P(某一个驻留窗覆盖整段),
量级在 1% 上下, 也就是"挂一小时抓到几次". 这个量在真机上凑不出样本 (一次 auto
45 秒, 现场握手又是随机到达), 只能离线算.

模型
----
· 客户端上线事件按泊松到达, 速率与该信道的客户端数成正比 (握手只发生在有客户
  端的信道上, 这条是全部收益的来源)
· 上线序列: 探测请求 → 认证 → 关联请求 → M1 → M2 → M3 → M4.
  M1 与 M2 相隔 1~3ms (STA 立即回), M2 与 M3 相隔 3~30ms (AP 算 PTK),
  M3 与 M4 相隔 1~3ms. 整段跨度 T 由这些随机量决定.
· 捕获判据分三档:
    full    M1..M4 都要            (最稳, 22000 双保险)
    m2m3    只要 M2 与 M3          (现场最常见, 也是实际能破的那种)
    pmkid   只要 M1 (带 PMKID)     (单帧即可, 但要看 AP 支不支持)
  三档都要求所需帧落在同一个驻留窗内: 跨窗就是漏.
· 触发延长: 驻留窗内看到任意一帧, 就地延长 X ms (上限 cap), 再从延长后的窗
  重新判捕获.

为什么关心"触发延长"
--------------------
直觉是"驻留越长越容易抓全". 但捕获率 ∝ D/R = D/(N(D+s)), 驻留翻倍只让轮转
慢一倍, 收益互相抵消. 真正决定捕获率的是 R (轮一遍多久), 也就是 N 和 D 的乘积.

触发延长把这个关系解耦: 短驻留 + 一旦看到帧就延长, 既保住轮转速度 (R 小),
又保住完整捕获 (窗口够长). 下面几组数就是量这个解耦到底值多少.
"""

import argparse
import math
import random
import statistics

# 与固件 s_channels_* 一致
CH_2G = list(range(1, 14))
CH_5G = [36, 40, 44, 48, 52, 56, 60, 64,
         100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
         149, 153, 157, 161, 165, 169, 173, 177]
CHANNELS = CH_2G + CH_5G

SWITCH_MS = 20.0


class Burst:
    """一次"客户端上线"产生的帧序列 (毫秒, 相对起始时刻)."""

    __slots__ = ("t", "probe", "auth", "assoc", "m1", "m2", "m3", "m4", "req_span")

    def __init__(self, t, rng):
        self.t = t
        self.probe = t
        self.auth = t + rng.uniform(1.0, 4.0)
        self.assoc = self.auth + rng.uniform(1.0, 4.0)
        # 关联完成到 M1: AP 发 EAPOL-Key, 通常紧接着
        self.m1 = self.assoc + rng.uniform(1.0, 6.0)
        self.m2 = self.m1 + rng.uniform(1.0, 3.0)
        self.m3 = self.m2 + rng.uniform(3.0, 30.0)     # AP 算 PTK 的时间是主项
        self.m4 = self.m3 + rng.uniform(1.0, 3.0)
        self.req_span = self.m4 - t

    def span(self, kind):
        if kind == "full":
            return self.m4 - self.m1
        if kind == "m2m3":
            return self.m3 - self.m2
        return 0.0


def make_bursts(rng, ch_clients, horizon, per_hour=30.0):
    """按信道客户端数铺到达事件.

    默认 30 次/时: 16 个客户端在场, 平均每台每小时重连约 2 次 (休眠唤醒、
    漫游、AP 踢人). 这个量级可以从"一天抓到的握手数"反推, 不是拍的.
    lam 单位是 1/ms, 所以 per_hour/3600/1000.
    """
    out = {}
    tot_cli = sum(ch_clients.values()) or 1
    for ch, n_cli in ch_clients.items():
        if n_cli <= 0:
            continue
        lam = per_hour / 3600.0 / 1000.0 * n_cli / tot_cli * tot_cli
        lam = per_hour / 3600.0 / 1000.0 * (n_cli / tot_cli) * tot_cli
        t = rng.expovariate(lam)
        while t < horizon:
            out.setdefault(ch, []).append(Burst(t, rng))
            t += rng.expovariate(lam)
    return out


def captured(burst, a, b, kind):
    """驻留窗 [a,b] 是否能抓到 kind 要求的那组帧."""
    if kind == "full":
        return a <= burst.m1 and burst.m4 <= b
    if kind == "m2m3":
        return a <= burst.m2 and burst.m3 <= b
    return a <= burst.m1 <= b


def any_frame_in(burst, a, b):
    """窗内是否看到这一串里的任意一帧 (触发延长的判据)."""
    for x in (burst.probe, burst.auth, burst.assoc, burst.m1, burst.m2, burst.m3, burst.m4):
        if a <= x <= b:
            return True
    return False


def run_policy(bursts, order, dwell, horizon, kind="full",
               ext_ms=0.0, ext_cap=0.0):
    """按 order 轮转, 返回 (捕获数, 总帧数, 在信道上花的时间占比).

    延长规则: 一次访问内看到任意帧就再驻留 ext_ms, 累计不超过 ext_cap.

    每条信道维护一个单调指针: 访问时刻递增, 早于窗口起点 200ms 的事件再也
    不可能被覆盖, 直接跳过. 这样总代价是 O(访问次数 + 事件数).
    """
    hits = 0
    visited_ms = 0.0
    total = sum(len(v) for v in bursts.values())
    for v in bursts.values():
        v.sort(key=lambda x: x.t)
    ptr = {ch: 0 for ch in bursts}
    t = 0.0
    idx = 0
    n = len(order)
    while t < horizon:
        ch = order[idx % n]
        idx += 1
        a = t
        b = t + dwell
        visited_ms += dwell
        t = b + SWITCH_MS

        here = bursts.get(ch)
        if not here:
            continue

        i = ptr[ch]
        while i < len(here) and here[i].t < a - 200.0:
            i += 1
        ptr[ch] = i

        # 窗口内是否触发了延长
        ext = 0.0
        if ext_ms > 0:
            j = i
            while j < len(here) and here[j].t <= b:
                if any_frame_in(here[j], a, b):
                    ext = min(ext_ms, ext_cap)
                    break
                j += 1
            b += ext
            t += ext

        # 判捕获 (延长后的窗)
        j = i
        while j < len(here) and here[j].t <= b:
            if captured(here[j], a, b, kind):
                hits += 1
            j += 1
    return hits, total, visited_ms / horizon


def policy_order(aps_chs, n_all=len(CHANNELS)):
    """两种信道集合: 全部 78 条, 或只轮有 AP 的那几条."""
    return {
        "全扫 78": list(CHANNELS),
        "有货信道": list(aps_chs),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--horizon", type=float, default=600_000, help="仿真时长 ms")
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--dwells", default="60,100,200,300,600")
    ap.add_argument("--per-hour", type=float, default=30.0,
                    help="握手总到达率, 次/小时")
    args = ap.parse_args()

    # 现场: 23 台 AP 落在 10 条信道上, 其中 4 条上有客户端
    ap_chs = [1, 6, 11, 36, 40, 44, 100, 149, 157, 161]
    ch_clients = {1: 3, 6: 5, 11: 2, 36: 4, 40: 1, 44: 0,
                  100: 0, 149: 1, 157: 0, 161: 0}

    dwells = [float(x) for x in args.dwells.split(",")]
    orders = policy_order(ap_chs)

    print(f"视界 {args.horizon/1000:.0f}s, {args.trials} 次重复, "
          f"{len(CHANNELS)} 条信道 / 有货 {len(ap_chs)} 条, "
          f"客户端 {sum(ch_clients.values())} 台分布在 "
          f"{sum(1 for v in ch_clients.values() if v)} 条信道")
    print(f"握手到达率 {args.per_hour:.0f} 次/时 (16 个客户端在场)")
    print()

    def ttfc(rate, lam_per_s):
        """首捕期望 (秒). 到达是泊松, 每次独立以 rate 概率被捕获,
        首捕时间服从指数分布, 均值 1/(lam*rate)."""
        return 1.0 / (lam_per_s * rate) if rate > 0 else float("inf")

    def fmt_t(sec):
        if sec == float("inf"):
            return "永不"
        if sec < 90:
            return f"{sec:.0f} 秒"
        if sec < 5400:
            return f"{sec/60:.0f} 分"
        return f"{sec/3600:.1f} 时"

    for kind, label in (("full", "全 4 帧 (M1..M4)"), ("m2m3", "只要 M2+M3")):
        print(f"== {label} ==")
        print(f"{'驻留':>6}{'策略':>11}{'延长':>7}{'捕获率':>8}{'轮一遍':>8}{'首捕期望':>10}")
        for d in dwells:
            for name, order in orders.items():
                round_s = len(order) * (d + SWITCH_MS) / 1000.0
                for ext, cap in ((0.0, 0.0), (300.0, 600.0)):
                    hs = tot = 0
                    for seed in range(args.trials):
                        rng = random.Random(seed * 7919 + int(d))
                        bursts = make_bursts(rng, ch_clients, args.horizon, args.per_hour)
                        h, tt, _ = run_policy(bursts, order, d, args.horizon,
                                              kind=kind, ext_ms=ext, ext_cap=cap)
                        hs += h
                        tot += tt
                    rate = hs / tot if tot else 0.0
                    lam_per_s = tot / (args.trials * args.horizon / 1000.0)
                    ext_s = f"{int(ext)}ms" if ext else "-"
                    print(f"{int(d):>6}{name:>11}{ext_s:>7}{rate*100:>7.1f}%"
                          f"{round_s:>7.1f}s{fmt_t(ttfc(rate, lam_per_s)):>10}")
            print()
        print()


if __name__ == "__main__":
    main()
