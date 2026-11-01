"""locate 拐点检测的参数定标.

场景: 循迹找源 (fox hunt). 人拿着设备走向发信源, RSSI 一路涨; 越过最近点后
一路跌. 拐点检测要在"越过"发生后尽快报出来, 同时不能把多径衰落当成拐点.

信号模型:
  rssi(t) = A - 10*gamma*log10(d(t)) + N(0, sigma) + 衰落
  d(t) = |d0 - v*t|, 衰落 = 每样本以 fade_p 概率开始一段 1~2 个样本、
  深 6~14dB 的掉点 (室内多径的实测量级).

检测器 (峰锁定状态机):
  level[t] = 最近 4 个样本的中位数 (抗单点衰落)
  sigma 用 |二阶差分| 的 q15 / 0.463 估计. 二阶差分消掉线性趋势; 峰值
  附近的信号曲率会把 q25 都抬高 ~2 倍 (窗内一半样本带曲率), q15 压住;
  衰落占比 <25% 时 q15 也干净. 归一化: |N(0,tau)| 的 q15 = 0.189*tau,
  tau = sqrt(6)*sigma, 0.189*2.449 = 0.463.

  武装 (SEARCHING), 两条互补的门:
    门 a (进行中的坡): 双窗中位数之差
      med(level[t-B..t-3]) - med(level[t-2B..t-B]) >= max(1.5*sigma, 4)
      斜坡的中位数落在窗口中央, 差值 ~= B 个样本的升程, 分辨力 0.5*sigma_lvl,
      是慢接近 (0.4dB/样本) 唯一能过的门; 远离场景为负, 天然抑制.
    门 b (刚完成的快通过): 单宽窗 level[t-2B..t-3]
      P = q80(窗), med = median(窗), start = med3(窗头 3 点)
      P - med   >= max(2*sigma, 5.5)   # 窗内有隆起
      P - start >= max(2.5*sigma, 7)   # 窗起点要低: 远离场景窗头是最高点,
                                       # 静止噪声 q80 只比中位高 ~1*sigma_lvl
    任一门成立 -> 锁 P (= 门 b 的 P 或门 a 的 q80(newer)), 进 ARMED.
  ARMED: 等当前电平 (med3, 抗衰落) 跌破 P - max(hf*sigma, 5), 连续 2 次
    (每 2 样本评一次) 报 "passed"; 3B 样本内没跌成, 解锁并冷却.
  开火/超时后冷却 2B. 用户折返再涨, 会重新武装.

用法: python scripts/loc_turn_sim.py
"""

import math
import random

SAMPLES = 120          # 60s @2Hz
DT = 0.5               # s per sample
A_DB = 45.0            # 1m 处参考电平
GAMMA = 2.5

# name: (d0, v, sigma, fade_p)
SCEN = {
    "pass_fast":  (10.0, 1.0, 3.0, 0.10),   # 20s 走到最近点
    "pass_slow":  (6.0, 0.5, 3.0, 0.10),    # 24s
    "pass_close": (3.0, 1.0, 3.0, 0.15),    # 6s 就到, 检出偏晚
    "approach":   (12.0, 0.15, 3.0, 0.10),  # 慢速远接近, 升程低于噪声分辨力
    "stationary": (5.0, 0.0, 3.0, 0.10),
    "recede":     (1.0, 0.5, 3.0, 0.10),
    "fade_storm": (5.0, 0.0, 4.0, 0.25),    # 衰落密集: 最容易误报的场景
}

ROUNDS = 300


def gen(d0, v, sigma, fade_p, rng):
    x = []
    fade_left = 0
    fade_db = 0.0
    for t in range(SAMPLES):
        d = max(abs(d0 - v * t * DT), 0.3)
        r = A_DB - 10 * GAMMA * math.log10(d)
        if fade_left > 0:
            fade_left -= 1
        else:
            fade_db = 0.0
            if rng.random() < fade_p:
                fade_left = rng.choice((0, 1))
                fade_db = -rng.uniform(6, 14)
        x.append(r + rng.gauss(0, sigma) + fade_db)
    return x


def med(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n & 1 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def quant(xs, q):
    s = sorted(xs)
    return s[(len(s) - 1) * q // 100]


def precompute(x):
    """level 轨迹与噪声尺度. 与参数无关, 每局算一次."""
    n = len(x)
    level = [None] * n
    for t in range(3, n):
        level[t] = med(x[t - 3: t + 1])
    sig = [None] * n
    for t in range(34, n):
        d2 = sorted(abs(x[i] - 2 * x[i - 1] + x[i - 2]) for i in range(t - 31, t + 1))
        sig[t] = max(d2[len(d2) * 15 // 100] / 0.463, 1.0)
    return level, sig


def scan(level, sig, B, hf, hr1, hr2, stride=2):
    SEARCH, ARMED, COOL = 0, 1, 2
    st = SEARCH
    P_lock = 0.0
    t_lock = 0
    t_cool = 0
    votes = 0
    events = []
    for t in range(2 * B, len(sig), stride):
        s = sig[t]
        if s is None:
            continue
        df = max(hf * s, 5.0)
        if st == SEARCH:
            older = [v for v in level[t - 2 * B: t - B] if v is not None]
            win = [v for v in level[t - 2 * B: t - 3] if v is not None]
            newer = [v for v in level[t - B: t - 3] if v is not None]
            if len(older) < 6 or len(newer) < 6 or len(win) < 2 * B - 6:
                continue
            P = quant(win, 80)
            m = med(win)
            head = [v for v in level[t - 2 * B: t - 2 * B + 3] if v is not None]
            if len(head) < 3:
                continue
            start = med(head)
            # 门 a: 双窗中位差, 抓进行中的坡 (慢接近唯一能过的门)
            ga = (med(newer) - med(older)) >= max(hr1 * s, 4.0)
            # 门 b: 宽窗隆起 + 窗起点低, 抓已完成的快通过
            gb = ((P - m) >= max(2.0 * s, 5.5) and
                  (P - start) >= max(hr2 * s, 7.0))
            if ga or gb:
                P_lock = P
                t_lock = t
                votes = 0
                st = ARMED
        elif st == ARMED:
            now = med([v for v in level[t - 2: t + 1] if v is not None])
            if now is None:
                continue
            if (P_lock - now) >= df:
                votes += 1
                if votes >= 2:
                    events.append(t)
                    st = COOL
                    t_cool = t
                    votes = 0
            else:
                votes = 0
            if t - t_lock > 3 * B:
                st = COOL
                t_cool = t
        else:
            if t - t_cool > 2 * B:
                st = SEARCH
    return events


def main():
    print(f"{'B':>3} {'hf':>4} | " +
          " | ".join(f"{n:>17s}" for n in SCEN))
    print("pass 列: 漏检/延迟中位/p90 (样本, 1样本=0.5s); 其余: 误报局数/300")
    series = {}
    for name, (d0, v, sg, fp) in SCEN.items():
        rng = random.Random(1234)
        peak_t = int(round(d0 / (v * DT))) if v else None
        lst = [precompute(gen(d0, v, sg, fp, rng)) for _ in range(ROUNDS)]
        series[name] = (lst, peak_t)

    best = None
    for B in (12, 16):
        for hf in (2.5, 3.0):
            for hr1, hr2 in ((1.5, 2.5), (2.0, 2.5), (2.0, 3.0), (2.5, 3.0)):
                fa = 0
                det = 0
                cells = []
                for name in SCEN:
                    lst, peak_t = series[name]
                    if name.startswith("pass"):
                        dl = [min(ev) - peak_t
                              for lv, sg in lst
                              if (ev := scan(lv, sg, B, hf, hr1, hr2))]
                        miss = ROUNDS - len(dl)
                        dmed = sorted(dl)[len(dl) // 2] if dl else 99
                        dp90 = sorted(dl)[int(len(dl) * 0.9)] if dl else 99
                        cells.append(f"miss{miss:2d} d={dmed:3d}/{dp90:3d}")
                        det += ROUNDS - miss
                    else:
                        f = sum(1 for lv, sg in lst
                                if scan(lv, sg, B, hf, hr1, hr2))
                        cells.append(f"FA {f:3d}")
                        fa += f
                tag = f"{B:3d} {hf:4.1f} {hr1:4.1f}/{hr2:4.1f}"
                print(f"{tag} | " + " | ".join(f"{c:>17s}" for c in cells) +
                      f"   [检出{det}/900 误报{fa}]")
                score = (900 - det) * 10 + fa * 3
                if best is None or score < best[0]:
                    best = (score, B, hf, hr1, hr2, det, fa)
    print("\n最优:", f"B={best[1]} hf={best[2]} hr1={best[3]} hr2={best[4]} "
          f"(检出{best[5]}/900 误报{best[6]})")


if __name__ == "__main__":
    main()
