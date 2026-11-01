"""CSI 动作检测: 单标量 vs 多子载波特征.

现状
----
固件把 52 个子载波的相邻帧残差**等权平均**成一个标量再送进 csi_det. 这丢掉两
件事:

1. **深衰落子载波被压掉**. 频率选择性信道上, 幅度接近零的子载波相位变化最
   剧烈 (同样 1mm 的路径变化, 在深零点附近引起的幅度变化最大). 但归一化之后
   它们的 a_i 本来就小, |Δa_i| 也小, 等权平均等于把最敏感的那几个点投了弃权票.
2. **频率维度的结构被抹平**. 真实运动让所有子载波的残差**同向**变化 (同一条
   路径的相位旋转在所有频率上一致), 而微波炉/单音干扰只砸一两个子载波. 平均
  之后这两种情况的标量可以一样大, 分不开.

这个脚本用多径合成数据量一量: 换一个特征到底能换来多少.

模型
----
H(f_k, t) = Σ_m a_m(t) · exp(-j·2π·f_k·(τ_m + Δ_m(t)))

静态路径的 a_m, τ_m 固定; 运动体现在某条路径的额外时延 Δ_m(t) 与遮挡引起的
幅度调制上. 每帧再叠一个随机 AGC 增益 (固件除以模长消掉) 和复高斯噪声.
固件拿到的只有 |H(f_k)|, 所以这里也只输出幅度.

场景
----
  static  静止, 只有噪声                    -> 误报率
  breath  呼吸: 单路径 ±2mm, 0.3Hz          -> 最难的小幅度
  walk    走动: 单路径 0.3~1.5m 随机游走     -> 主要目标
  interf  静止 + 一两个子载波被窄带干扰砸     -> 不该报成"有人"
"""

import argparse
import cmath
import math
import random
import statistics

# 802.11 20MHz OFDM: 子载波间隔 312.5kHz, 有效 52 个
N_SUB = 52
DF = 312.5e3        # Hz
F0 = 2.437e9        # ch6 中心频率
C = 3e8

# 固件的采样: 每 10 帧判一次. 帧率按 100Hz 算, 判定率 10Hz.
DECIM = 10


def make_paths(rng, kind):
    """返回 [[幅度, 基础时延, 时延调制, 幅度调制], ...].

    时延必须拉开. 之前用 0~120ns, 相邻路径只差 9ns, 而 16MHz 带宽对应的相位
    只转 0.9 弧度, 通带内几乎是平的, 没有深衰落. 幅度检测的敏感度全在深衰落
    点上 (那里一点相位变化就能换出大幅度变化), 谱是平的就什么都测不到.
    室内 100~400ns 的时延扩展才对应实测里那种梳状谱.
    """
    taus = sorted(rng.uniform(0, 400e-9) for _ in range(6))
    paths = []
    for i, tau in enumerate(taus):
        # 功率随时延指数衰减, 首径最强但不超过总功率的一半
        amp = math.exp(-tau / 180e-9) * rng.uniform(0.55, 1.0)
        paths.append([amp, tau, (lambda t: 0.0), (lambda t: 0.0)])

    if kind == "breath":
        # 呼吸: 胸廓位移约 5mm 峰峰, 0.3Hz
        d = 2.5e-3
        w = 2 * math.pi * 0.3
        paths[0][2] = lambda t: (d / C) * math.sin(w * t)
    elif kind == "walk":
        # 走动: 路径长度按两个不同频率叠加变化, 幅度同时被遮挡
        def step(t):
            return 0.9 * math.sin(2 * math.pi * 0.4 * t) + \
                   0.5 * math.sin(2 * math.pi * 1.1 * t + 1.0)
        paths[0][2] = lambda t: step(t) / C
        paths[0][3] = lambda t: 0.45 * math.sin(2 * math.pi * 0.4 * t + 0.7)
    elif kind == "interf":
        pass       # 干扰在采样阶段加
    return paths


def csi_frame(paths, t, rng, snr_db, interf_sub=None, interf_amp=0.0):
    """一帧的幅度向量 (52 点, 已做 AGC 归一化前的原始幅度)."""
    n = N_SUB
    re = [0.0] * n
    im = [0.0] * n
    for amp, tau, dmod, amod in paths:
        d = dmod(t)
        a = amp * (1.0 + amod(t))
        ph0 = -2.0 * math.pi * F0 * (tau + d)
        for k in range(n):
            ph = ph0 - 2.0 * math.pi * DF * k * (tau + d)
            re[k] += a * math.cos(ph)
            im[k] += a * math.sin(ph)

    # 复高斯噪声, 功率由 SNR 定 (信号功率按 1 归一)
    sigma = 10.0 ** (-snr_db / 20.0)
    out = [0.0] * n
    for k in range(n):
        nr = rng.gauss(0, sigma) * 0.5
        ni = rng.gauss(0, sigma) * 0.5
        if interf_sub and k in interf_sub:
            nr += rng.gauss(0, interf_amp)
            ni += rng.gauss(0, interf_amp)
        out[k] = math.hypot(re[k] + nr, im[k] + ni)

    # AGC: 每帧一个随机增益, 归一化之后应该被完全消掉
    g = math.exp(rng.gauss(0, 0.35))
    return [v * g for v in out]


# ---------------- 特征 ----------------

def norm(a):
    s = math.sqrt(sum(v * v for v in a))
    return s, ([v / s for v in a] if s > 1e-9 else None)


def feat_mean(d):
    """现状: 等权平均 (d 是带符号的残差)."""
    return sum(abs(v) for v in d) / len(d)


def feat_topk(d, k=8):
    """最敏感的 k 个子载波. 深衰落点的相对变化最大, 等权平均时被稀释."""
    a = sorted((abs(v) for v in d), reverse=True)
    a = a[:k] if len(a) > k else a
    return sum(a) / len(a)


def feat_max(d):
    return max(abs(v) for v in d)


def feat_coh(d):
    """同向一致性加权的均值.

    真实运动是同一条路径的相位旋转, 在频率轴上连续同向; 窄带干扰只在
    个别点上跳. 相邻残差同号的占比能分开这两种.
    一致率 50% 时权重为 0: 那说明残差在频率轴上就是白噪声, 不该算动作.
    """
    ad = [abs(v) for v in d]
    base = sum(ad) / len(ad)
    if len(d) < 3:
        return base
    same = sum(1 for i in range(len(d) - 1) if d[i] * d[i + 1] > 0)
    frac = same / (len(d) - 1)
    return base * max(0.0, 2.0 * frac - 1.0) * 2.0


FEATS = {"mean": feat_mean, "top8": feat_topk, "max": feat_max, "coh": feat_coh}

def coh_of(d):
    """同向一致性权重, 单独提出来给滞后差分复用."""
    ad = [abs(v) for v in d]
    base = sum(ad) / len(ad)
    if len(d) < 3:
        return 1.0
    same = sum(1 for i in range(len(d) - 1) if d[i] * d[i + 1] > 0)
    return max(0.0, 2.0 * (same / (len(d) - 1)) - 1.0)


def feat_lag_coh(d):
    """滞后差分上的同向一致性.

    呼吸这类慢动作在帧间 (10ms) 上几乎不动: 0.3Hz、±2.5mm 的胸廓位移,
    每帧只差 0.047mm, 相位变 0.0024 弧度, 掉进噪声里. 但把比较的基准换到
    500ms 之前, 位移差变成 2.4mm, 相位差 0.12 弧度, 深衰落点上就能看见.

    代价是 SNR 变差 (两帧各带一份噪声, 而且间隔久了信道真的可能变了),
    所以只能在"慢"这一档用, 快动作仍然看帧间.
    """
    return coh_of(d)



# ---------------- 检测器 (与 csi_det.c 同参数) ----------------

ENTER_Z, EXIT_Z, HOLD_N, CUSUM_K, CUSUM_H = 4.0, 1.5, 5, 0.5, 6.0
BASE_DOWN, BASE_UP, MAD_RATE, MAD_FLOOR = 0.02, 0.002, 0.05, 0.02


class Det:
    def __init__(self):
        self.base = 0.0
        self.mad = MAD_FLOOR
        self.cusum = 0.0
        self.hold = 0
        self.motion = False
        self.init = False

    def update(self, metric):
        if not self.init:
            self.base = metric
            self.init = True
            return False
        dev = metric - self.base
        self.cusum += dev - CUSUM_K * self.mad
        if self.cusum < 0:
            self.cusum = 0.0
        if self.motion:
            self.cusum = 0.0
        score = dev / (self.mad + MAD_FLOOR)
        enter = score > ENTER_Z or self.cusum > CUSUM_H * (self.mad + MAD_FLOOR)
        if self.motion:
            self.hold += 1
            if score < EXIT_Z and self.cusum <= 0 and self.hold >= HOLD_N:
                self.motion = False
                self.hold = 0
        elif enter:
            self.motion = True
            self.hold = 0
            self.cusum = 0.0
        self.base += (BASE_UP if self.motion else BASE_DOWN) * dev
        if not self.motion:
            self.mad += MAD_RATE * (abs(dev) - self.mad)
            if self.mad < MAD_FLOOR:
                self.mad = MAD_FLOOR
        return self.motion


def run_scenario(kind, frames=3000, snr_db=25.0, seed=1, warm=300, lag=50):
    """生成一帧帧 CSI, 返回 {特征名: 指标序列}.

    短滞后 = 相邻帧 (10ms), 长滞后 = lag 帧之前 (默认 50 帧 = 500ms).
    """
    rng = random.Random(seed)
    paths = make_paths(rng, kind)
    interf = {24, 25} if kind == "interf" else None
    iamp = 0.35 if kind == "interf" else 0.0

    prev = None
    buf = []                       # 归一化帧的历史, 长度 lag+1
    hist = {k: [] for k in FEATS}
    hist_lag = {k: [] for k in FEATS}
    t = 0.0
    for i in range(frames):
        t += 0.01
        amp = csi_frame(paths, t, rng, snr_db, interf, iamp)
        s_, a = norm(amp)
        if a is None:
            continue
        if prev is not None:
            d = [a[k] - prev[k] for k in range(len(a))]
            for name, fn in FEATS.items():
                hist[name].append(fn(d))
        if len(buf) >= lag:
            old_a = buf.pop(0)
            dl = [a[k] - old_a[k] for k in range(len(a))]
            for name, fn in FEATS.items():
                hist_lag[name].append(fn(dl))
        buf.append(a)
        prev = a
    return ({k: v[warm:] for k, v in hist.items()},
            {k: v[warm:] for k, v in hist_lag.items()})


def auc(pos, neg):
    """P(正样本指标 > 负样本指标). 0.5 等于瞎猜."""
    if not pos or not neg:
        return 0.5
    sp = sorted(neg)
    n = len(sp)
    tot = 0.0
    for v in pos:
        lo, hi = 0, n
        while lo < hi:                  # 第一个 >= v 的位置
            mid = (lo + hi) // 2
            if sp[mid] < v:
                lo = mid + 1
            else:
                hi = mid
        lt = lo
        lo, hi = 0, n
        while lo < hi:                  # 第一个 > v 的位置
            mid = (lo + hi) // 2
            if sp[mid] <= v:
                lo = mid + 1
            else:
                hi = mid
        le = lo
        tot += lt + 0.5 * (le - lt)     # 并列算半分
    return tot / (len(pos) * n)


def summarise(decisions):
    return sum(decisions) / len(decisions) if decisions else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--frames", type=int, default=3000)
    ap.add_argument("--snr", default="30,25,20,15")
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()

    snrs = [float(x) for x in args.snr.split(",")]

    print("AUC = P(有动作时的指标 > 静止时的指标). 0.5 瞎猜, 1.0 完美分开.")
    print("短滞后 = 相邻帧 (10ms); 长滞后 = 500ms 前. 慢动作只有长滞后看得见.")
    print()
    for tag, idx in (("短滞后 10ms", 0), ("长滞后 500ms", 1)):
        print(f"-- {tag} --")
        print(f"{'SNR':>5}{'场景':>8}" + "".join(f"{k:>9}" for k in FEATS))
        for snr in snrs:
            base = {}
            for sd in range(args.seeds):
                r = run_scenario("static", args.frames, snr, seed=sd * 31 + 7)[idx]
                for name in FEATS:
                    base.setdefault(name, []).extend(r[name])
            for kind in ("interf", "breath", "walk"):
                acc = {k: [] for k in FEATS}
                for sd in range(args.seeds):
                    r = run_scenario(kind, args.frames, snr, seed=sd * 31 + 7)[idx]
                    for name in FEATS:
                        acc[name].append(auc(r[name], base[name]))
                row = {k: statistics.mean(v) for k, v in acc.items()}
                print(f"{snr:>5.0f}{kind:>8}" + "".join(f"{row[k]:>9.3f}"
                                                        for k in FEATS))
            print()


if __name__ == "__main__":
    main()
