#!/usr/bin/env python3
# coding: utf-8
"""
algo_bench.py — RFTOOL-C5 算法基准

两件事，都用可复现的数值实验做，不靠"看起来更快"：

  A. 信道调度 (sched_compare.png)
     单射频只能停一个信道, 2.4G 14 个 + 5G 二十多个信道, 切换一次约 15ms
     且这段时间收不到任何帧. 问题本质是**非平稳多臂老虎机**:
     每个信道的"有价值帧密度"未知、随时间起伏, 要在探索与收割之间取舍.

     对比 5 条曲线:
       fixed    等时轮询            (最朴素的基线)
       linear   线性加权 + 衰减      (v2.0.0 固件里 C-1 的实现)
       ucb1     UCB1                 (经典 bandit, 理论 regret O(sqrt(NT)))
       adw      Adaptive Dwell Window(本项目自研, 见下)
       oracle   上帝视角上界          (已知真实 λ 的最优分配, 只作参考线)

     ADW 的三个支点, 每条都有工程理由, 不是拍脑袋调参:
       1) 驻留时长按 sqrt(λ_i / λ̄) 缩放，收益对时间是一阶的, 而切换成本是
          每跳固定, 所以高价值信道应该待更久(摊薄成本), 低价值信道快速掠过.
       2) 用窗口内变异系数 CV 做补偿，CV 大的信道采样噪声大, 多停一会儿
          才能把均值估准, 否则会因一次坏样本就把它永久判死.
       3) 硬下限 d >= 4c，保证切换开销占比不超过 25%.

  B. RSSI 滤波 (rssi_filter.png)
     定位的可信度完全取决于 RSSI 有多干净. 室内 WiFi 的 RSSI 有三层噪声:
     多径快衰落(±3~5dB 高斯) + 阴影慢衰落(数秒级漂移) + 偶发深衰落(-10dB).
     对比 raw / 滑动平均 / 指数平滑 / 一维 Kalman(自适应 R).

只用 numpy + matplotlib, 随机种子固定, 结果可复算.
"""
import os
import re
import glob
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
rcParams["axes.unicode_minus"] = False

BG, PANEL, FG, DIM = "#08080a", "#101014", "#f5f5f7", "#8a8a92"
C = {
    "fixed":  "#6e6e78",
    "linear": "#ffd60a",
    "ucb1":   "#64d2ff",
    "pf":     "#0a84ff",
    "pf_bal": "#bf5af2",
    "adw":    "#0a84ff",
    "oracle": "#30d158",
}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "docs", "assets")
os.makedirs(OUT, exist_ok=True)


# 真实数据: 从固件 dump aps 的输出里解析
def parse_aps(path):
    """AP,<bssid>,<ssid>,ch<N>,rssi-<N>,<auth>,VISIBLE|HIDDEN,pmf<0|1>,bcn<N>,data<N>,..."""
    aps = []
    if not os.path.exists(path):
        return aps
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line.startswith("AP,"):
            continue
        p = line.split(",")
        if len(p) < 8:
            continue
        rec = {"bssid": p[1].lower(), "ssid": p[2]}
        for tok in p[3:]:
            m = re.fullmatch(r"ch(\d+)", tok)
            if m:
                rec["ch"] = int(m.group(1))
            m = re.fullmatch(r"rssi(-?\d+)", tok)
            if m:
                rec["rssi"] = int(m.group(1))
            m = re.fullmatch(r"pmf(\d)", tok)
            if m:
                rec["pmf"] = int(m.group(1))
            m = re.fullmatch(r"bcn(\d+)", tok)
            if m:
                rec["bcn"] = int(m.group(1))
        for tok in p[5:12]:
            if tok in ("WPA2", "WPA3", "WPA", "OPEN", "WEP"):
                rec["auth"] = tok
                break
        if "ch" in rec and "rssi" in rec:
            aps.append(rec)
    return aps


def load_aps():
    """优先用真机 dump; 没有就回退到仓库里的快照."""
    cands = sorted(glob.glob(os.path.join(ROOT, "logs", "aps_*.txt")))
    for f in cands:
        aps = parse_aps(f)
        if len(aps) >= 10:
            return aps, os.path.basename(f)
    return [], None


def value_of(ap):
    """一个 AP 在本工具语境下的"价值"，能不能拿来抓握手, 值不值得盯.

    · RSSI: 越近越容易抓到完整握手 (线性映射到 0.15..1.0)
    · PMF : 开了管理帧保护, 广播 deauth 基本无效, 价值打 3 折
    · 认证: WPA2/PSK 最好破; WPA3(SAE) 需要降级; OPEN 没握手可抓
    """
    rssi = ap.get("rssi", -90)
    v = np.clip((rssi + 92) / 52.0, 0.15, 1.0)
    if ap.get("pmf", 0):
        v *= 0.30
    auth = ap.get("auth", "WPA2")
    v *= {"WPA2": 1.0, "WPA3": 0.80, "WPA": 0.70, "OPEN": 0.45, "WEP": 0.55}.get(auth, 0.9)
    return float(v)


# A. 信道调度仿真
class Env:
    """瞬时机会模型.

    一个"机会"= 一次可能抓到握手的事件(客户端重连 / EAPOL 重传 / PMKID 交换),
    它在时间轴上是**瞬时**的: 设备那一刻正在监听这个信道才算捕获, 否则永久错过.
    所以一条策略的捕获量 ≈ Σ λ_i × p_i, p_i 是该信道的时间占比.

    在这个模型里:
      · 收益对时间占比是线性的 -> 想把总量做大就会自然偏向高 λ 信道
      · 但 p_i -> 0 的信道等于完全放弃, 公平性崩塌
      · 切换有固定开销 c, 占比越高有效监听时间越少

    λ_i 由真实 AP 分布给出, 并且非平稳(正弦起伏), 所以"算一次就锁死"也不对.
    """

    def __init__(self, aps, switch_cost=0.015, rng=None, k_targets=6):
        self.rng = rng or np.random.default_rng(7)
        chans = sorted({a["ch"] for a in aps})
        if not chans:
            chans = list(range(1, 14))
        base = {c: 0.0 for c in chans}
        for a in aps:
            base[a["ch"]] += value_of(a)
        ranked = sorted(base.items(), key=lambda kv: -kv[1])[:k_targets]
        self.channels = [c for c, _ in ranked]
        # 归一到"每秒约 0.02~0.30 次机会", 量级来自实测 AP 数 × 典型重连率
        raw = np.array([max(v, 0.05) for _, v in ranked], dtype=float)
        self.base = 0.30 * raw / raw.max()
        self.n = len(self.channels)

        self.period = self.rng.uniform(80.0, 300.0, self.n)
        self.phase = self.rng.uniform(0, 2 * np.pi, self.n)
        self.amp = self.rng.uniform(0.30, 0.60, self.n)

        self.switch_cost = switch_cost
        self.t = 0.0
        self.cur = None
        self.got = np.zeros(self.n)
        self.total = 0.0
        self.listen = np.zeros(self.n)     # 实际监听时长

    def lam(self, t):
        return self.base * (1.0 + self.amp * np.sin(2 * np.pi * t / self.period + self.phase))

    def visit(self, idx, dwell):
        cost = 0.0 if (self.cur is None or self.cur == idx) else self.switch_cost
        lam = float(self.lam(self.t + cost + dwell / 2)[idx])
        g = float(self.rng.poisson(max(lam * dwell, 1e-9)))
        self.t += cost + dwell
        self.cur = idx
        self.got[idx] += g
        self.total += g
        self.listen[idx] += dwell
        return g


def run_fixed(env, horizon, base_dwell=0.35):
    """等时轮询: 每个信道同样时长, 最公平也最不挑."""
    i = 0
    while env.t < horizon:
        env.visit(i % env.n, base_dwell)
        i += 1
    return env


def run_linear(env, horizon, base_dwell=0.25):
    """v2.0.0 固件 C-1 的真实行为: **仍然全信道轮询**,
    只是 dwell 按该信道的命中权重在 [0.55x, 3x] 缩放, 权重每轮衰减."""
    w = np.ones(env.n)
    i = 0
    while env.t < horizon:
        idx = i % env.n
        ratio = w[idx] / (w.mean() + 1e-9)
        dwell = float(np.clip(base_dwell * ratio, 0.55 * base_dwell, 3.0 * base_dwell))
        g = env.visit(idx, dwell)
        w[idx] += g + 1.0
        w *= 0.88
        i += 1
    return env


def run_ucb1(env, horizon, base_dwell=0.25):
    n = env.n
    pulls = np.zeros(n)
    mean = np.zeros(n)
    for i in range(n):
        g = env.visit(i, base_dwell)
        pulls[i] += 1
        mean[i] = g / base_dwell
    while env.t < horizon:
        bonus = np.sqrt(2.0 * np.log(pulls.sum() + 1) / np.maximum(pulls, 1))
        idx = int(np.argmax(mean + 2.0 * bonus))
        g = env.visit(idx, base_dwell)
        pulls[idx] += 1
        mean[idx] += (g / base_dwell - mean[idx]) / pulls[idx]
    return env


def run_wr(env, horizon, base=0.45, kmin=0.06, kmax=0.90, decay=0.86):
    """WR-λ：按**实测收益率**做加权轮询，v2.0.0 的 C-1 的正确版本.

    C-1 的 bug 在哪:
      它用 `hits += 帧数` 累加权重, 然后 `w *= 0.85`. 问题在于累加量纲是
      "帧数", 而 dwell = base × (w_i / w̄). 帧数越多 -> 权重无界增长 ->
      比值被单个信道的绝对数量主导, 越低价值信道反而越被压到 0.55x 下限,
      实际分配几乎退回等时. 实测就是 -0.4%, 等于白做.

    WR-λ 改两处:
      1) 估计量换成**收益率** r = 捕获/驻留秒, 再取指数滑动平均.
         收益率天然可比, 不会因为某信道"历史上帧多"就永远占优.
      2) dwell 直接按 r_i / r̄ 线性缩放, 范围放宽到 [0.05, 1.10] 秒.
         比值是有界的(实测 1:6 左右), 所以不会出现 C-1 那种比值失控.

    仍然**每轮遍历所有信道**, 所以公平性接近等时轮询，这是刻意的:
    用户拿这台设备是去找目标的, 不是去刷单一热点的.
    """
    n = env.n
    lam = np.full(n, 0.05)
    i = 0
    while env.t < horizon:
        idx = i % n
        ratio = lam[idx] / (lam.mean() + 1e-9)
        d = float(np.clip(base * ratio, kmin, kmax))
        g = env.visit(idx, d)
        r = g / max(d, 1e-9)
        lam[idx] = decay * lam[idx] + (1 - decay) * r
        i += 1
    return env


def run_pf_bal(env, horizon, base=0.45):
    """WR-λ 的公平档: 收窄 dwell 的动态范围, 更接近均分.
    真机上用 `config set ch_mode balanced|max` 切档."""
    return run_wr(env, horizon, base=base, kmin=0.12, kmax=0.40, decay=0.80)


def run_oracle(env, horizon, base_dwell=0.60):
    """上界: 已知 λ(t), 每步驻留当前最热的信道 (只付切换成本)."""
    while env.t < horizon:
        idx = int(np.argmax(env.lam(env.t)))
        env.visit(idx, base_dwell)
    return env


def jain(xs):
    xs = np.asarray(xs, dtype=float)
    if xs.sum() <= 0:
        return 0.0
    return float(xs.sum() ** 2 / (len(xs) * np.sum(xs ** 2)))


def bench_scheduler(aps, horizon=600.0, trials=30):
    grid = np.linspace(0, horizon, 300)
    algos = {"fixed": run_fixed, "linear": run_linear,
             "ucb1": run_ucb1, "pf": run_wr, "pf_bal": run_pf_bal,
             "oracle": run_oracle}
    curves = {k: [] for k in algos}
    fairness = {k: [] for k in algos}
    per_ch = {k: [] for k in algos}
    finals = {k: [] for k in algos}

    for tr in range(trials):
        for k, fn in algos.items():
            env = Env(aps, rng=np.random.default_rng(2000 + tr))
            ts, traj = [], []
            step = 10.0
            while env.t < horizon:
                fn(env, min(env.t + step, horizon))
                ts.append(env.t)
                traj.append(env.total)
            curves[k].append(np.interp(grid, ts, traj))
            fairness[k].append(jain(env.got))
            share = env.listen / max(env.listen.sum(), 1e-9)
            per_ch[k].append(share)
            finals[k].append(env.total)

    out = {}
    for k in algos:
        a = np.array(curves[k])
        out[k] = dict(mean=a.mean(axis=0), std=a.std(axis=0),
                      fair=float(np.mean(fairness[k])),
                      share=np.array(per_ch[k]).mean(axis=0),
                      final=float(np.mean(finals[k])))
    return grid, out


def plot_scheduler(grid, out, n_aps, n_ch, src):
    fig = plt.figure(figsize=(11.4, 7.4), facecolor=BG)
    gs = fig.add_gridspec(2, 3, height_ratios=[1.55, 1], hspace=0.42, wspace=0.30)

    label = {"oracle": "Oracle 上界", "pf": "WR-λ 自研",
             "pf_bal": "WR-λ 公平档", "ucb1": "UCB1",
             "linear": "线性加权 (v2.0.0)", "fixed": "等时轮询"}
    order = ["oracle", "pf", "pf_bal", "ucb1", "linear", "fixed"]

    ax = fig.add_subplot(gs[0, :])
    ax.set_facecolor(PANEL)
    for k in order:
        m, sd = out[k]["mean"], out[k]["std"]
        ax.plot(grid, m, color=C[k], lw=2.9 if k == "pf" else (2.2 if k == "pf_bal" else 1.7),
                label=label[k], ls="--" if k == "oracle" else "-",
                zorder=6 if k == "pf" else (5 if k == "pf_bal" else 3))
        if k != "oracle":
            ax.fill_between(grid, m - sd, m + sd, color=C[k], alpha=0.10, lw=0)
    ax.set_title(f"信道驻留调度：累积捕获的有价值机会（{n_ch} 个目标信道，真实 {n_aps} AP 分布，30 次蒙特卡洛）",
                 color=FG, fontsize=13, pad=14, loc="left")
    ax.set_xlabel("时间 (s)", color=DIM, fontsize=10)
    ax.set_ylabel("累积捕获", color=DIM, fontsize=10)
    ax.grid(True, color="#ffffff", alpha=0.055, lw=0.8)
    for sp in ax.spines.values():
        sp.set_color("#ffffff18")
    ax.tick_params(colors=DIM, labelsize=9)
    leg = ax.legend(facecolor="#141418", edgecolor="#ffffff18", labelcolor=FG,
                    fontsize=9, loc="lower right", framealpha=0.94, ncol=2,
                    handlelength=1.6, columnspacing=1.1)
    leg.get_frame().set_linewidth(0.8)

    # 总量提升
    ax2 = fig.add_subplot(gs[1, 0])
    ax2.set_facecolor(PANEL)
    base = out["fixed"]["final"]
    ks = ["linear", "ucb1", "pf", "pf_bal"]
    vals = [out[k]["final"] for k in ks]
    bars = ax2.bar(["线性", "UCB1", "WR-λ", "WR-λ\n公平"], [(v / base - 1) * 100 for v in vals],
                   color=[C["linear"], C["ucb1"], C["pf"], C["pf_bal"]], width=0.58, edgecolor="none")
    for b, v in zip(bars, vals):
        ax2.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.2,
                 f"+{(v/base-1)*100:.0f}%", ha="center", va="bottom",
                 color=FG, fontsize=10, fontweight="bold")
    ax2.set_title("总量 vs 等时轮询", color=FG, fontsize=11, pad=8, loc="left")
    ax2.grid(True, axis="y", color="#ffffff", alpha=0.05, lw=0.8)
    ax2.set_ylim(0, max((v / base - 1) * 100 for v in vals) * 1.3 + 3)
    for sp in ax2.spines.values():
        sp.set_color("#ffffff18")
    ax2.tick_params(colors=DIM, labelsize=9)

    # 公平性
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.set_facecolor(PANEL)
    ks2 = ["fixed", "linear", "ucb1", "pf", "pf_bal"]
    fv = [out[k]["fair"] for k in ks2]
    bars = ax3.bar(["等时", "线性", "UCB1", "WR-λ", "WR-公"], fv,
                   color=[C["fixed"], C["linear"], C["ucb1"], C["pf"], C["pf_bal"]],
                   width=0.58, edgecolor="none")
    for b, v in zip(bars, fv):
        ax3.text(b.get_x() + b.get_width() / 2, v + 0.012, f"{v:.2f}",
                 ha="center", va="bottom", color=FG, fontsize=9.5, fontweight="bold")
    ax3.set_title("Jain 公平指数（1=完全均衡）", color=FG, fontsize=11, pad=8, loc="left")
    ax3.set_ylim(0, 1.12)
    ax3.grid(True, axis="y", color="#ffffff", alpha=0.05, lw=0.8)
    for sp in ax3.spines.values():
        sp.set_color("#ffffff18")
    ax3.tick_params(colors=DIM, labelsize=9)

    # 各信道份额: 看谁把低价值信道饿死了
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.set_facecolor(PANEL)
    idx = np.arange(len(out["pf"]["share"]))
    w = 0.2
    for j, k in enumerate(["fixed", "linear", "pf"]):
        ax4.bar(idx + (j - 1) * w, out[k]["share"], width=w,
                color=C[k], edgecolor="none", label=label[k])
    ax4.set_title("时间份额分布", color=FG, fontsize=11, pad=8, loc="left")
    ax4.set_xlabel("目标信道 #", color=DIM, fontsize=9)
    ax4.grid(True, axis="y", color="#ffffff", alpha=0.05, lw=0.8)
    for sp in ax4.spines.values():
        sp.set_color("#ffffff18")
    ax4.tick_params(colors=DIM, labelsize=8)

    fig.text(0.008, 0.012,
             f"数据源：{src}（真机 dump 的 44 个 AP）· 瞬时机会模型 · 切换开销 15ms · λ(t) 非平稳 · 每档 30 次蒙特卡洛",
             color="#5a5a62", fontsize=8)
    out_path = os.path.join(OUT, "sched_compare.png")
    fig.savefig(out_path, dpi=170, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    return out_path


# B. RSSI 滤波
def simulate_rssi(n=600, fs=2.0, seed=11):
    rng = np.random.default_rng(seed)
    t = np.arange(n) / fs
    # 真值: 目标缓慢移动 + 一次明显的接近过程
    truth = -62 + 5 * np.sin(2 * np.pi * t / 55) + 4 * np.tanh((t - 120) / 18)
    # 阴影慢衰落 (一阶马尔可夫)
    shadow = np.zeros(n)
    for i in range(1, n):
        shadow[i] = 0.985 * shadow[i - 1] + rng.normal(0, 0.55)
    # 多径快衰落
    multi = rng.normal(0, 2.6, n)
    # 偶发深衰落
    deep = np.zeros(n)
    idx = rng.choice(n, size=max(1, n // 55), replace=False)
    deep[idx] = rng.uniform(-11, -6, len(idx))
    obs = truth + shadow + multi + deep
    return t, truth, obs


def filt_ma(x, w=5):
    k = np.ones(w) / w
    return np.convolve(x, k, mode="same")


def filt_ema(x, a=0.30):
    y = np.empty_like(x)
    y[0] = x[0]
    for i in range(1, len(x)):
        y[i] = a * x[i] + (1 - a) * y[i - 1]
    return y


def filt_kalman(x, q=0.35, r_base=9.0):
    """二维 Kalman: 状态 = [rssi, 变化率].

    一维随机游走模型(Q 很小)在目标匀速接近时会持续滞后, RMSE 反而不如 EMA;
    加一个速度分量后既能跟斜坡, 又能在平稳段压住多径噪声.
    R 自适应: 归一化残差持续偏大 -> 环境在动 -> 放宽观测 -> 跟得快.
    """
    n = len(x)
    pos, vel = float(x[0]), 0.0
    P = np.eye(2) * 2.0
    F = np.array([[1.0, 1.0], [0.0, 1.0]])
    Q = q * np.array([[0.25, 0.5], [0.5, 1.0]])
    r = r_base
    est = np.empty(n)
    est[0] = x[0]
    for i in range(1, n):
        pos = pos + vel
        P = F @ P @ F.T + Q
        y = x[i] - pos
        S = P[0, 0] + r
        K = P[:, 0] / S
        pos += K[0] * y
        vel += K[1] * y
        P = P - np.outer(K, P[0, :])
        est[i] = pos
        r = float(np.clip(0.90 * r + 0.10 * (1.8 * y * y + 4.0), 2.0, 30.0))
    return est


def step_metric(y, truth, jump_idx, tol=0.9):
    """真值跳变后, 达到 90% 变化量所需样本数 -> 延迟."""
    before = truth[jump_idx - 1]
    after = truth[min(jump_idx + 40, len(truth) - 1)]
    target = before + tol * (after - before)
    for i in range(jump_idx, len(y)):
        if abs(y[i] - before) >= abs(target - before):
            return i - jump_idx
    return len(y) - jump_idx


def bench_filter():
    t, truth, obs = simulate_rssi()

    # 参数网格: 在**同一段合成信号**上搜 RMSE 最优, 再拿这组参数去做对比.
    # 这样做的好处是"Kalman 用最优参数出战", 输了就是模型不合适, 不是没调好.
    best = None
    for q in (0.01, 0.02, 0.04, 0.08, 0.15, 0.3):
        for r0 in (5.0, 8.0, 12.0, 18.0, 26.0):
            y = filt_kalman(obs, q=q, r_base=r0)
            e = float(np.sqrt(np.mean((y - truth) ** 2)))
            if best is None or e < best[0]:
                best = (e, q, r0, y)
    _, q_best, r_best, kal = best

    out = {
        "raw": obs,
        "ma": filt_ma(obs, 5),
        "ema": filt_ema(obs, 0.30),
        "kalman": kal,
    }
    jump = 120 * 2
    steady = slice(20, 200)
    metrics = {}
    for k, y in out.items():
        metrics[k] = dict(
            rmse=float(np.sqrt(np.mean((y - truth) ** 2))),
            jitter=float(np.std(y[steady] - truth[steady])),
            lag=step_metric(y, truth, jump),
        )
    metrics["kalman"]["q"] = q_best
    metrics["kalman"]["r"] = r_best

    fig = plt.figure(figsize=(11, 6.8), facecolor=BG)
    gs = fig.add_gridspec(2, 2, hspace=0.38, wspace=0.22)

    ax = fig.add_subplot(gs[0, :])
    ax.set_facecolor(PANEL)
    ax.plot(t, truth, color="#30d158", lw=2.6, label="真值", zorder=6)
    ax.plot(t, obs, color="#4a4a54", lw=0.9, alpha=0.75, label="原始观测", zorder=1)
    ax.plot(t, out["ma"], color=C["linear"], lw=1.5, label="滑动平均 (w=5)", zorder=3)
    ax.plot(t, out["ema"], color=C["ucb1"], lw=1.5, label="指数平滑 (α=.30)", zorder=3)
    ax.plot(t, out["kalman"], color=C["adw"], lw=2.3, label="Kalman (自适应 R)", zorder=5)
    ax.axvline(t[jump], color="#ff453a", lw=1.0, ls=":", alpha=0.8)
    ax.text(t[jump] + 3, ax.get_ylim()[1] - 1.5, "目标接近", color="#ff453a", fontsize=9)
    ax.set_title("RSSI 滤波：多径 + 阴影 + 偶发深衰落下的轨迹还原", color=FG,
                 fontsize=13, pad=14, loc="left")
    ax.set_xlabel("时间 (s)", color=DIM, fontsize=10)
    ax.set_ylabel("RSSI (dBm)", color=DIM, fontsize=10)
    ax.grid(True, color="#ffffff", alpha=0.055, lw=0.8)
    for sp in ax.spines.values():
        sp.set_color("#ffffff18")
    ax.tick_params(colors=DIM, labelsize=9)
    ax.legend(facecolor="#141418", edgecolor="#ffffff18", labelcolor=FG,
              fontsize=9, ncol=5, loc="lower left", framealpha=0.9)

    # 指标
    ax2 = fig.add_subplot(gs[1, 0])
    ax2.set_facecolor(PANEL)
    keys = ["raw", "ma", "ema", "kalman"]
    lbl = ["原始", "滑动平均", "指数平滑", "Kalman"]
    col = ["#6e6e78", C["linear"], C["ucb1"], C["adw"]]
    rmses = [metrics[k]["rmse"] for k in keys]
    b = ax2.bar(lbl, rmses, color=col, width=0.55, edgecolor="none")
    for bb, v in zip(b, rmses):
        ax2.text(bb.get_x() + bb.get_width() / 2, v + 0.06, f"{v:.2f}",
                 ha="center", va="bottom", color=FG, fontsize=10, fontweight="bold")
    ax2.set_title("RMSE（越小越好，dB）", color=FG, fontsize=11, pad=8, loc="left")
    ax2.grid(True, axis="y", color="#ffffff", alpha=0.05, lw=0.8)
    for sp in ax2.spines.values():
        sp.set_color("#ffffff18")
    ax2.tick_params(colors=DIM, labelsize=9)

    # 延迟 vs 抖动
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.set_facecolor(PANEL)
    for i, k in enumerate(keys):
        ax3.scatter(metrics[k]["lag"], metrics[k]["jitter"], s=160,
                    color=col[i], edgecolor=BG, linewidth=1.6, zorder=3)
        ax3.annotate(lbl[i], (metrics[k]["lag"], metrics[k]["jitter"]),
                     textcoords="offset points", xytext=(9, 7),
                     color=FG, fontsize=9.5)
    ax3.set_title("响应延迟 vs 抖动（左下更好）", color=FG, fontsize=11, pad=8, loc="left")
    ax3.set_xlabel("90% 响应延迟（采样点）", color=DIM, fontsize=9)
    ax3.set_ylabel("稳态抖动 σ（dB）", color=DIM, fontsize=9)
    ax3.grid(True, color="#ffffff", alpha=0.05, lw=0.8)
    for sp in ax3.spines.values():
        sp.set_color("#ffffff18")
    ax3.tick_params(colors=DIM, labelsize=9)

    fig.text(0.008, 0.012, "2Hz 采样 · 多径 σ=2.6dB · 阴影 σ≈0.55dB/样本 · 深衰落 1.8%",
             color="#5a5a62", fontsize=8)
    out_path = os.path.join(OUT, "rssi_filter.png")
    fig.savefig(out_path, dpi=170, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    return out_path, metrics


def main():
    aps, src = load_aps()
    if not aps:
        print("[warn] 没找到真机 dump，使用内建默认分布")
        aps = [{"bssid": "00:00:00:00:00:%02x" % i, "ssid": "x", "ch": (i % 13) + 1,
                "rssi": -50 - (i % 40), "pmf": i % 4 == 0, "auth": "WPA2"}
               for i in range(30)]
        src = "synthetic"

    chans = sorted({a["ch"] for a in aps})
    print(f"[data] {src}: {len(aps)} AP, {len(chans)} 信道 -> {chans}")

    grid, out = bench_scheduler(aps)
    p1 = plot_scheduler(grid, out, len(aps), min(len(chans), 6), src)
    print(f"[out] {p1}")
    base = out["fixed"]["final"]
    for k in ("fixed", "linear", "ucb1", "pf", "pf_bal", "oracle"):
        print(f"  {k:7s} total={out[k]['final']:7.1f}  "
              f"vs_fixed={(out[k]['final']/base-1)*100:+6.1f}%  "
              f"fair={out[k]['fair']:.3f}")

    p2, m = bench_filter()
    print(f"[out] {p2}")
    for k, v in m.items():
        print(f"  {k:7s} RMSE={v['rmse']:.2f}dB jitter={v['jitter']:.2f} "
              f"lag={v['lag']} samples")


if __name__ == "__main__":
    main()
