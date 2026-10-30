# 验证分工：主机 / 仿真 / 真机

owner: chinese1123243
last verified: 2026-10-31
applies-to: 全仓库
related checks: `test/host/run_all.sh`、`scripts/chan_cross.py`、`scripts/test_sweep.py`

三档不能互相替代。用错档位的表现是「测试全绿但真机不工作」。

## 一、主机端（不插板，进 CI）

`bash test/host/run_all.sh`，八组共 540 条断言，另有 `chan_cross.py` 750 点公式比对。

前提是**纯逻辑不依赖 ESP-IDF**。做法不是造抽象，是按「碰不碰硬件」拆文件：

| 模块 | 纯逻辑 | 需要 ESP 的部分 |
|---|---|---|
| `radio_rules` | 冲突规则表与查询 | 无 |
| `frame_build` | deauth/auth/beacon/assoc/CSA 组帧 | `frame_build_tx` 负责发射 |
| `eapol_core` | KeyInfo 判消息号、PMKID 提取 | 无 |
| `ie_parse` | RSN/HT/VHE/RNR 解析 | 无 |
| `zbtx_frame` | 802.15.4 beacon/beaconreq/data 组帧 | `zbtx` 负责射频 |
| `chan_sched` | 两套驻留算法与排序 | 无 |
| `wifi_names` / `wifi_export` | 三表派生 + CSV/JSON 行布局 | 无 |

`test/host/stub/esp_err.h` 是最小桩，只放纯逻辑真正用到的类型与常量。
**往桩里加符号前先问：这个文件本该依赖 ESP 吗？该的话应该拆出去，不是往桩里堆。**

## 二、仿真（不插板，进 CI）

`scripts/chan_cross.py`：把 `chan_dwell_psd` 的 750 个输入点与
`chan_sim.py` 的 `run_psd` 算式逐点比对。抽成纯函数之前这件事做不了。

`scripts/chan_sim.py`：4 策略 × 3 场景 × 300 局的离散事件模型，用于筛掉坏设计。
`scripts/stress.py --compare`：9 个功能族反复启停做内存归因。

**仿真能验证状态机、报文解析、估计算法和边界值，不能证明辐射、EVM、灵敏度、
功率、邻道与法规符合性。**

## 三、真机（本地，进不了 CI）

| 脚本 | 覆盖 | 耗时 |
|---|---|---|
| `selftest_b4.py COM4` | 11 条命令 + OTA + 启动 | 约 25s |
| `test_sweep.py COM4` | 127 条用例全量扫描 | 约 3.5min |
| `test_inject.py COM4` | 注入引擎 20 项断言 | 约 2min |
| `stress.py --compare` | 9 个功能族内存归因 | 数分钟 |

## 四、三档都没抓住的教训

`hs.c` 的 KeyInfo 位曾把 MIC 写成 `0x0008`（那是 Key Type），自检帧又刚好没置该位，
于是真实 M1 一直被当 M3，PMKID 提取从未执行，**自检长期是绿的**。

同类事故的共同形状：**自检构造的输入恰好绕开了缺陷条件**。
所以自检帧必须逐字节照线上抓到的抄，不能自己拼一个「看起来对」的。
