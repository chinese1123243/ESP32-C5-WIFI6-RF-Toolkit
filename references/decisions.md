# 已批准的决定、例外与冲突裁决

owner: chinese1123243
last verified: 2026-10-31
applies-to: 全仓库
related checks: `scripts/arch_check.py`、`test/host/run_all.sh`

只记「为什么不这么做」和「和文档哪里不一样」。正常按文档执行的事不记。

## 一、文档与代码冲突，以代码或实测为准的

### 1. RSN Capabilities 的 B6/B7 含义

**冲突**：`main/ie_parse.c` 原注释写 `B6 = MFPC (支持) / B7 = MFPR (强制)`。
**裁决**：按 802.11 标准，`B6 = MFPR`、`B7 = MFPC`。代码位序写反了，已修正。
**依据**：板机实测 `4c:b7:e0:16:28:27`「6G网」`akm,PSK/SAE` 为过渡模式 AP，
只置 MFPC；旧代码把它判成强制 PMF，固件自己挡掉 deauth。
**复检**：`test/host/test_ie_parse.c` 里 MFPC 与 MFPR 分开验；把位序改回错误版本会 FAIL 两条。

### 2. 射频冲突规则是 6 条不是 5 条

**冲突**：架构文档的 `k_conflicts[]` 列 5 行，没有 `TX_INJECT / RES_15_4`。
**裁决**：实现 6 行。
**依据**：`cmd_zbsniff` 与 `cmd_zbtx` 都会先调 `wifi_attack_stop_all()`，注入与 15.4 实际互斥。
**复检**：`test/host/test_radio_rules.c` 把规则条数钉在 6；少一条即 FAIL。

### 3. 反向依赖是 8 条不是 3 条

**冲突**：文档 §5.3 记 3 条（`cap.c`、`hs.c`、`ble_cli.c→phish.h`）。
**裁决**：实测 8 条，其中 7 个领域文件为 `raw_out` 回传手机而 `include "ble_cli.h"`。
**处置**：抽出 `main/out_stream.c/.h`，改调 `out_raw()`，8 → 4。
**剩余四条不合并**，因为不是同一类问题，合成一个抽象会更差：
- `ble_adv.c → ble_cli.h`：BLE 角色耦合（暂停广播），不是输出耦合
- `phish.c` / `wifi_attack.c → http_server.h`：控制面耦合，门户要自己起停 HTTP 服务
- `ble_cli.c → phish.h`：文档点名的数据上传槽
**复检**：`scripts/arch_check.py` 基线 4，已知集合只能变短。

### 4. chan_sim.py 没建模 2000ms 绝对封顶

**冲突**：固件 `chan_dwell_psd` 有绝对上限 2000ms，`scripts/chan_sim.py` 的 `run_psd` 只有 `base*2`。
**裁决**：保留固件上限，不改仿真器。
**影响**：750 点比对里 48 点分叉，全部在 `base=1500`。默认 `base=1000` 时
`2×base` 正好 2000，上限不起作用，所以「psd 达 oracle 94.5%~99.0%」的历史结论不受影响。
**复检**：`scripts/chan_cross.py` 每次 CI 跑；分叉点数变动即需复查。

## 二、刻意不修的问题

### 5. `zbtx_build_data` 的 cap 检查早于截断

先用未截断的 `plen` 判 `cap < 1+9+plen`，再截断。于是缓冲装不下原始 `plen` 时直接拒绝，
而不是截断后照发。行为安全（不越界），但代码读起来像「先截断」。
**不修的理由**：改它会改变对外行为（拒绝 → 截断），属接口语义变更，需单独决策。
**现状**：`test/host/test_zbtx_frame.c` 把两种情形分别钉住。

### 6. `frame_build_tx.c` 的两处 ESP_LOGW 被去掉

原因改用 `esp_err_t` 返回码传递。丢掉的是人读的诊断文本，但调用方本来就按返回码分支。
**更好的做法**（未做）：给 HAL 加 `log_warn` 函数指针。属下一轮范围。

## 三、流程上的硬约束

### 7. arch_check 是棘轮，不是达标判定

基线锁定当日实测值，只许降不许升。**每还掉一笔欠账，必须同步下调脚本里的基线数字**，
否则闸门形同虚设。当前基线：`cli.c` 2592 行、单文件最大 2592、`printf("META` 318、反向依赖 4。

### 8. 主机单测必须验变异

能过的测试不等于有效。已发现两次变异未被抓住：
- 用 `0x00C0` 同时置 MFPC/MFPR 两位，位序写反也照样通过 → 拆成两个独立用例
- 变异头文件放在 `-I` 路径，但带引号的 include 按源文件目录优先解析 → 变异根本没生效

**规则**：每条断言做完必须退回缺陷行为确认它 FAIL。改完变异要确认「测试真的看见了变异」。

### 9. ρ 量在 out_stream，不是 event_bus

第一版把到达率窗口写进 `event_publish`。实测 `sniff auto` 12 秒后 `ev_pub` 只涨 1，
读数没有意义：每包一行的调用者是 `cap.c` / `hs.c` / `phish.c` / `wifi_attack.c` 的
`raw_out`，它们走 `out_raw` 而不经过事件总线。

`out_raw` 是所有出站行的唯一汇点，λ 量在这里才是链路真实负载。
`event_bus` 只保留自己的两个计数：`ev_pub` 与 `ev_dropped`（拿不到环形锁整条丢）。

### 10. ρ 现在到不了 1，因为每个生产者都自限速

实测（v2.4.2，COM4）：

| 状态 | `out_rate_x10` | ρ | `ev_ble_drop` |
|---|---|---|---|
| 空载 | 0 | 0% | 0 |
| `sniff auto` | 10（1.0 行/秒） | 4% | 0 |

μ = 25 行/秒（`EVT_MIN_GAP_MS` 40ms 的倒数）。`cap.c` 的 key 事件自己限到 5/s，
注释写着「别把 BLE 打满」。所以宪法里 ρ>1 时限流这条，在当前事件源下**没有触发路径**。
它现在的用途是看余量，不是看拥塞。要真的压到 1 以上，得先有每包一行且不限速的生产者。

## 四、带数字的待处理缺陷

### 11. auth 帧 10ms 间隔注入，30 帧里有 13 帧 ESP_ERR_NO_MEM

扫全 127 条里唯一一条红的：`flood -b 00:11:22:33:44:55 -t auth -n 30 -i 10 --yes`。

实测对照（COM4，重启后立刻跑，`internal_free` 33843 / `largest` 17408）：

| 用例 | 结果 |
|---|---|
| auth, `-i 100` | 0/30 报错 |
| auth, `-i 10` | 13/30 报错，`DONE err,13` |
| deauth / disassoc, `-i 10` | 0/30 报错 |

所以与堆无关，也不是这轮加的计数造成的（改前改后同一现象），是 auth 帧的驱动侧
管理帧缓冲在 100 帧/秒下不够。**没修**：修它要改注入节流策略（NO_MEM 重试还是降速），
属行为变更，需单独决定。

测试用例保留 `-i 10` 不改：改成 100ms 能让扫全变绿，但那条用例想测的就是高速注入，
把它改慢等于把缺陷藏起来。
