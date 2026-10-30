# Agent Instructions

This is a map, not a manual. If a line is not a command, path, number, or acceptance
criterion, it does not belong here.

## Project

ESP32-C5 双频 Wi-Fi 射频测试固件。37 条 CLI（`main/cli.c` 的 `g_cmds[]`），三种控制通道
（BLE NUS、串口 REPL、HTTP REST 22 个端点）。27 个 `.c` 共 13,613 行，27 个 `.h` 共 1,529 行。

单核 RISC-V 240MHz，384KB SRAM（硬件上限，不是可用堆预算），8MB PSRAM，16MB flash，无 MMU。
ESP-IDF v5.5.3，目标 `esp32c5`，app 起始偏移 `0x20000`。

仅用于自有网络、已获书面授权的目标、CTF 与教学研究。

## Commands

| 任务 | 命令 |
|------|------|
| 构建 | `.\scripts\build.ps1`（`-Fresh` 编到 `build\fresh`） |
| 静态尺寸 | `idf.py size` / `size-files` |
| 烧录 | `.\scripts\flash.ps1 COM4` |
| 板级自检（要串口） | `python scripts/selftest_b4.py COM4` |
| 注入引擎断言（要串口） | `python scripts/test_inject.py COM4` |
| 全命令扫描（要串口） | `python scripts/test_sweep.py COM4` |
| 内存压力仿真 | `python scripts/stress.py --compare` |
| 信道调度仿真 | `python scripts/chan_sim.py` |
| APK 校验 | `python scripts/verify_apk.py` |
| NUS 帧协议 | `node tools/nus_test.js` |
| META 协议 | `node tools/proto_test.js` |
| 固件与前端一致性 | `node tools/ui_check.js` |
| 注释质量 | `python scripts/check_slop.py` |

## External references

| 需要 | 文件 |
|------|------|
| 规划与阶段 | `ROADMAP.md` |
| 构建烧录 | `README.md` |
| 贡献与自检 | `CONTRIBUTING.md` |
| 安全取舍 | `SECURITY.md` |
| 命令注册表 | `main/cli.c` 的 `g_cmds[]` |
| 输出协议现状 | `main/cli.c` 里所有 `printf("META`（310 处） |
| 内存预算 / 射频 / HIL / 实验 / 术语 | `references/` 下同名文件 |

## Hard constraints

- 共享资源只用 `xSemaphoreCreateMutex()`，不用二值或计数信号量（无优先级继承）。
- 驱动回调与 ISR 内不碰 flash、不 `printf`、不阻塞。
- PSRAM 在 flash cache 禁用期间不可访问，OTA 与 NVS 写入路径不得查知识库。
- 发射类命令必须显式 `--yes`，缺失只回拒绝。
- 领域层不得 include 传输层头文件。
- 改 META 输出字段要同步 `app/app.js` 的解析，并跑 `node tools/ui_check.js`。
- 缓冲区按 worst case 算；调用 `malloc` 前说明生命周期与失败处理。
- 不新增依赖。
- 改分区表要提示整片 `flash`。只烧 app 会落在错误偏移。

## Autonomy

Green（做完给证据）：读文件、跑只读命令与已声明脚本、修本次文件集内的明显错误、自主联网检索。

Yellow（先给计划）：加库升库、改 CMake、改任务优先级栈大小堆策略 ISR API、改射频参数、
超出最小变更集的重构。

Red（停下问人）：改射频法规或安全限值、向外发数据、动签名密钥 bootloader OTA、
与锁定的 SDK 或数据手册相左的判断、失败会损坏硬件的动作。

Autonomous search: 本地 SDK 与锁定文件 > 乐鑫官方手册与 ESP-IDF 文档 > 厂商勘误与例程 >
同行评审论文 > 知名开源仓库。论坛博客只用于定位线索。引用留 URL、版本、访问日期、原句。
搜索不能替代上板验证；与本地事实冲突时以本地为准并记录冲突。

## Evidence gate

完成 = 每条验收标准都有本次运行产生的新鲜产物。

- 能编译：`idf.py build` 输出尾部，commit SHA，target 与 SDK 版本。
- 无静态内存回归：`idf.py size` 与 `size-files` 各区 used 与 remaining 的差分。
- 栈安全：每个任务 `uxTaskGetStackHighWaterMark()`，以及跑过的场景时长。
- 逻辑正确：主机测试命令与通过或失败输出，记录 seed 与输入。
- 硬件正确：板卡版本、固件 SHA、夹具状态、命令、串口原文、判定。
- 性能：脚本、数据集、样本量、单位、均值与最值或置信区间、前后对比表。

禁止写「应该好了」「已修复」「手动验证过」「不需要测」。跑不起来时输出：

```
STATUS: UNVERIFIED
BLOCKER: 跑不了的命令或拿不到的资源
RISK: 仍未证明的部分
```

计划不是证据。构建通过不是射频行为的证据。截图没有命令与输入输出，不算证据。

## Self-critique before done

1. 本次唯一改变的行为，以及验收它的测试。
2. 超出请求范围碰过的文件，说明理由或回滚。
3. 一个能推翻当前方案的输入或条件，及它怎么被检查。
4. 同命令、同固件、同板卡状态、同输入的前后对比。
5. 没证据就输出 `UNVERIFIED`，不写已完成。

## Key conventions

- 先定义可验证的完成标准（数字或可 `grep` 的计数），再开工。
- 纯逻辑先写 PC 仿真验证再上板。`chan_sim.py` 与 `stress.py` 是现成范式。
- 自研算法先给 oracle 上界或理论界作参照，达不到 90% 说明思路有问题。保留反例与放弃的方案。
- 新增命令要给 `test_sweep.py` 补用例，含至少一条 `reject`（喂非法参数，固件必须挡回）。
- 发现文档与代码冲突：安全法规接口以规范为准，实测内存与时序以实测为准，
  团队约定以代码既有稳定模式为准。不得静默选一方。
- 版本号单一来源 `main/version.h` 与 `app/app.js`。小补丁走 patch 位，不因改动多就跳 minor。

## Overriding a rule

推翻规则要留五样：触发条件、证据（命令输出或行号）、替代方案、谁批准、何时复检。
只有「本规则可以例外」不算推翻机制。

## Writing standard

禁「不是 A 而是 B」、三连并列、句尾伪分析、元标签、开场铺垫与结尾客套、破折号作标点、emoji。

形容词换数字：「性能显著提升」改成「p99 从 840ms 降到 120ms」。

禁用词：极大地、显著、大幅、优雅、健壮、无缝、全面、赋能、闭环、robust、seamless、leverage。

中文禁翻译腔：基于上述分析、存在着的问题、因此／从而硬接、长句不拆、「进行」「作出」掩盖动作。

中英文间加空格。同一个概念全篇一个中文词。保留安全前提与不确定度。

注释默认不写，只写 why、非显然约束、API 契约。禁复述下一行、步骤旁白、装饰分隔线。
