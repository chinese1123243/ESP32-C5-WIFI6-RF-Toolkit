# 内存预算

owner: chinese1123243
last verified: 2026-10-31（ESP-IDF v5.5.3，esp32c5，v2.4.1 基线）
applies-to: `main/` 全部模块
related checks: `health --json`、`scripts/stress.py --compare`、`idf.py size`

## 一、硬件上限与可用量

| 项 | 值 | 说明 |
|---|---|---|
| SRAM | 384 KB | SoC 上限，不是可用堆预算 |
| `SPIRAM_MALLOC_RESERVE_INTERNAL` | 98304 | 划走 96KB 给内部专用 |
| PSRAM | 8 MB | flash cache 禁用期间不可访问 |
| Flash | 16 MB | 双 OTA，app 起始 `0x20000` |

可用量受 bootloader、cache 配置、链接脚本、模组变体影响，**必须测量，不能计算**。

## 二、实测数字

开机后 `health --json` 稳定输出（2026-10-31，COM4）：

| 字段 | 值 | 备注 |
|---|---|---|
| `internal_free` | 43707 | 内部堆空闲 |
| `internal_largest` | 23552 | **最大连续块，比 free 更能说明还能不能干活** |
| `internal_frag` | 47 | 碎片率 % |
| `internal_blocks` / `internal_free_blocks` | 502 / 6 | 空闲块只有 6 个 |
| `heap_total` (含 PSRAM) | 7932472 | |
| `cli_stack_min` | 7384 | CLI 任务栈低水位 |
| `init_stack_min` | 7116 | 初始化任务栈低水位 |

对照：关掉 CSI（`CONFIG_ESP_WIFI_CSI_ENABLED=n`）时 `internal_free` 70019、`largest` 36864。
**开 CSI 的代价约 26KB free。** 这是当前 `largest` 只有 23552 的主因之一。

全量扫全（127 条命令）后：`internal_free` 43707 → 36735，`internal_largest` 23552 → 19456。
掉 7KB free、4KB 连续块，说明扫全过程有驻留或碎片累积，未定位。

## 三、目标与差距

| 指标 | 目标 | 实测 | 差距 |
|---|---|---|---|
| `internal_largest` 常态 | >64 KB | 23.5 KB | **差 40 KB，最大的一项欠账** |
| 栈安全 | 低水位 × 2~3 倍余量 | cli 7384 / init 7116 | 已达标 |

`largest` 差 40KB 不是加个字段能解决的，是内存布局问题。已知的几条约束：

- **堆上第一笔分配决定 `largest` 上限**：init_task 退出后留下等大的洞，32KB 的洞曾把
  `largest` 死死压在 32768；init 栈缩到 8KB 后才到 47104。
- **不能搬 PSRAM**：写 Flash 的缓冲（`cap.c` 4KB）与 `config.c` 静态表（`nvs_commit`
  会关 cache，别的任务此时读表就 fault）。
- **栈不要拍**：给 `health` 看 `cli_stack_min` / `init_stack_min`，跑完 127 条命令取低水位，
  按 2~3 倍余量定。实测 cli 只用 3244、init 只用 1076（早期版本）。

## 四、标定阈值的正确方法

用"占住内存压到失败"来标定，不凭感觉。先例：临时 memhog 压测得出
**BLE 只需 1.3KB 连续块、门户需要 13KB**，1664 时才失败。凭感觉写 32KB 告警线是虚报。

## 五、待办

- 定位扫全后 4KB 连续块去哪了（`internal_largest` 23552 → 19456）
- 评估 CSI 是否改为按需开启，把 26KB free 还回来
- `stress.py --compare` 做一次 9 个功能族的前后归因
