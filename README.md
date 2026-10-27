# RFTOOL-C5

ESP32-C5 双频无线测试工具。固件跑在板子上，通过 BLE 或串口连手机 App、上位机，覆盖侦察、捕获、注入、诱捕、测量、导出。

![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Platform: ESP32-C5](https://img.shields.io/badge/Platform-ESP32--C5-green.svg)
![ESP-IDF: v5.5](https://img.shields.io/badge/ESP--IDF-v5.5-orange.svg)

> **仅限已授权目标**：自有网络、CTF、教学研究。对未授权网络发 Deauth、伪造热点、搭钓鱼门户违反《无线电管理条例》与《网络安全法》。使用者自负法律责任。

## 目录

- [功能](#功能)
- [快速开始](#快速开始)
- [硬件](#硬件)
- [环境](#环境)
- [构建](#构建)
- [烧录](#烧录)
- [自检](#自检)
- [连接](#连接)
- [命令](#命令)
- [输出协议](#输出协议)
- [目录结构](#目录结构)
- [已知限制](#已知限制)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)
- [免责声明](#免责声明)

## 功能

37 条 CLI 命令，分七类：

| 类别 | 能力 |
|---|---|
| 侦察 | 2.4G / 5G 信道扫描，AP / 客户端 / EAPOL 三表，CSV 与 JSON 导出，BLE 扫描 |
| 捕获 | 握手四步跟踪，PMKID 提取，pcap 落盘 8MB PSRAM，离线密钥归集 |
| 注入 | Deauth、Beacon 洪泛、Probe 洪泛、原始帧构造 |
| 诱捕 | 钓鱼门户、Evil Twin、KARMA、WPA3 降级 |
| 测量 | FTM 测距、CSI 动作检测、信道占用率、Wi-Fi 6 结构解析、BLE 功率 |
| 跨射频 | 802.15.4（Zigbee / Thread）嗅探与发射 |
| 编排 | 多阶段自动化场景，事件总线回读 |

三种控制通道：BLE NUS 手机 App、串口 REPL、板载 HTTP REST。固件双区 OTA。

## 快速开始

```powershell
# 1. 构建
.\scripts\build.ps1

# 2. 烧录（COM 口按实际改）
.\scripts\flash.ps1 COM4

# 3. 板级自检
python scripts/selftest_b4.py COM4

# 4. 串口进 REPL，115200 8N1
help
sniff auto -n 50
dump aps
```

手机 App 从 [Releases](../../releases) 取 APK，或自行用 `cd app && npm run build:android` 打包。

## 硬件

| 项 | 值 |
|---|---|
| 开发板 | Waveshare ESP32-C5-WIFI6-N16R8 |
| 模组 | ESP32-C5-WROOM-1，RISC-V 240MHz，双频 Wi-Fi 6 |
| 存储 | 16MB Flash + 8MB PSRAM |
| 串口 | H2 口经 CH343P 桥 UART0，115200 8N1 |
| LED | 板载 WS2812，GPIO27 |

用 UART0 而不是原生 USB-CDC：C5 的 USB-Serial/JTAG 在 Windows 下 CDC 端点会写超时卡死，且固件早期 panic 时无人服务 CDC，串口一片空白。走 UART0 至少能看到崩溃现场。

## 环境

| 项 | 版本 |
|---|---|
| ESP-IDF | v5.5（推荐 v5.5.3） |
| Python | 3.10+，需 `pyserial` |
| Node.js | 18+，构建 App 用 |
| Android SDK | API 34，构建 APK 用 |

## 构建

```powershell
# 脚本方式（自动定位 IDF、清理构建、竞态重试）
.\scripts\build.ps1
.\scripts\build.ps1 -IdfPath D:\Espressif
```

```powershell
# 手动方式
$env:IDF_TOOLS_PATH = "D:\Espressif"
. "D:\Espressif\frameworks\esp-idf-v5.5.3\export.ps1"
idf.py build
```

编译可能卡住：`riscv32-esp-elf-gcc` 或 `collect2` 挂几分钟 CPU 不动。杀掉重跑 `ninja -C build -j 1` 即可，已编好的目标不会重来。

产物 `build/rftool.bin`，约 1.6MB，OTA 槽 2.5MB，余量 40%。

## 烧录

```powershell
.\scripts\flash.ps1 COM4
# 或
idf.py --no-ccache -p COM4 -b 921600 flash
```

分区表是双 OTA，app 起始偏移 `0x20000`。从 1.5.x 升上来必须整片 `flash`，只烧 app 会落在错误偏移。

## 自检

```powershell
python scripts/selftest_b4.py COM4          # 板级 12 项功能自检
python scripts/test_inject.py COM4          # 注入引擎 20 项断言（含 30s 浸泡）
python scripts/test_sweep.py COM4           # 82 条命令全量扫描，找会打板或卡死的命令
python scripts/verify_apk.py                # 校验 APK 内嵌前端与源文件一致
```

`test_sweep` 的每条用例带「预期」字段：留空表示应当正常执行，`"reject"` 表示故意喂非法参数或前置条件未满足，固件必须挡回去。挡不住就是测试失败。只看「命令有没有崩」抓不到「非法参数被默默接受」，也抓不到测试预期本身写错了。

错误行在协议里分三类，`test_sweep` 分开统计：致命（崩、断言、没内存）、入参拒绝（校验挡回，属预期）、未知（新出现的消息，提示去补归类表）。

打包 APK 必须走 package.json 里的流程，不能只跑 gradlew：

```powershell
cd app && npm run build:android
```

`app/android/app/src/main/assets/public/` 与 `app/www/` 在 .gitignore 里，不先同步就打，gradle 会判定资源任务 up-to-date，打出来的是上一版前端（实测过一次，app.js 少 3660 字节）。打完用 `scripts/verify_apk.py` 兜一道。

## 连接

### 手机 App（BLE）

广播名 `rftool-c5`，服务 UUID `6e400001-b5a3-f393-e0a9-e50e24dcca9e`（NUS）。App 里点「搜索板子」扫描并连接。

### 串口 REPL

任意串口工具，115200 8N1，回车换行。输入 `help` 看命令。

### 板载 HTTP

```text
http start --ssid rftool-ap --pass 12345678
```

手机连该热点后访问 `http://192.168.71.1`。接口要 `api_token`，用 `config get api_token` 查。

## 命令

`help` 列出全部命令，`<命令> --help` 看参数。

| 类别 | 命令 |
|---|---|
| 侦察 | `sniff <ch\|auto> [-n N] [-d ms]`、`dump <aps\|clients\|eapols\|all>`、`blescan`、`export <csv\|json>` |
| 捕获 | `hs [complete\|clear\|22000\|selftest]`、`cap <start\|stop\|info\|keys\|read\|hdr\|clear>`、`pmkid <watch\|status\|clear>` |
| 注入 | `deauth -b <bssid> [-s <sta>] [-n N] [-r R] [-i ms]`、`beaconflood -p <prefix>`、`probeflood`、`raw <tx\|deauth\|auth\|assoc\|beacon\|proberesp>` |
| 诱捕 | `phish <start\|stop\|status\|stations\|creds\|html>`、`eviltwin <clone\|stop>`、`karma`、`downgrade <ssid>` |
| 测量 | `ftm <bssid\|status>`、`locate <mac> [秒]\|status\|export`、`ble <power>`、`bleadv`、`airtime`、`wifi6`、`csi <start\|stop\|stats\|raw\|selftest>` |
| 跨射频 | `zbsniff <ch 11-26>\|stop\|status\|dump\|clear`、`zbtx <beacon\|beaconreq\|data\|raw\|replay\|flood\|stop\|stats>` |
| 编排 | `scenario <survey\|handshake\|pmf\|stop\|status>`、`events [n]` |
| 系统 | `config <set\|get\|list\|reset>`、`log`、`health`、`ota <status\|confirm\|rollback\|url\|reboot>`、`http`、`stop`、`version` |

全局开关：`--json` 让 `status`、`health`、`version` 输出 JSON；`--force` 跳过 PMF 拦截；`--yes` 确认危险命令。

`deauth` 默认拒绝两类目标：不在扫描表里的、PMF 必需的。加 `--force` 会跳过全部校验，包括这两类。

## 输出协议

命令输出两种行：

- 文本行：给人看，`dump aps` 的表格就是。
- `META,...` 行：给程序解析，逗号分隔的键值对。

```text
META,WIFI,STATUS,state,SNIFF,channel,6,auto_ch,1,sniff_total,1024,...
META,EAPOL,DETECTED,src,aa:bb:cc:dd:ee:ff,dst,11:22:33:44:55:66
META,SCENARIO,PHASE,phase,handshake,round,2,target,4c:b7:e0:16:28:29
```

App 用 `META` 行更新界面，不解析文本表格。加新命令时保持这个约定，否则 App 侧解析要跟着改。

## 目录结构

```
main/               固件源码
app/                Android App（index.html + app.js，Capacitor 打包）
docs/               使用指南
scripts/            构建、烧录、自检、算法基准
tools/              离线校验：NUS 帧协议、app.js 与 index.html 一致性
build/              编译产物（不入库）
logs/               构建与测试日志（不入库）
partitions.csv      分区表
sdkconfig.defaults  编译配置默认值（入库，sdkconfig 不入库）
```

## 已知限制

- 单射频。嗅探、注入、门户三者互斥，开一个会停另一个。
- 802.15.4 已在 `sdkconfig.defaults` 中启用（`CONFIG_IEEE802154_ENABLED=y`）。它与 BLE 广播争同一块内部 RAM，同时开启时 BLE 广播可能因 `BLE_ERR_MEM_CAPACITY` 起不来。要用 Zigbee / Thread 嗅探，需接受 BLE 不可用。
- `ota url` 只支持 `http://`。不带 TLS 是刻意的：mbedtls 的静态缓冲会挤掉 NimBLE 需要的内部 RAM。
- 未做镜像签名。OTA 只校验镜像结构，防不住换一份合法但非官方的固件。要防这个得启用 Secure Boot v2。

## 路线图

见 [ROADMAP.md](ROADMAP.md)。当前主线是架构治理：射频仲裁器、HAL 化与 CI、Job 户籍账本，之后是可观测性与目标设备画像。

规划讨论进 [Issues](../../issues)，带 `roadmap` 标签。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交前跑 `scripts/test_sweep.py`，安全相关问题走 [SECURITY.md](SECURITY.md) 的私下报告流程。

## 许可证

GPL-3.0。见 [LICENSE](LICENSE)。

## 免责声明

- 只对自有或已获书面授权的网络使用。
- 发射功率、频段须符合当地无线电管理规定。
- 抓到的握手、凭据、pcap 属敏感数据，用完删除。
- 本项目不提供任何规避执法或入侵他人网络的用途。
