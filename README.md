# rftool — ESP32-C5 Wi-Fi 无线电工具

> ⚠️ **仅用于已授权的安全测试、自有网络、CTF 竞赛与安全研究。** 对未授权网络发起 deauth/beacon flood 等攻击属违法行为。详见 [docs/使用说明.md](docs/使用说明.md#9-伦理与法律)。

基于 Waveshare **ESP32-C5-WIFI6-KIT** 开发板的 Wi-Fi 无线电工具。ESP-IDF v5.5.3 + 自建 fgets REPL (argtable3 参数解析), 覆盖嗅探/deauth/beacon flood/probe flood 四类功能。

## 功能

| 命令 | 说明 | 示例 |
|---|---|---|
| `sniff` | 802.11 promiscuous 嗅探, PKT 摘要 + HEX 行 → pcap | `sniff 6 -n 50` |
| `deauth` | Deauth 帧注入 (双向欺骗) | `deauth -b aa:bb:cc:dd:ee:ff --count 10` |
| `beaconflood` | 伪造随机 beacon 洪水 | `beaconflood -p TESTAP --count 100` |
| `probeflood` | Probe request 洪水 | `probeflood --count 200` |
| `status` | 查看状态/计数 | `status` |
| `stop` | 停止当前嗅探/注入 | `stop` |
| `help` | 中英双语命令列表 | `help` |

## RGB LED 状态指示

板载 WS2812 (GPIO27) 实时反映固件状态:

| 颜色 | 状态 | 含义 |
|---|---|---|
| 紫色 | BOOT | 启动中, Wi-Fi 初始化 |
| 蓝色 | IDLE | 空闲待命 |
| 亮绿 | SNIFF | 嗅探中, 每收到一帧闪一下 |
| 亮红 | INJECT | 注入中, 每 5 帧闪一下 |
| 最亮红 | ERROR | 出错 |

## 目录

```
rftool/
├── main/
│   ├── main.c            # app_main: 三层任务隔离 (init→cli)
│   ├── cli.c/h           # fgets+dispatch REPL + argtable3 命令
│   ├── wifi_attack.c/h   # 嗅探 / deauth / beacon / probe flood
│   ├── rgb_led.c/h       # WS2812 RMT 驱动 + 状态指示
│   └── radio_common.c/h  # MAC/hex/pcap 辅助 + 802.11 帧构造器
├── scripts/
│   ├── build.ps1         # 编译脚本 (支持重试)
│   ├── flash.ps1         # 自动探测 CH343P 端口烧录
│   ├── tui.py            # 交互式终端 (推荐, 支持命令历史/彩色/pcap 录包)
│   ├── monitor.py        # 串口→pcap 转换工具
│   └── test_commands.py  # 自动化自检脚本
├── docs/使用说明.md      # 完整手册 + 实战场景
├── sdkconfig.defaults
└── CMakeLists.txt
```

## 快速开始

```powershell
# 前置: ESP-IDF v5.5.3 已装于 D:\Espressif
cd C:\Users\CN112\Desktop\esp32c5\rftool

# 1. 编译
.\scripts\build.ps1

# 2. 烧录 (CH343P H2 口, 自动探测 COM)
.\scripts\flash.ps1

# 3. 连接 (推荐 TUI)
D:\Python\python.exe .\scripts\tui.py COM4

# 带 pcap 录包
D:\Python\python.exe .\scripts\tui.py COM4 -o capture.pcap
```

## 控制台输出约定 (机器可解析)

```
META,WIFI,<key>,<value>,...     # 状态/事件/错误
PKT,WIFI,<type>,<subtype>,<len>,<rssi>,<src>,<dst>,<bssid>,<ssid>
HEX,<hex bytes space-separated>  # raw 802.11 (无 FCS, 供 host 重组 pcap)
```

TUI / monitor.py 把 `PKT` + 配对 `HEX` 组装为 pcap (DLT=105), Wireshark 直接打开。

## 硬件要点

- **控制台 UART0 via CH343P (H2 口)**: 原生 USB-Serial/JTAG (H1) 在 Windows 下 CDC 端点会卡死, 故禁用。
- **WS2812 在 GPIO27**: strapping 脚仅在复位时采样, 运行时作 GPIO 输出无碍。
- **仅用 STA + 802.11_tx**: 关闭 softap / BT / 802.15.4 节省 flash/RAM。

## 架构决策

- **fgets REPL 替代 esp_console**: esp_console 内部 linenoise + vfprintf 栈消耗不可控 (即使 128KB 任务栈仍溢出)。自建 fgets + argtable3 分发, 32KB 栈足够, 功能不缩水。
- **三层任务隔离**: main_task(16KB) → init_task(32KB, Wi-Fi init) → cli_task(32KB, REPL 常驻), 避免初始化栈叠加。
- **安全停止**: promiscuous 回调运行在 wifi task 上下文, 直接调 set_promiscuous(false) 可能死锁。回调只递减计数 + 唤醒独立 stopper task。

## 许可与免责

本工具仅供授权安全测试与教育。使用者须确保对目标拥有所有权或书面授权, 并遵守当地无线电管理法规。作者不对滥用行为负责。