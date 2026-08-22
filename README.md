# rftool — ESP32-C5 Wi-Fi 无线电攻击工具

> ⚠️ **仅用于已授权的安全测试、自有网络、CTF 竞赛与安全研究。** 对未授权网络发起 deauth/beacon flood 等攻击属违法行为。详见 [docs/使用说明.md](docs/使用说明.md#9-伦理与法律)。

基于 Waveshare **ESP32-C5-WIFI6-KIT** 开发板的 Wi-Fi 无线电工具（ESP-IDF v5.5.3 + 自研 fgets REPL + argtable3），覆盖 **嗅探 / 注入 / 追踪导出 / HTTP 远程控制 / TUI 交互** 五大类功能。

## 功能一览

| 类别 | 命令 | 说明 | 示例 |
|------|------|------|------|
| **嗅探** | sniff | 802.11 promiscuous 单信道嗅探（PKT+HEX） | sniff 6 -n 50 |
| **嗅探** | sniff auto | 自动轮询 1-13 信道（--dwell 调驻留时间） | sniff auto --dwell 300 |
| **注入** | deauth | 双向 Deauth 帧注入（踢设备下线） | deauth -b aa:bb:cc:dd:ee:ff -n 10 |
| **注入** | eaconflood | 伪造随机 SSID+MAC 的 Beacon 洪水 | eaconflood -p FAKE -n 100 |
| **注入** | probeflood | 广播 Probe Request 洪水 | probeflood -n 200 |
| **追踪导出** | dump | 打印 AP / Client / EAPOL 追踪表 | dump aps / dump all |
| **追踪导出** | xport | 导出为 CSV / JSON（离线分析） | xport csv / xport json |
| **远程控制** | http | 启动 SoftAP + HTTP REST API 服务器 | http start / http stop |
| **通用** | status | 查看状态 + 追踪表计数 | status |
| **通用** | stop | 停止当前嗅探 / 注入 / 自动轮询 | stop |
| **通用** | help | 命令列表 + <cmd> --help 详情 | help |

板级测试报告（扩展 14/14 全通过）：
- sniff auto 200ms 轮询 3s → 捕获 13 个不同 AP
- export json → 合法 JSON，含 bssid/ssid/channel/rssi/encryption/vendor
- http start → 切换 APSTA，SoftAP 192.168.71.1，HTTP 服务启动
- dump aps → 13 条 AP 记录（含厂商 / RSSI / WPA2 / PMF / beacon 计数）

## HTTP REST API

启动 http start 后连接 AP **
ftool-AP**（默认无密码），浏览器访问 http://192.168.71.1 即可远程控制。端点清单：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | / | 交互式 Web 控制页 |
| GET | /api/status | 状态 + 追踪表计数（JSON） |
| POST | /api/sniff/start | 启动嗅探 { "channel":6, "count":0 } |
| POST | /api/sniff/auto | 自动信道轮询 { "dwell_ms":300 } |
| POST | /api/sniff/stop | 停止嗅探 |
| POST | /api/deauth/start | Deauth 注入 |
| POST | /api/beaconflood/start | Beacon 洪水 |
| POST | /api/probeflood/start | Probe 洪水 |
| POST | /api/inject/stop | 停止注入 |
| GET | /api/db/aps | AP 追踪表 JSON |
| GET | /api/db/clients | Client 追踪表 JSON |
| GET | /api/db/eapols | EAPOL 握手记录 JSON |
| GET | /api/export/csv | 三表 CSV（下载） |
| GET | /api/export/json | 三表 JSON（下载） |

## RGB LED 状态指示

板载 WS2812 (GPIO27) 实时反映固件状态：

| 颜色 | 状态 | 含义 |
|---|---|---|
| 紫色 | BOOT | 启动中，Wi-Fi 初始化 |
| 蓝色 | IDLE | 空闲待命 |
| 亮绿 | SNIFF | 嗅探中，每帧闪一下 |
| 亮红 | INJECT | 注入中，每 5 帧闪一下 |
| 最亮红 | ERROR | 出错 |

## 目录结构

`
rftool/
├── main/
│   ├── main.c             # app_main: 三层任务隔离 (main→init→cli)
│   ├── cli.c/h            # fgets+dispatch REPL + argtable3 命令
│   ├── wifi_attack.c/h    # 嗅探 / deauth / beacon / probe / auto rotate
│   ├── wifi_db.c/h        # AP / Client / EAPOL 哈希追踪 + OUI 厂商识别
│   ├── http_server.c/h    # SoftAP + HTTP REST API (esp_http_server)
│   ├── rgb_led.c/h        # WS2812 RMT 驱动 + 状态指示
│   └── radio_common.c/h   # MAC/hex/pcap 辅助 + 802.11 帧构造器
├── scripts/
│   ├── build.ps1          # 编译脚本（支持重试 + 自动 source idf.ps1）
│   ├── flash.ps1          # 自动探测 CH343P 端口 + 烧录
│   ├── tui.py             # 交互式终端（命令历史/彩色/pcap/本地命令）
│   ├── monitor.py         # 串口 → pcap 转换工具
│   └── test_commands.py   # 自动化板级自检脚本
├── docs/使用说明.md       # 完整手册 + 8 个实战场景
├── sdkconfig.defaults
└── CMakeLists.txt
`

## 快速开始

`powershell
# 前置: ESP-IDF v5.5.3 安装于 D:\Espressif ; Python 3.14 @ D:\Python\python.exe
cd C:\Users\CN112\Desktop\esp32c5\rftool

# 1. 编译 (~2 分钟)
.\scripts\build.ps1

# 2. 烧录 (CH343P H2 口, 自动探测 COM)
.\scripts\flash.ps1

# 3. 连接 (推荐 TUI)
D:\Python\python.exe .\scripts\tui.py COM4

# 或带 pcap 录包:
D:\Python\python.exe .\scripts\tui.py COM4 -o capture.pcap
`

连接后：
`
rftool> help                    # 查看命令
rftool> sniff auto --dwell 200  # 200ms 轮询 1-13 信道
rftool> status                  # 查看抓包进度 / DB 计数
rftool> dump aps                # 打印 AP 列表
rftool> export json             # 导出 JSON
rftool> http start              # 启动 HTTP 远程控制
rftool> stop                    # 停止一切操作
`

TUI 本地命令（不需要发给板子）：
`
/display db       → 美化展示追踪表
/display hist     → 展示抓包直方图
/http open        → 用默认浏览器打开 http://192.168.71.1
/export <path>    → 导出历史到本地文件
/help             → TUI 本地命令帮助
Ctrl+C            → 退出
`

## 控制台输出约定 (机器可解析)

`
META,WIFI,<key>,<value>,...        # 状态/事件/错误
META,HTTP,<key>,<value>,...        # HTTP 子系统状态
PKT,WIFI,<type>,<subtype>,<len>,<rssi>,<src>,<dst>,<bssid>,<ssid>
HEX,<hex bytes space-separated>    # raw 802.11 (无 FCS, 供 host 重组 pcap)
AP,<bssid>,<ssid>,ch<>,rssi<>,...  # dump aps 行
CLIENT,<mac>,<bssid>,rssi<>,...    # dump clients 行
EAPOL,<src>,<dst>,...              # dump eapols 行
`

TUI / monitor.py 把 PKT + 配对 HEX 组装为 pcap (DLT=105)，可直接用 Wireshark 打开。

## 架构决策 & 调优

1. **fgets REPL 替代 esp_console**：esp_console 内部 linenoise + vfprintf 栈消耗不可控（128KB 栈都溢出）。自研 fgets + argtable3 分发，32KB cli_task 栈足够。
2. **三层任务栈隔离**：main_task(16KB) → init_task(32KB, Wi-Fi 初始化) → cli_task(32KB, REPL 常驻)，分步加载避免初始化栈叠加。
3. **注入效率优化**：--interval 0ms（默认）+ 	askYIELD() 主动让出 CPU，Beacon Flood 可达约 **50 fps**。
4. **PSRAM 哈希数据库**：wifi_db 使用 heap_caps_malloc(MALLOC_CAP_SPIRAM) 在 8MB PSRAM 上分配，支持数百个 AP/Client/EAPOL 追踪。
5. **安全停止**：promiscuous 回调运行在 Wi-Fi 驱动任务上下文，不直接调 set_promiscuous(false)，用原子计数 + stop_task 异步停止，避免死锁。
6. **HTTP API + SoftAP**：Wi-Fi 切 APSTA 模式，SoftAP 默认 SSID 
ftool-AP（IP 192.168.71.1），DHCP 分配 192.168.71.2-10；同时保留 STA 以嗅探/注入。

## 硬件要点

- **控制台 UART0 via CH343P (H2 口)**：原生 USB-Serial/JTAG (H1) 在 Windows 下 CDC 端点会卡死，故禁用；波特率 115200 8N1。
- **WS2812 在 GPIO27**：strapping 脚仅在复位时采样，运行时作 GPIO 输出无碍。
- **ESP32-C5-WROOM-1**：RISC-V 240MHz，16MB Flash + 8MB PSRAM，全部可用。

## 硬件 & 软件环境

| 项目 | 版本/配置 |
|------|-----------|
| 开发板 | Waveshare ESP32-C5-WIFI6-KIT |
| 模组 | ESP32-C5-WROOM-1（16MB Flash + 8MB PSRAM） |
| ESP-IDF | v5.5.3 |
| Python 全局 | 3.14.3 @ D:\Python\python.exe |
| ESP-IDF Python env | idf5.5_py3.14_env |
| 桥接芯片 | CH343P（UART0 → COM4，115200 8N1） |

## 许可与免责

本工具仅供授权安全测试与教育。使用者须确保对目标拥有所有权或书面授权，并遵守当地无线电管理法规。作者不对滥用行为负责。
