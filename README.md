# RFTOOL-C5

ESP32-C5 双频无线测试工具。固件跑在板子上，通过 BLE 或串口连手机 App、上位机，覆盖侦察、捕获、注入、诱捕、导出。

> 仅限已授权目标：自有网络、CTF、教学研究。对未授权网络发 Deauth、伪造热点、搭钓鱼门户违反《无线电管理条例》与《网络安全法》。使用者自负法律责任。

## 文档

| 文件 | 内容 |
|---|---|
| `README.md` | 硬件、构建、烧录、连接、命令速查 |
| `docs/使用指南.md` | App 导航、各功能操作流程、常见问题 |

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
| ESP-IDF | v5.5.3（本机 `D:\Espressif\frameworks\esp-idf-v5.5.3`） |
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

烧完跑板级自检：

```powershell
python scripts/selftest_b4.py COM4          # 板级 12 项功能自检
python scripts/test_inject.py COM4          # 注入引擎 20 项断言 (含 30s 浸泡)
python scripts/test_sweep.py COM4           # 82 条命令全量扫描, 找会打板/卡死的命令
python scripts/verify_apk.py                # 校验 APK 内嵌前端与源文件一致
```

`test_sweep` 的每条用例带「预期」字段：留空=应当正常执行，`"reject"`=故意喂非法参数或前置条件未满足，固件必须挡回去。挡不住就是测试失败。光看「命令有没有崩」抓不到「非法参数被默默接受」，也抓不到测试预期本身写错了。

错误行在协议里分三类，`test_sweep` 分开统计：致命（崩 / 断言 / 没内存）、入参拒绝（校验挡回，属预期）、未知（新出现的消息，提示去补归类表）。

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

## 命令速查

`help` 列出全部 31 条，`<命令> --help` 看参数。

| 类别 | 命令 |
|---|---|
| 侦察 | `sniff <ch\|auto> [-n N] [-d ms]`、`dump <aps\|clients\|eapols\|all>`、`blescan`、`export <csv\|json>` |
| 捕获 | `hs [complete\|clear\|22000\|selftest]`、`cap <start\|stop\|info\|keys\|read\|hdr\|clear>`、`pmkid <watch\|status\|clear>` |
| 注入 | `deauth -b <bssid> [-s <sta>] [-n N] [-r R] [-i ms]`、`beaconflood -p <prefix>`、`probeflood`、`raw <tx\|deauth\|auth\|assoc\|beacon\|proberesp>` |
| 诱捕 | `phish <start\|stop\|status\|stations\|creds\|html>`、`eviltwin <clone\|stop>`、`karma`、`downgrade <ssid>` |
| 测量 | `ftm <bssid\|status>`、`locate <mac> [秒]\|status\|export`、`ble <power>`、`bleadv`、`zbsniff` |
| 编排 | `scenario <survey\|handshake\|pmf\|stop\|status>`、`events [n]` |
| 系统 | `config <set\|get\|list\|reset>`、`log`、`health`、`ota <status\|confirm\|rollback\|url\|reboot>`、`http`、`stop`、`version` |

全局开关：`--json` 让 `status`、`health`、`version` 输出 JSON；`--force` 跳过 PMF 拦截；`--yes` 确认危险命令。

`deauth` 默认拒绝两类目标：不在扫描表里的、PMF 必需的。要跳过检查加 `--force`，此时不再校验任何条件。

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

## 目录

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
- 802.15.4 默认关闭。C5 上它和 BLE 广播抢同一块内部 RAM，同时开启时 BLE 广播会因 `BLE_ERR_MEM_CAPACITY` 起不来。要用 Zigbee/Thread 嗅探，改 `CONFIG_IEEE802154_ENABLED=y` 重编，并接受 BLE 不可用。
- `ota url` 只支持 `http://`。不带 TLS 是刻意的：mbedtls 的静态缓冲会挤掉 NimBLE 需要的内部 RAM。
- 未做镜像签名。OTA 只校验镜像结构，防不住换一份合法但非官方的固件。要防这个得启用 Secure Boot v2。

## 合规

- 只对自有或已获书面授权的网络使用。
- 发射功率、频段须符合当地无线电管理规定。
- 抓到的握手、凭据、pcap 属敏感数据，用完删除。
- 本项目不提供任何规避执法或入侵他人网络的用途。
