# rftool 烧录脚本: 自动探测 CH343P UART0 端口 (COMx) 并 idf.py flash
# 用法: .\scripts\flash.ps1 [COM5] [-IdfPath D:\Espressif]
param(
  [string]$Port = "",
  [string]$IdfPath = $env:IDF_TOOLS_PATH
)

$ErrorActionPreference = 'Continue'

# 后台任务包装下 $PSScriptRoot 可能为空, 逐级兜底
$scriptDir = $PSScriptRoot
if (-not $scriptDir) {
  foreach ($p in @($PSCommandPath, $MyInvocation.MyCommand.Path, $MyInvocation.MyCommand.Definition)) {
    if ($p -and (Test-Path -LiteralPath $p)) { $scriptDir = Split-Path -Parent $p; break }
  }
}
$root = if ($scriptDir) { Split-Path -Parent $scriptDir } else { (Get-Location).Path }
if (-not (Test-Path -LiteralPath (Join-Path $root 'main\cli.c'))) {
  Write-Host "[!] 无法定位仓库根 (解析结果: $root). 请在仓库根目录执行本脚本."
  exit 1
}
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
Set-Location $root

$idfVersion = 'v5.5.3'
if (-not $IdfPath) { $IdfPath = 'D:\Espressif' }
$exportPs1 = Join-Path $IdfPath "frameworks\esp-idf-$idfVersion\export.ps1"
if (-not (Test-Path $exportPs1)) {
  Write-Host "[!] 未找到 ESP-IDF: $exportPs1"
  Write-Host "    请用 .\scripts\flash.ps1 -IdfPath <你的 ESP-IDF 工具目录> 指定"
  exit 1
}

$env:IDF_TOOLS_PATH = $IdfPath
$env:IDF_CCACHE_ENABLE = "0"
. $exportPs1 *> $null

# 自动探测 CH343P 端口
if (-not $Port) {
    $candidates = python -c @"
import serial.tools.list_ports as L
for p in L.comports():
    vid = (p.vid or 0)
    pid = (p.pid or 0)
    desc = (p.description or '')
    # CH343: VID=1A86, PID=55D3/55D4/55DD, 或描述含 CH343
    if vid == 0x1A86 and pid in (0x55D3, 0x55D4, 0x55DD):
        print(p.device); break
    if 'CH343' in desc.upper():
        print(p.device); break
"@
    if ($candidates) { $Port = ($candidates -split "`n")[0].Trim() }
    if (-not $Port) {
        Write-Host "[!] 未找到 CH343P 端口, 请用 .\scripts\flash.ps1 COMx 显式指定"
        Write-Host "[*] 当前可见串口:"
        python -c "import serial.tools.list_ports as L; [print(' ', p.device, p.description) for p in L.comports()]"
        exit 1
    }
}
Write-Host "[*] 使用端口: $Port"

# 直接调用 idf.py, 不用 Start-Process: 进程环境块里存在仅大小写不同的重复键
# (HTTPS_PROXY / https_proxy), Start-Process 复制环境时报键冲突直接抛异常.
$log = Join-Path $logs 'flash.log'
& idf.py --no-ccache -p $Port -b 921600 flash *> $log
$rc = $LASTEXITCODE
Write-Host "FLASH_EXIT=$rc"
if ($rc -ne 0) { Get-Content $log -Tail 30 }
exit $rc
