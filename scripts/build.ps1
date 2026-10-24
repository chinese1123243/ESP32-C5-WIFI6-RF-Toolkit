# rftool 构建脚本 (清理构建 + ldgen 竞态重试)
# 用法: .\scripts\build.ps1 [-IdfPath D:\Espressif]
param([string]$IdfPath = $env:IDF_TOOLS_PATH)

$ErrorActionPreference = 'Continue'

# 仓库根目录 = 本脚本的上一级
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
Set-Location $root

# 定位 ESP-IDF: 优先参数 / 环境变量, 其次常见默认位置
$idfVersion = 'v5.5.3'
if (-not $IdfPath) { $IdfPath = 'D:\Espressif' }
$exportPs1 = Join-Path $IdfPath "frameworks\esp-idf-$idfVersion\export.ps1"
if (-not (Test-Path $exportPs1)) {
  Write-Host "[!] 未找到 ESP-IDF: $exportPs1"
  Write-Host "    请用 .\scripts\build.ps1 -IdfPath <你的 ESP-IDF 工具目录> 指定"
  exit 1
}

$env:IDF_TOOLS_PATH = $IdfPath
$env:IDF_CCACHE_ENABLE = "0"
. $exportPs1 *> $null

Get-Process ninja,riscv32-esp-elf-gcc,cc1,ccache,ld -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
try { Add-MpPreference -ExclusionPath $root -ErrorAction Stop } catch {}

if (Test-Path "$root\build") {
  Remove-Item -Recurse -Force "$root\build" -ErrorAction SilentlyContinue
  Write-Host "[*] build dir wiped"
}

Write-Host "=== set-target esp32c5 ==="
$p0 = Start-Process -FilePath "idf.py" -ArgumentList "--no-ccache","set-target","esp32c5" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\st.out" -RedirectStandardError "$logs\st.err"
Write-Host "SETTARGET_EXIT=$($p0.ExitCode)"
if ($p0.ExitCode -ne 0) { Get-Content "$logs\st.err" -Tail 20; Write-Host "ABORT: set-target failed"; exit 1 }

Write-Host "=== build attempt 1 ==="
$p1 = Start-Process -FilePath "idf.py" -ArgumentList "--no-ccache","build" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\b1.out" -RedirectStandardError "$logs\b1.err"
Write-Host "BUILD1_EXIT=$($p1.ExitCode)"

$bin = "$root\build\rftool.bin"
if (Test-Path $bin) { Write-Host "SUCCESS: $bin ($((Get-Item $bin).Length) bytes)"; exit 0 }

Write-Host "=== build attempt 2 (ldgen 竞态重试) ==="
$p2 = Start-Process -FilePath "idf.py" -ArgumentList "--no-ccache","build" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\b2.out" -RedirectStandardError "$logs\b2.err"
Write-Host "BUILD2_EXIT=$($p2.ExitCode)"

if (Test-Path $bin) { Write-Host "SUCCESS (retry): $bin ($((Get-Item $bin).Length) bytes)"; exit 0 }
Write-Host "BUILD FAILED. logs:"; Get-Content "$logs\b2.err" -Tail 30
exit 1
