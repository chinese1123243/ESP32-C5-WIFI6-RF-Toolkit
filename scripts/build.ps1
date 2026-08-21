# rftool 构建: 清理构建 + ldgen 竞态重试 (沿用 bench 的 robust 模式)
# 用法: .\scripts\build.ps1
$ErrorActionPreference = 'Continue'
$env:IDF_TOOLS_PATH = "D:\Espressif"
$env:IDF_CCACHE_ENABLE = "0"
. D:\Espressif\frameworks\esp-idf-v5.5.3\export.ps1 *> $null

$root = "C:\Users\CN112\Desktop\esp32c5\rftool"
$logs = "$root\logs"
New-Item -ItemType Directory -Path $logs -Force | Out-Null
Set-Location $root
$idfpy = "D:\Espressif\bin\idf.py.bat"

Get-Process ninja,riscv32-esp-elf-gcc,cc1,ccache,ld -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
try { Add-MpPreference -ExclusionPath $root -ErrorAction Stop } catch {}

if (Test-Path "$root\build") {
  Remove-Item -Recurse -Force "$root\build" -ErrorAction SilentlyContinue
  Write-Host "[*] build dir wiped"
}

Write-Host "=== set-target esp32c5 ==="
$p0 = Start-Process -FilePath $idfpy -ArgumentList "--no-ccache","set-target","esp32c5" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\st.out" -RedirectStandardError "$logs\st.err"
Write-Host "SETTARGET_EXIT=$($p0.ExitCode)"
if ($p0.ExitCode -ne 0) { Get-Content "$logs\st.err" -Tail 20; Write-Host "ABORT: set-target failed"; exit 1 }

Write-Host "=== build attempt 1 ==="
$p1 = Start-Process -FilePath $idfpy -ArgumentList "--no-ccache","build" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\b1.out" -RedirectStandardError "$logs\b1.err"
Write-Host "BUILD1_EXIT=$($p1.ExitCode)"

$bin = "$root\build\rftool.bin"
if (Test-Path $bin) { Write-Host "SUCCESS: $bin ($((Get-Item $bin).Length) bytes)"; exit 0 }

Write-Host "=== build attempt 2 (ldgen 竞态重试) ==="
$p2 = Start-Process -FilePath $idfpy -ArgumentList "--no-ccache","build" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$logs\b2.out" -RedirectStandardError "$logs\b2.err"
Write-Host "BUILD2_EXIT=$($p2.ExitCode)"

if (Test-Path $bin) { Write-Host "SUCCESS (retry): $bin ($((Get-Item $bin).Length) bytes)"; exit 0 }
Write-Host "BUILD FAILED. logs:"; Get-Content "$logs\b2.err" -Tail 30
exit 1
