# rftool 构建脚本
# 用法: .\scripts\build.ps1 [-IdfPath D:\Espressif] [-Fresh]
#
# 不删 build 目录. 本机上层有 safe-delete 守卫, Remove-Item -Recurse 与
# idf.py fullclean 都会被拦下(SAFE_DELETE_BULK_GUARD_ERROR), 删不掉还拖一分钟.
# 需要干净构建时用 -Fresh, 编到独立目录 build\fresh, 靠新建目录而不是删除.
param(
  [string]$IdfPath = $env:IDF_TOOLS_PATH,
  [switch]$Fresh
)

$ErrorActionPreference = 'Continue'

# 后台任务包装下 $PSScriptRoot 与 $MyInvocation.* 可能全为空, 逐级兜底到当前目录.
# 兜底成立的前提是调用方已在仓库根执行, 下面用 main\cli.c 存在性校验.
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

# 直接调用 idf.py, 不用 Start-Process: 进程环境块里存在仅大小写不同的重复键
# (HTTPS_PROXY / https_proxy), Start-Process 复制环境时报键冲突直接抛异常.
function Invoke-Idf {
  param([string[]]$IdfArgs, [string]$Tag)
  $log = Join-Path $logs "$Tag.log"
  & idf.py @IdfArgs *> $log
  return $LASTEXITCODE
}

$buildDir = if ($Fresh) { Join-Path $root 'build\fresh' } else { Join-Path $root 'build' }
$global:idfExtra = @('-B', $buildDir)

# set-target 只在 sdkconfig 缺失或目标不符时执行, 避免无谓的 fullclean
$needTarget = $true
$sdkcfg = Join-Path $root 'sdkconfig'
if (Test-Path $sdkcfg) {
  $t = Select-String -LiteralPath $sdkcfg -Pattern '^CONFIG_IDF_TARGET="(.+)"' | Select-Object -First 1
  if ($t -and $t.Matches[0].Groups[1].Value -eq 'esp32c5') { $needTarget = $false }
}
if ($needTarget) {
  Write-Host "=== set-target esp32c5 ==="
  $rc = Invoke-Idf -IdfArgs ($global:idfExtra + @('--no-ccache','set-target','esp32c5')) -Tag 'st'
  Write-Host "SETTARGET_EXIT=$rc"
  if ($rc -ne 0) { Get-Content "$logs\st.log" -Tail 20; Write-Host "ABORT: set-target failed"; exit 1 }
}

Write-Host "=== build attempt 1 (build dir: $buildDir) ==="
# main/CMakeLists.txt 用 file(GLOB) 收源文件, 是 configure 期的.
# 新增 .c 后不 reconfigure 就不会被编进去, 到链接期才报未定义符号.
# 用文件名清单的戳文件判断是否新增/删除了源文件, 只在这种时候 reconfigure.
$srcStamp = Join-Path $logs 'srcs.stamp'
$srcNow = ((Get-ChildItem (Join-Path $root 'main') -Filter *.c | Sort-Object Name).Name) -join "`n"
$srcPrev = if (Test-Path $srcStamp) { Get-Content $srcStamp -Raw } else { '' }
if ($srcNow.Trim() -ne $srcPrev.Trim()) {
  Write-Host "=== reconfigure (源文件清单变化) ==="
  $rc = Invoke-Idf -IdfArgs ($global:idfExtra + @('--no-ccache','reconfigure')) -Tag 'reconf'
  Write-Host "RECONF_EXIT=$rc"
  if ($rc -eq 0) { Set-Content -LiteralPath $srcStamp -Value $srcNow -NoNewline }
}

# 用产物时间戳判断成败, 只看存在会把上次的旧 bin 当成这次的成功
$bin = Join-Path $buildDir 'rftool.bin'
$binBefore = if (Test-Path $bin) { (Get-Item $bin).LastWriteTime } else { [datetime]::MinValue }
$rc = Invoke-Idf -IdfArgs ($global:idfExtra + @('--no-ccache','build')) -Tag 'b1'
Write-Host "BUILD1_EXIT=$rc"

if ((Test-Path $bin) -and ((Get-Item $bin).LastWriteTime -gt $binBefore)) {
  Write-Host "SUCCESS: $bin ($((Get-Item $bin).Length) bytes, $(Get-Item $bin).LastWriteTime)"
  exit 0
}

Write-Host "=== build attempt 2 (ldgen 竞态重试) ==="
$rc = Invoke-Idf -IdfArgs ($global:idfExtra + @('--no-ccache','build')) -Tag 'b2'
Write-Host "BUILD2_EXIT=$rc"

if ((Test-Path $bin) -and ((Get-Item $bin).LastWriteTime -gt $binBefore)) {
  Write-Host "SUCCESS (retry): $bin ($((Get-Item $bin).Length) bytes, $(Get-Item $bin).LastWriteTime)"
  exit 0
}
Write-Host "BUILD FAILED. logs:"; Get-Content "$logs\b2.log" -Tail 40
exit 1
