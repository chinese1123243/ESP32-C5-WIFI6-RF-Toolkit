# rftool 烧录: 自动探测 CH343P UART0 端口 (COMx) 并 idf.py flash
# 用法: .\scripts\flash.ps1 [COM5]
param([string]$Port = "")

$env:IDF_TOOLS_PATH = "D:\Espressif"
$env:IDF_CCACHE_ENABLE = "0"
. D:\Espressif\frameworks\esp-idf-v5.5.3\export.ps1 *> $null

$root = "C:\Users\CN112\Desktop\esp32c5\rftool"
Set-Location $root
$idfpy = "D:\Espressif\bin\idf.py.bat"

# 自动探测 CH343P 端口
if (-not $Port) {
    $candidates = & D:\Espressif\python_env\idf5.5_py3.14_env\Scripts\python.exe -c @"
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
        & D:\Espressif\python_env\idf5.5_py3.14_env\Scripts\python.exe -c "import serial.tools.list_ports as L; [print(' ', p.device, p.description) for p in L.comports()]"
        exit 1
    }
}
Write-Host "[*] 使用端口: $Port"

$p = Start-Process -FilePath $idfpy -ArgumentList "--no-ccache","-p",$Port,"-b","921600","flash" -Wait -PassThru -NoNewWindow
Write-Host "FLASH_EXIT=$($p.ExitCode)"
exit $p.ExitCode
