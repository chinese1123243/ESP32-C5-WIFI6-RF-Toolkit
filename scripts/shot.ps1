# shot.ps1 — 批量截图（每次用独立 user-data-dir，并强制等待）
param(
    [string]$AppDir = "C:/Users/CN112/Desktop/ESP32-C5-WIFI6-RF-Toolkit/app",
    [string]$OutDir = "C:/Users/CN112/Desktop/_preview",
    [string[]]$Tabs = @("dash","scan","sniff","deauth","beacon","probe","downgrade","phish","adv","tools","data","raw")
)
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

foreach ($t in $Tabs) {
    $png = Join-Path $OutDir ("a_" + $t + ".png")
    if (Test-Path $png) { Remove-Item $png -Force }
    $url = "file:///" + $AppDir + "/_fr_" + $t + ".html"
    $prof = Join-Path $OutDir ("prof_" + $t)
    $argList = @(
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-first-run",
        "--disable-extensions",
        "--user-data-dir=$prof",
        "--hide-scrollbars",
        "--window-size=402,860",
        "--screenshot=$png",
        "--virtual-time-budget=2800",
        $url
    )
    $p = Start-Process -FilePath $edge -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    $ok = Test-Path $png
    Write-Output ("{0,-10} exit={1} shot={2}" -f $t, $p.ExitCode, $ok)
    if ($ok) {
        $sz = (Get-Item $png).Length
        Write-Output ("           size={0}" -f $sz)
    }
}
