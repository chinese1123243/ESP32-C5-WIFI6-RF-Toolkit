"""界面预览截图.

用假的 AP 列表和一条假的 health JSON 走真实解析路径 (parseOutputLine),
这样截出来的不是"手工摆出来的样子", 而是真数据长什么样.

用法: python tools/ui_shot.py [输出前缀]
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "app" / "index.html").as_uri()
CHROME = Path.home() / "AppData/Local/ms-playwright/chromium-1208/chrome-win64/chrome.exe"
OUT = ROOT / ".cache"

APS = [
    ("50c7bf", "TP-LINK_5G_8821", 36, -44, "WPA2"),
    ("3c2eff", "Xiaomi_AX3000", 6, -51, "WPA3"),
    ("f4f5d8", "HUAWEI-9A3C", 1, -57, "WPA2"),
    ("bcd177", "iPhone-de-CN112", 36, -62, "WPA2"),
    ("84f3eb", "ESP32-C5-RF", 6, -38, "OPEN"),
    ("020011", "Random_Phone", 6, -70, "WPA2"),
    ("a4c138", "ChinaNet-2.4G", 11, -66, "WPA 混合"),
    ("d8f15b", "H3C_Office_5G", 149, -74, "WPA2"),
    ("1cbdba", "Xiaomi_AIoT", 11, -81, "WPA2"),
    ("6c5ab0", "CMCC-Free", 1, -77, "OPEN"),
]

HEALTH = (
    '{"ok":true,"internal_free":33203,"internal_largest":19456,"psram_free":4194304,'
    '"tasks":14,"jobs_active":2,"jobs_cap":4,"jobs_peak":3,"jobs_rejected":1,'
    '"jobs_rej_name":"sniff","out_rate_x10":128,"ev_rho_pct":37,"ev_dropped":0,'
    '"ev_pub":9021,"sniff_total":18422}'
)

PAINT_APS = """aps => {
    apList.length = 0;
    for (const [oui, ssid, ch, rssi, enc] of aps){
        apList.push({ bssid: oui.match(/../g).join(':') + ':1a:2b:3c', ssid,
                      channel: ch, rssi, enc, hidden: false, vendor: 'Unknown',
                      pmf: false,
                      caps: { akm: 'PSK', cip: 'CCMP', bw: ch >= 36 ? 80 : 20,
                              std: '11ax', wps: '0', pmfc: '0', crk: '1' } });
    }
    renderApList();
}"""


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "ui"
    OUT.mkdir(exist_ok=True)

    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=str(CHROME) if CHROME.exists() else None)
        pg = b.new_page(viewport={"width": 390, "height": 900}, device_scale_factor=3)
        pg.goto(PAGE)
        pg.wait_for_timeout(700)
        pg.evaluate("document.getElementById('splash').style.display='none'")

        # 仪表盘: 喂一条真 health JSON 走解析
        pg.evaluate("line => parseOutputLine(line)", HEALTH)
        pg.evaluate("rfOpen('dash')")
        pg.wait_for_timeout(500)
        pg.screenshot(path=str(OUT / f"{prefix}_dash.png"))

        # 扫描页: 假 AP 列表 + 筛选条
        pg.evaluate(PAINT_APS, APS)
        pg.evaluate("rfOpen('scan')")
        pg.wait_for_timeout(400)
        pg.locator("#pan-scan .blk").nth(1).screenshot(path=str(OUT / f"{prefix}_scan.png"))

        # 只筛 5G, 验证筛选条生效
        pg.evaluate("""() => {
            const b = document.querySelector('#apSort [data-band="5"]');
            b.click();
        }""")
        pg.wait_for_timeout(350)
        pg.locator("#pan-scan .blk").nth(1).screenshot(path=str(OUT / f"{prefix}_scan5g.png"))

        b.close()
    print("截图完成:", prefix)


if __name__ == "__main__":
    sys.exit(main())
