"""给图表页拍截图, 用构造的 AP 数据 (不连板).

    python tools/chart_shot.py [输出图]

只做视觉检查: 打开 app/index.html, 灌入假 AP, 切到图表页截图.
OUI 从 App 自带表里现取, 顺带验证厂商映射本身.
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PAGE = (ROOT / "app" / "index.html").as_uri()
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".cache" / "chart.png"

# (厂商, SSID, 信道, RSSI, 加密)
APS = [
    ("TP-Link", "TP-LINK_5G_8821", 36, -48, "WPA2"),
    ("TP-Link", "TP-LINK_2.4G", 6, -52, "WPA2"),
    ("TP-Link", "TP-LINK_Guest", 1, -61, "OPEN"),
    ("TP-Link", "TP-LINK_MESH", 44, -61, "WPA3"),
    ("Xiaomi", "Xiaomi_AX3000", 11, -58, "WPA3"),
    ("Xiaomi", "Xiaomi_IoT", 6, -83, "WPA2"),
    ("Huawei", "HUAWEI-9A3C", 1, -44, "WPA2"),
    ("Huawei", "HUAWEI-9A3C_5G", 157, -55, "WPA2"),
    ("Huawei", "HUAWEI-Guest", 6, -59, "OPEN"),
    ("Huawei", "CMCC-8821", 11, -70, "WPA2"),
    ("Huawei", "ChinaNet-8Kzq", 3, -81, "WPA2"),
    ("Apple", "iPhone-de-CN112", 36, -40, "WPA2"),
    ("Apple", "iPhone-hotspot", 149, -69, "WPA3"),
    ("Samsung", "Samsung_Galaxy", 11, -66, "WPA2"),
    ("Espressif", "ESP32-C5-RF", 6, -35, "OPEN"),
    ("Espressif", "ESP_1A2B3C", 1, -91, "WPA2"),
    ("Cisco", "Corp-WiFi", 100, -75, "WPA2"),
    ("Cisco", "Corp-WiFi-5G", 48, -57, "WPA3"),
    ("Unknown", "DIRECT-3f-HP", 9, -72, "WPA2"),
    ("Unknown", "D-Link_DIR-816", 13, -88, "WEP"),
    ("Unknown", "(hidden)", 40, -79, "WPA2"),
    ("Unknown", "(hidden)", 6, -86, "WPA2"),
]

JS = """
(aps) => {
    /* OUI 表按厂商分组, 每个厂商取前几条真实前缀 */
    const byVendor = new Map();
    for (const kv of OUI_PACK.split(',')){
        const i = kv.indexOf(':');
        const name = (OUI_VEND[parseInt(kv.slice(i + 1), 16)] || '').split('|')[0];
        if (!byVendor.has(name)) byVendor.set(name, []);
        byVendor.get(name).push(kv.slice(0, i));
    }
    const used = new Map();
    const nextOui = v => {
        const list = byVendor.get(v) || [];
        const k = used.get(v) || 0;
        used.set(v, k + 1);
        return list[k % Math.max(1, list.length)] || '020000';
    };
    apList.length = 0;
    for (const [vendor, ssid, ch, rssi, enc] of aps){
        const oui = nextOui(vendor);
        const mac = oui.match(/../g).join(':') + ':' + Math.random().toString(16).slice(2, 8).match(/../g).join(':');
        apList.push({
            bssid: mac, ssid, channel: ch, rssi, enc,
            hidden: ssid === '(hidden)', vendor: 'Unknown',
            pmf: enc === 'WPA3',
            caps: { akm: enc === 'OPEN' ? '-' : 'PSK', cip: enc === 'OPEN' ? '-' : 'CCMP',
                    bw: ch >= 36 ? 80 : 20, std: '11ax', wps: '0', pmfc: '0', crk: '1' },
        });
    }
    renderApList();
    return apList.map(a => a.bssid + ' ' + deviceOf(a.bssid, a.vendor).vendor).slice(0, 6);
}
"""

CHROME = Path.home() / "AppData/Local/ms-playwright/chromium-1208/chrome-win64/chrome.exe"

with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=str(CHROME) if CHROME.exists() else None)
    pg = b.new_page(viewport={"width": 390, "height": 1900}, device_scale_factor=2)
    pg.goto(PAGE)
    pg.wait_for_timeout(900)
    pg.evaluate("document.getElementById('splash').style.display='none'")
    # 分批灌入, 让"发现节奏"有真实的上升沿
    pg.evaluate('window.__aps = ' + str(len(APS)) + ';')
    for i in range(0, len(APS), 4):
        pg.evaluate(JS, APS[:i + 4])
        pg.wait_for_timeout(500)
    print(pg.evaluate(JS, APS))
    info = pg.evaluate('''() => {
        const t = document.querySelector('.tab[data-tab="chart"]');
        return { tabs: document.querySelectorAll('.tab').length, found: !!t,
                 box: t ? t.getBoundingClientRect().toJSON() : null,
                 vis: t ? getComputedStyle(t).visibility + '/' + getComputedStyle(t).display : '' };
    }''')
    print(info)
    pg.evaluate('document.querySelector(\'.tab[data-tab="chart"]\').click()')
    pg.wait_for_timeout(3000)
    pg.screenshot(path=str(OUT), full_page=True)
    print("截图", OUT)
    # 每块单独拍一张, 检查细节
    for i in range(6):
        el = pg.locator('#pan-chart .blk').nth(i)
        el.screenshot(path=str(OUT.with_name(f'chart_blk{i}.png')))
    b.close()
