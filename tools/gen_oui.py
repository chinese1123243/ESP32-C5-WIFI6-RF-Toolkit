"""从 IEEE OUI 注册表生成厂商表 (App 与固件共用一份数据源).

用法:
    curl -o .cache/oui.csv https://standards-oui.ieee.org/oui/oui.csv
    python tools/gen_oui.py

输出:
    app/app.js         OUI:BEGIN / OUI:END 之间的数据块
    main/oui_table.h   排序后的 C 表, 二分查找

为什么要限量: 全量 34114 条, 打包成文本 250KB, App 里塞不下; 按厂商各取前 N 条
(注册号越大越新, 前 N 条是老设备, 覆盖率更高) 后 1712 条约 17KB.
固件侧再窄一档, 只留 700 余条, flash 和 vendor[16] 字段都省.
"""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV = ROOT / ".cache" / "oui.csv"

# (关键字, 规范厂商名, 设备类别). 顺序即优先级, 先匹配先得.
MAP = [
    (["apple"], "Apple", "手机/PC"),
    (["samsung"], "Samsung", "手机/家电"),
    (["xiaomi"], "Xiaomi", "手机/IoT"),
    (["huawei", "hi silicon"], "Huawei", "手机/路由"),
    (["honor"], "Honor", "手机"),
    (["oppo"], "OPPO", "手机"),
    (["vivo"], "vivo", "手机"),
    (["oneplus"], "OnePlus", "手机"),
    (["meizu"], "Meizu", "手机"),
    (["zte"], "ZTE", "手机/路由"),
    (["tp-link", "tp link"], "TP-Link", "路由"),
    (["d-link"], "D-Link", "路由"),
    (["netgear"], "Netgear", "路由"),
    (["tenda"], "Tenda", "路由"),
    (["mercury"], "Mercury", "路由"),
    (["new h3c", "h3c"], "H3C", "路由"),
    (["ruijie"], "Ruijie", "路由"),
    (["asustek", "asus"], "ASUS", "路由/PC"),
    (["aruba"], "Aruba", "企业AP"),
    (["cisco", "meraki"], "Cisco", "企业AP"),
    (["ubiquiti"], "Ubiquiti", "企业AP"),
    (["mikrotik"], "MikroTik", "路由"),
    (["ruckus"], "Ruckus", "企业AP"),
    (["juniper"], "Juniper", "企业网络"),
    (["fortinet"], "Fortinet", "安全设备"),
    (["sagemcom", "technicolor", "arcadyan", "sercomm", "gemtek", "actiontec",
      "zyxel", "draytek", "cambium", "edimax", "trendnet", "buffalo", "linksys",
      "belkin"], "宽带CPE", "路由"),
    (["espressif"], "Espressif", "IoT模块"),
    (["realtek"], "Realtek", "网卡/IoT"),
    (["mediatek"], "MediaTek", "芯片"),
    (["qualcomm"], "Qualcomm", "芯片"),
    (["broadcom"], "Broadcom", "芯片"),
    (["intel"], "Intel", "PC"),
    (["murata", "azurewave", "ampak", "liteon", "foxconn", "hon hai",
      "pegatron", "compal", "quanta", "wistron", "inventec"], "代工模组", "模组"),
    (["tuya"], "Tuya", "智能家居"),
    (["broadlink"], "Broadlink", "智能家居"),
    (["raspberry"], "Raspberry Pi", "开发板"),
    (["nordic semi"], "Nordic", "蓝牙"),
    (["texas instr"], "TI", "芯片"),
    (["silicon lab"], "Silicon Labs", "IoT芯片"),
    (["st micro", "stmicro"], "ST", "芯片"),
    (["microchip", "cypress"], "Microchip", "芯片"),
    (["infineon"], "Infineon", "芯片"),
    (["nxp"], "NXP", "芯片"),
    (["bosch", "honeywell", "siemens", "schneider", "ecobee"], "楼宇工控", "IoT"),
    (["philips", "signify", "lifx"], "Signify", "照明"),
    (["hikvision", "ezviz"], "Hikvision", "摄像"),
    (["dahua", "imou"], "Dahua", "摄像"),
    (["uniview"], "Uniview", "摄像"),
    (["wyze", "eufy"], "Wyze", "摄像"),
    (["sonos"], "Sonos", "音频"),
    (["roku"], "Roku", "影音"),
    (["amazon"], "Amazon", "音箱/IoT"),
    (["google", "nest labs"], "Google", "手机/IoT"),
    (["sony", "htc", "lg electronics", "motorola", "lenovo", "tcl", "hisense",
      "skyworth", "changhong", "konka", "haier", "midea", "gree"], "消费电子", "终端"),
    (["dji"], "DJI", "无人机"),
    (["gopro"], "GoPro", "摄像"),
    (["fitbit", "garmin", "withings"], "穿戴", "穿戴"),
    (["nintendo"], "Nintendo", "游戏机"),
    (["microsoft"], "Microsoft", "PC"),
    (["vmware", "oracle", "xensource", "parallels", "qemu"], "虚拟化", "虚拟机"),
    (["dell", "hewlett", "acer", "gigabyte", "asrock", "supermicro"], "PC厂商", "PC"),
    (["synology", "qnap"], "NAS", "存储"),
    (["seagate", "toshiba", "kingston"], "存储", "存储"),
]

APP_CAP = 0     # 0 = 不限量. App 体积无人管, 精选厂商全量进去约 250KB
FW_CAP = 48     # 固件吃 flash 与 vendor[16], 每个厂商留 48 条足够

BEGIN = "/* OUI:BEGIN 由 tools/gen_oui.py 从 IEEE 注册表生成, 勿手改 */"
END = "/* OUI:END */"


def load():
    if not CSV.exists():
        sys.exit(f"缺少 {CSV}, 先 curl -o .cache/oui.csv https://standards-oui.ieee.org/oui/oui.csv")
    rows = csv.DictReader(open(CSV, encoding="utf-8", errors="replace"))
    seen = {}
    for r in rows:
        org = (r.get("Organization Name") or "").lower()
        oui = (r.get("Assignment") or "").upper()
        if len(oui) != 6 or oui in seen:
            continue
        for keys, name, cat in MAP:
            if any(k in org for k in keys):
                seen[oui] = (name, cat)
                break
    return seen


def cap(seen, limit):
    if not limit:
        return dict(seen)
    used, out = {}, {}
    for oui in sorted(seen):
        name, cat = seen[oui]
        if used.get(name, 0) >= limit:
            continue
        used[name] = used.get(name, 0) + 1
        out[oui] = (name, cat)
    return out


def write_app(table):
    pairs = sorted({(name, cat) for name, cat in table.values()})
    index = {p: i for i, p in enumerate(pairs)}
    vendors = ",".join(f'"{n}|{c}"' for n, c in pairs)
    pack = ",".join(f"{oui.lower()}:{index[(n, c)]:x}" for oui, (n, c) in sorted(table.items()))

    block = [
        BEGIN,
        f"const OUI_VEND = [{vendors}];",
        "const OUI_PACK = '" + pack + "';",
        END,
    ]
    text = "\n".join(block)

    p = ROOT / "app" / "app.js"
    s = p.read_text(encoding="utf-8", newline="")
    i, j = s.find(BEGIN), s.find(END)
    if i < 0 or j < 0:
        sys.exit("app.js 里找不到 OUI 标记块")
    s = s[:i] + text + s[j + len(END):]
    p.write_text(s, encoding="utf-8", newline="")
    return len(pairs), len(table)


def write_fw(table):
    lines = [
        "/* 由 tools/gen_oui.py 从 IEEE 注册表生成, 勿手改.",
        " * 按 OUI 升序, oui_lookup 二分查找. 厂商名截到 15 字符, 因为 vendor[16]. */",
        "#ifndef OUI_TABLE_H",
        "#define OUI_TABLE_H",
        "",
        "typedef struct { uint32_t key; const char *name; } oui_entry_t;",
        "",
        "static const oui_entry_t s_oui_table[] = {",
    ]
    for oui, (name, _cat) in sorted(table.items()):
        lines.append(f'    {{0x{oui}, "{name[:15]}"}},')
    lines += [
        "};",
        "#define OUI_COUNT (sizeof(s_oui_table) / sizeof(s_oui_table[0]))",
        "",
        "#endif",
        "",
    ]
    (ROOT / "main" / "oui_table.h").write_text("\n".join(lines), encoding="utf-8")


def main():
    seen = load()
    app_t, fw_t = cap(seen, APP_CAP), cap(seen, FW_CAP)
    nv, ne = write_app(app_t)
    write_fw(fw_t)
    print(f"注册表命中 {len(seen)} 条")
    print(f"App:  {ne} 条 OUI, {nv} 个厂商")
    print(f"固件: {len(fw_t)} 条")


if __name__ == "__main__":
    main()
