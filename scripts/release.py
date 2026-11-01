"""把当前版本的 APK 与固件发到 GitHub Releases.

为什么要有这个脚本: 手工发一次要 取 token -> 建 release -> 传两个文件 ->
贴烧录说明, 每次都得重来一遍, 漏传固件也没人发现. 现在一条命令, 且默认
会先跑 verify_apk.py, 包内前端与源文件不一致就直接退出.

用法:
    python scripts/release.py                 # 打包并发布当前版本
    python scripts/release.py --dry-run       # 只准备产物, 不发
    python scripts/release.py --notes 说明.md  # 用指定文件当 release 正文
    python scripts/release.py --prerelease    # 标成预发布

版本号唯一来源是 main/version.h 的 RFTOOL_VERSION, 不从别处读.

凭据: 优先环境变量 GITHUB_TOKEN, 否则退到 git credential fill
(Windows 上凭据管理器里存的那份 PAT). 只用 classic PAT 的 repo 权限.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "chinese1123243/ESP32-C5-WIFI6-RF-Toolkit"
API = "https://api.github.com"

APK = ROOT / "app/android/app/build/outputs/apk/debug/app-debug.apk"
FW_APP = ROOT / "build/rftool.bin"
FW_BOOT = ROOT / "build/bootloader/bootloader.bin"
FW_PART = ROOT / "build/partition_table/partition-table.bin"
FW_OTA = ROOT / "build/ota_data_initial.bin"
OUT = ROOT / ".cache/release"

FLASH_TXT = """RFTOOL-C5 v{ver} 烧录说明
================================

一、整包烧录 (推荐, 从零开始或换分区表后必须用这个)
--------------------------------------------------
四个文件的偏移不能错. 分区表在 0x8000, 不在 0xf000 (0xf000 是 otadata).
写错位置板子会进 boot loop, 报 partition 0 invalid magic number.

  esptool.py -p <端口> -b 460800 write_flash \\
      0x2000   bootloader.bin \\
      0x8000   partition-table.bin \\
      0xf000   ota_data_initial.bin \\
      0x20000  rftool.bin

Windows 下端口形如 COM4, Linux/macOS 形如 /dev/ttyUSB0.

二、只更新应用 (保留 NVS 里的配置)
----------------------------------
  esptool.py -p <端口> -b 460800 write_flash 0x20000 rftool.bin

三、板载 OTA
------------
起一个 HTTP 服务把 rftool.bin 放上去, 然后:

  ota http://<你的电脑IP>:8000/rftool.bin

四、装 App
----------
  rftool-c5-v{ver}.apk

debug 签名, 可安装, Android 会提示"未知来源". 与固件版本号一致 ({ver}).
"""


def sh(args, **kw):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, **kw)


def version():
    m = re.search(r'RFTOOL_VERSION\s+"([0-9.]+)"',
                  (ROOT / "main/version.h").read_text(encoding="utf-8"))
    if not m:
        sys.exit("读不到 main/version.h 里的 RFTOOL_VERSION")
    return m.group(1)


def token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t.strip()
    r = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True, cwd=ROOT)
    for line in r.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    sys.exit("拿不到 GitHub 凭据: 设 GITHUB_TOKEN, 或让 git 凭据管理器存一份 PAT")


def api(method, path, tok, data=None, raw=None, ctype="application/json",
        allow_404=False):
    url = path if path.startswith("http") else API + path
    headers = {
        "Authorization": "token " + tok,
        "Accept": "application/vnd.github+json",
        "User-Agent": "rftool-release",
    }
    body = raw
    if data is not None:
        body = json.dumps(data).encode()
    if body is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt.strip() else {}
    except urllib.error.HTTPError as e:
        if allow_404 and e.code == 404:
            return None
        detail = e.read().decode()[:400]
        sys.exit(f"GitHub API {method} {path} 失败 {e.code}: {detail}")


def make_assets(ver):
    """产出待上传的三个文件: APK / 裸固件 / 整包 zip."""
    OUT.mkdir(parents=True, exist_ok=True)
    apk = OUT / f"rftool-c5-v{ver}.apk"
    apk.write_bytes(APK.read_bytes())

    fw = OUT / f"rftool-c5-v{ver}.bin"
    fw.write_bytes(FW_APP.read_bytes())

    txt = OUT / "FLASH.txt"
    txt.write_text(FLASH_TXT.format(ver=ver), encoding="utf-8")

    full = OUT / f"rftool-c5-v{ver}-full.zip"
    with zipfile.ZipFile(full, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(FW_BOOT, "bootloader.bin")
        z.write(FW_PART, "partition-table.bin")
        z.write(FW_OTA, "ota_data_initial.bin")
        z.write(FW_APP, "rftool.bin")
        z.write(txt, "FLASH.txt")
    return [apk, fw, full]


def notes(ver, custom):
    if custom:
        return Path(custom).read_text(encoding="utf-8")
    log = sh(["git", "log", "--oneline", "-14", "--no-merges"]).stdout.strip()
    lines = "\n".join("- " + l.split(" ", 1)[1] for l in log.splitlines() if " " in l)
    return f"""## 版本 {ver} · {date.today().isoformat()}

## 本次变更
{lines}

## 文件说明

| 文件 | 用途 |
|---|---|
| `rftool-c5-v{ver}.apk` | Android App, debug 签名 |
| `rftool-c5-v{ver}.bin` | 应用固件镜像, 烧到 0x20000, 或给板载 `ota` 用 |
| `rftool-c5-v{ver}-full.zip` | 整包 (bootloader + 分区表 + otadata + 固件 + 烧录说明) |

整包烧录:

```
esptool.py -p <端口> -b 460800 write_flash \\
    0x2000 bootloader.bin 0x8000 partition-table.bin \\
    0xf000 ota_data_initial.bin 0x20000 rftool.bin
```

分区表在 `0x8000` 不是 `0xf000`, 写错会进 boot loop.
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--notes")
    ap.add_argument("--prerelease", action="store_true")
    args = ap.parse_args()

    ver = version()
    tag = "v" + ver

    if not APK.exists():
        sys.exit(f"没有 APK: {APK}\n先构建: cd app && npm run www:sync && "
                 f"./node_modules/.bin/cap sync android && cd android && ./gradlew.bat assembleDebug")
    for p in (FW_APP, FW_BOOT, FW_PART, FW_OTA):
        if not p.exists():
            sys.exit(f"缺少固件产物: {p}\n先构建: .\\scripts\\build.ps1")

    # 包内前端与源文件不一致的话, 发出去的就是旧界面
    print("== 校验 APK ==")
    r = sh([sys.executable, "scripts/verify_apk.py"])
    if r.returncode != 0:
        sys.exit(r.stdout[-900:] + r.stderr[-400:])
    print("   OK")

    assets = make_assets(ver)
    for a in assets:
        print(f"   产物 {a.name}  {a.stat().st_size:,} 字节")

    if args.dry_run:
        print("\n--dry-run: 产物已备好, 没有发布")
        return 0

    tok = token()
    body = notes(ver, args.notes)

    # release 已存在就复用, 免得重复跑时报 422
    existing = api("GET", f"/repos/{REPO}/releases/tags/{tag}", tok, allow_404=True)

    if existing and existing.get("id"):
        rel = existing
        print(f"\n复用已有 release {tag} (id {rel['id']})")
        api("PATCH", f"/repos/{REPO}/releases/{rel['id']}", tok,
            data={"body": body, "prerelease": args.prerelease})
    else:
        rel = api("POST", f"/repos/{REPO}/releases", tok, data={
            "tag_name": tag,
            "name": f"RFTOOL-C5 v{ver}",
            "body": body,
            "draft": False,
            "prerelease": args.prerelease,
        })
        print(f"\n新建 release {tag} (id {rel['id']})")

    # 同名资产先删再传, 否则 GitHub 会让 upload 报 422
    old = api("GET", f"/repos/{REPO}/releases/{rel['id']}/assets?per_page=100", tok)
    by_name = {a["name"]: a for a in (old if isinstance(old, list) else [])}

    upload = rel["upload_url"].split("{")[0]
    for a in assets:
        if a.name in by_name:
            api("DELETE", f"/repos/{REPO}/releases/assets/{by_name[a.name]['id']}", tok)
            print(f"   替换 {a.name}")
        ctype = ("application/vnd.android.package-archive" if a.suffix == ".apk"
                 else "application/zip" if a.suffix == ".zip"
                 else "application/octet-stream")
        res = api("POST", f"{upload}?name={a.name}", tok,
                  raw=a.read_bytes(), ctype=ctype)
        print(f"   上传 {res.get('name')}  {res.get('size'):,} 字节")

    print(f"\n{rel['html_url']}")
    print("下载直链:")
    for a in assets:
        print(f"  {rel['html_url'].replace('/tag/', '/download/')}/{a.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
