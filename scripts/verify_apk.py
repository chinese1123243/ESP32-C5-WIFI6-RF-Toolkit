"""校验 APK 里内嵌的前端与源文件一致.

背景 (这个坑踩过一次):
    `app/android/app/src/main/assets/public/` 在 .gitignore 里,
    Capacitor 的前端拷贝产物不入库. 如果直接跑 gradlew assembleDebug 而不先同步,
    gradle 会认为资源任务是 up-to-date, 于是打出上一个版本的 APK ——
    实测过一次: app.js 少了 3660 字节, 打出来的是 2.2.0 而不是 2.3.0.
    功能看起来"能跑", 所以肉眼看不出来.

正确的构建方式是 package.json 里的:
    npm run build:android        (= www:sync && cap sync android && gradlew)

本脚本不负责构建, 只负责在构建之后拦一道: 不管你是怎么构建出来的,
只要包里的前端和源文件对不上, 就报错退出.

用法:
    python scripts/verify_apk.py                       # 校验默认 debug 产物
    python scripts/verify_apk.py <apk路径>
"""

import hashlib
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_APK = os.path.join(
    ROOT, "app", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk"
)

# 这些文件源自 app/ 源码目录, 必须在 APK 里逐字节一致.
# assets/public 下另有 cordova.js / cordova_plugins.js / icon*.png,
# 它们是 Capacitor 生成的, 不来自 app/, 不在校验范围.
SYNCED = ["app.js", "index.html", "manifest.json", "sw.js"]

APK_PREFIX = "assets/public/"

def md5(b):
    return hashlib.md5(b).hexdigest()


def main():
    apk_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_APK

    if not os.path.exists(apk_path):
        print(f"FAIL 找不到 APK: {apk_path}")
        print("     先构建: cd app && npm run build:android")
        return 2

    print(f"APK : {apk_path}")
    print(f"大小: {os.path.getsize(apk_path):,} 字节")
    print()

    try:
        z = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        print("FAIL 不是有效的 zip/apk 文件")
        return 2

    bad = []

    with z:
        names = set(z.namelist())

        for name in SYNCED:
            src = os.path.join(ROOT, "app", name)
            entry = APK_PREFIX + name

            if not os.path.exists(src):
                print(f"SKIP {name}: 源文件不存在 ({src})")
                continue
            if entry not in names:
                bad.append(f"{name}: APK 里没有 {entry} (前端压根没拷进去)")
                continue

            a = open(src, "rb").read()
            b = z.read(entry)

            if a == b:
                print(f"OK   {name:<16} {len(a):>8,} 字节  md5={md5(a)}")
            else:
                # 给出首个差异位置, 定位时省一大圈
                i = next(
                    (i for i, (x, y) in enumerate(zip(a, b)) if x != y),
                    min(len(a), len(b)),
                )
                if len(a) == len(b):
                    hint = f"长度相同但第 {i} 字节不同"
                else:
                    hint = (
                        f"长度不同: 源 {len(a):,} vs 包内 {len(b):,} "
                        f"(差 {len(a) - len(b):+,}); 首个差异在第 {i} 字节"
                    )
                bad.append(f"{name}: {hint}")
                print(f"DIFF {name:<16} {hint}")

        # 版本号交叉验证: 包内 app.js 自称的版本 vs package.json
        app_js = None
        if APK_PREFIX + "app.js" in names:
            app_js = z.read(APK_PREFIX + "app.js").decode("utf-8", "replace")

        if app_js:
            m = re.search(r"APP_VERSION\s*=\s*['\"]([^'\"]+)['\"]", app_js)
            pkg = re.search(
                r'"version"\s*:\s*"([^"]+)"',
                open(os.path.join(ROOT, "app", "package.json"), encoding="utf-8").read(),
            )
            if m and pkg:
                v_in, v_pkg = m.group(1), pkg.group(1)
                if v_in == v_pkg:
                    print(f"OK   版本号一致      {v_in}")
                else:
                    bad.append(f"版本号不一致: 包内 app.js={v_in}, package.json={v_pkg}")
                    print(f"DIFF 版本号不一致    包内={v_in} package.json={v_pkg}")

    print()
    if bad:
        print(f"==== 校验失败: {len(bad)} 项 ====")
        for b in bad:
            print("  -", b)
        print()
        print("修复方法 (同步 app/ 到 assets/public/ 后全量重编):")
        print("    cd app && npm run build:android")
        print()
        print("不要直接 gradlew assembleDebug —— 那样会用旧的前端产物.")
        return 1

    print("==== 校验通过: 包内前端与源文件逐字节一致 ====")
    return 0


if __name__ == "__main__":
    sys.exit(main())
