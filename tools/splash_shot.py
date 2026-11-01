"""开屏动画的分帧截图.

开屏在 1.25 秒后就收尾了, 靠人手截不到中间帧, 所以在固定时间点连拍几张,
逐帧看曲线是不是在长、峰标记是不是跟着扫描线落下.
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "app" / "index.html").as_uri()
CHROME = Path.home() / "AppData/Local/ms-playwright/chromium-1208/chrome-win64/chrome.exe"
OUT = ROOT / ".cache"


def main():
    OUT.mkdir(exist_ok=True)
    # 从导航提交开始计时: goto 默认等 load, 慢一点就会错过中段
    shots = [260, 520, 780, 1020, 1320, 1750]
    with sync_playwright() as pw:
        b = pw.chromium.launch(executable_path=str(CHROME) if CHROME.exists() else None)
        pg = b.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=3)
        pg.goto(PAGE, wait_until="commit")

        prev = 0
        for ms in shots:
            pg.wait_for_timeout(ms - prev)
            prev = ms
            pg.screenshot(path=str(OUT / f"splash_{ms:04d}.png"))

        # 收尾后应该是主界面
        pg.wait_for_timeout(1200)
        pg.screenshot(path=str(OUT / "splash_after.png"))

        # headless 在 3 倍分辨率下解析 230KB 脚本会卡几秒, 动画早就跑完了,
        # 中间帧经常抓空. 把开屏强行放回来拍它的收尾态, 至少有一个确定的样本.
        pg.evaluate("""() => {
            const s = document.getElementById('splash');
            s.style.display = 'flex';
            s.classList.remove('hidden');
            s.style.opacity = '1';
            Splash.redraw();
        }""")
        # 淡入过渡是 620ms, 等太短会拍到开屏和主界面叠在一起的状态
        pg.wait_for_timeout(900)
        pg.screenshot(path=str(OUT / "splash_final.png"))
        b.close()
    print("截图完成:", ", ".join(f"splash_{m:04d}.png" for m in shots))


if __name__ == "__main__":
    sys.exit(main())
