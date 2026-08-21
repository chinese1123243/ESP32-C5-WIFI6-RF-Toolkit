#!/usr/bin/env python3
"""
rftool 板级自检: 复位 -> 读启动 banner -> 发命令 -> 收输出.
用法: python scripts\test_commands.py [COM4]

验证项:
  1. 启动 banner 出现 (rgb_led_init 的 "WS2812 init ok, GPIO=27")
  2. rftool> REPL 提示符出现
  3. status / help 命令有响应
  4. sniff <ch> -n <n> 能抓到 PKT 行 (验证 promiscuous + RGB 绿灯)
"""
import sys, time, serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
BAUD = 115200

def drain(ser, secs):
    end = time.time() + secs
    buf = bytearray()
    while time.time() < end:
        n = ser.in_waiting
        if n:
            buf.extend(ser.read(n))
        else:
            time.sleep(0.05)
    return buf.decode("utf-8", "replace")

def send(ser, cmd, wait=1.5):
    ser.write((cmd + "\n").encode())
    return drain(ser, wait)

def main():
    print(f"[*] open {PORT} @ {BAUD}")
    with serial.Serial(PORT, BAUD, timeout=0.1) as ser:
        # 复位: ESP32 用 DTR=0->1 / RTS 控制 BOOT/EN; esptool 约定: EN=RTS, BOOT=DTR
        # 简单起见: 拉 RTS 复位 (EN=0) 再释放
        ser.dtr = False
        ser.rts = True   # EN low -> reset
        time.sleep(0.1)
        ser.rts = False  # EN high -> run
        time.sleep(0.05)
        ser.reset_input_buffer()

        print("[*] boot output (4s):")
        boot = drain(ser, 4.0)
        print(boot)
        print("=" * 50)

        led_ok = "WS2812 init ok" in boot
        repl_ok = "rftool>" in boot
        print(f"[?] RGB LED init log present: {led_ok}")
        print(f"[?] REPL prompt present:      {repl_ok}")
        print("=" * 50)

        # 发一个空行唤醒 REPL
        send(ser, "", 0.5)

        print("[*] cmd: status")
        print(send(ser, "status", 1.5))
        print("-" * 50)

        print("[*] cmd: help")
        print(send(ser, "help", 1.5))
        print("-" * 50)

        print("[*] cmd: sniff 6 -n 15  (channel 6, 15 packets)")
        out = send(ser, "sniff 6 -n 15", 6.0)
        print(out)
        npkt = out.count("PKT,")
        print(f"[?] captured PKT lines: {npkt}")
        print("-" * 50)

        print("[*] cmd: stop")
        print(send(ser, "stop", 1.0))

        print("\n=== SUMMARY ===")
        print(f"  RGB LED init log : {led_ok}")
        print(f"  REPL prompt      : {repl_ok}")
        print(f"  sniff PKT count  : {npkt}")
        if led_ok and repl_ok:
            print("  -> RGB 灯应已点亮 (启动=暗紫, 嗅探=绿). 若不亮, 检查 GPIO27 焊接/RGB_CTRL 门控.")
        print("DONE")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] error: {e}")
        sys.exit(1)
