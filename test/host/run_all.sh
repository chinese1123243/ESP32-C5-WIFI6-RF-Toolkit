#!/usr/bin/env bash
# 主机端纯逻辑单测. 不插板, 不需要 ESP-IDF, 只要有 gcc/cc.
# 用法: bash test/host/run_all.sh
set -u

cd "$(dirname "$0")/../.." || exit 1
CC="${CC:-cc}"
OUT=build/host
mkdir -p "$OUT"

fail=0
run() {
  local name="$1"; shift
  printf '== %s ==\n' "$name"
  if ! "$CC" -std=c11 -Wall -Wextra -O1 -I main -I test/host/stub -lm -o "$OUT/$name" "$@" ; then
    printf '  COMPILE FAIL\n'; fail=1; return
  fi
  "$OUT/$name" || fail=1
}

# 每加一项就在这里加一行, CI 用同一条命令跑全量
run test_radio_rules main/radio_rules.c test/host/test_radio_rules.c
run test_frame_build main/frame_build.c test/host/test_frame_build.c
run test_chan_sched main/chan_sched.c test/host/test_chan_sched.c
run chan_dump main/chan_sched.c test/host/chan_dump.c
run test_wifi_export main/wifi_export.c main/wifi_names.c main/ie_parse.c test/host/test_wifi_export.c
run test_wifi_names main/wifi_names.c main/ie_parse.c test/host/test_wifi_names.c
run test_zbtx_frame main/zbtx_frame.c main/radio_hal.c test/host/radio_hal_mock.c test/host/test_zbtx_frame.c
run test_eapol_core main/eapol_core.c test/host/test_eapol_core.c
run test_ie_parse main/ie_parse.c test/host/test_ie_parse.c
run test_csi_det main/csi_det.c test/host/test_csi_det.c
run test_frame_build_tx main/frame_build.c main/frame_build_tx.c main/radio_hal.c test/host/radio_hal_mock.c test/host/test_frame_build_tx.c

printf '\n'
if [ "$fail" -ne 0 ]; then printf 'HOST TESTS FAILED\n'; exit 1; fi
printf 'HOST TESTS PASSED\n'
