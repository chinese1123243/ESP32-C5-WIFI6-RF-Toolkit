#!/usr/bin/env bash
# 算法层主机测试: 只编 main/ 下的纯函数文件, 不需要 ESP-IDF 与开发板.
# 用法: bash tests/host/run.sh
set -e
cd "$(dirname "$0")/../.."

CC=${CC:-gcc}
OUT=.cache/hosttest
mkdir -p .cache

$CC -std=c11 -O2 -Wall -Wextra -I main -o "$OUT" \
    tests/host/test_algo.c main/chan_sched.c main/locate_est.c main/csi_det.c -lm

"$OUT"
