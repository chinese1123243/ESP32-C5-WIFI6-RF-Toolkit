#include "out_stream.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_timer.h"

typedef struct {
    out_sink_fn fn;
    void *ctx;
    bool used;
} out_sink_t;

static out_sink_t s_sinks[OUT_SINK_MAX];
static out_adv_gate_fn s_adv_gate;
static out_link_fn s_link_fn;
static out_stats_fn s_stats_fn;

/* 1 秒窗口的到达率, 只存 32 位毫秒戳: 单字读写原子, 回绕按无符号减法算 */
static volatile uint32_t s_win_cnt;
static volatile uint32_t s_win_ms;
static volatile uint32_t s_rate_x10;

void out_stream_init(void)
{
    /* 汇点表是静态的, 无需初始化动作. 保留入口是为了将来加锁时不用改调用方. */
    s_win_cnt = s_rate_x10 = 0;
    s_win_ms = (uint32_t)(esp_timer_get_time() / 1000);
}

unsigned out_rate_x10(void) { return (unsigned)s_rate_x10; }

int out_sink_add(out_sink_fn fn, void *ctx)
{
    if (!fn) return -1;
    for (int i = 0; i < OUT_SINK_MAX; i++) {
        if (s_sinks[i].used) continue;
        s_sinks[i].fn = fn;
        s_sinks[i].ctx = ctx;
        s_sinks[i].used = true;
        return i;
    }
    return -1;
}

void out_sink_remove(int id)
{
    if (id < 0 || id >= OUT_SINK_MAX) return;
    s_sinks[id].used = false;
    s_sinks[id].fn = NULL;
    s_sinks[id].ctx = NULL;
}

void out_raw(const char *line)
{
    if (!line) return;

    /* 到达率: 顺路算, 不起定时器. 空载时窗口不推进, 所以读到的是
     * "最近一个有输出的 1 秒", 突发过后要等下一秒才归零. */
    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t dt = now_ms - s_win_ms;
    if (dt >= 1000) {
        s_rate_x10 = (uint32_t)((uint64_t)s_win_cnt * 10000u / dt);
        s_win_cnt = 0;
        s_win_ms = now_ms;
    }
    s_win_cnt++;

    /* 先拷贝一份: 汇点可能在下一次调用时才真正读取, 而调用方的 buf 在栈上 */
    char copy[256];
    size_t n = strlen(line);
    if (n >= sizeof(copy)) n = sizeof(copy) - 1;
    memcpy(copy, line, n);
    copy[n] = '\0';

    for (int i = 0; i < OUT_SINK_MAX; i++) {
        if (s_sinks[i].used && s_sinks[i].fn) s_sinks[i].fn(copy, s_sinks[i].ctx);
    }
}

void out_line(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) out_raw(buf);
}

void out_adv_gate_set(out_adv_gate_fn fn) { s_adv_gate = fn; }

void out_adv_gate(bool hold)
{
    if (s_adv_gate) s_adv_gate(hold);
}

void out_link_set(out_link_fn fn) { s_link_fn = fn; }

void out_link(out_link_t *out)
{
    if (!out) return;
    out->mtu = 0;
    out->connected = false;
    out->phy = 0;
    if (s_link_fn) s_link_fn(out);
}

void out_stats_set(out_stats_fn fn) { s_stats_fn = fn; }

void out_stats(out_stats_t *out)
{
    if (!out) return;
    out->capacity_per_s = 0;
    out->dropped = 0;
    if (s_stats_fn) s_stats_fn(out);
}
