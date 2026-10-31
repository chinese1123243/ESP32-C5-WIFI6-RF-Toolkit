/* health.c: 整机自检
 *
 * 从 cli.c 拆出来的原因: cli.c 是仓库最大的文件, arch_check 的棘轮只许降不许升.
 * 这个命令不碰任何解析逻辑, 只读状态, 拆走是零风险的减行.
 *
 * 阈值来自实测, 不是估的:
 *   用临时命令逐级占住内部 RAM 再起功能, BLE 扫描 / BLE 广播伪造在 largest
 *   只剩 1344 字节时仍能起来; 最吃内存的 phish start (AP + DHCP + HTTP + DNS)
 *   在 13312 时正常, 掉到 1664 才失败. 所以 32KB 那条线纯属虚报:
 *   实测 31.7KB 时报 WARN, 但 BLE 与门户都好好的.
 *   取 8KB 作告警线, 是失败点 (1.6KB) 的 5 倍余量.
 */
#include "health.h"

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_system.h"

#include "cap.h"
#include "city_time.h"
#include "cli.h"
#include "event_bus.h"
#include "job.h"
#include "logring.h"
#include "out_stream.h"
#include "zbsniff.h"

/* init 任务自删前存下的栈低水位, 由 main.c 写入 */
extern uint32_t g_init_stack_min;

int cmd_health(int argc, char **argv)
{
    (void)argc; (void)argv;

    uint32_t int_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    uint32_t int_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    uint32_t ps_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint32_t ps_largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    uint32_t total_free = esp_get_free_heap_size();
    uint32_t min_free = esp_get_minimum_free_heap_size();

    /* 空闲块数与最大块一起看才有意义: 内部堆剩 50KB 但被切成 20 块时,
     * 最大连续块可能只剩 4KB, NimBLE 重新起广播就申请不到.
     * frag = 1 - largest/free, 越高越碎. */
    multi_heap_info_t mi;
    heap_caps_get_info(&mi, MALLOC_CAP_INTERNAL);
    unsigned frag = mi.total_free_bytes
        ? (unsigned)(100 - (uint64_t)mi.largest_free_block * 100 / mi.total_free_bytes)
        : 0;
    /* 本函数跑在 cli_task 里, NULL 取到的就是 cli_task 的栈余量低水位.
     * 栈该给多大要拿这个数定, 不能靠估算. */
    uint32_t cli_stack_min =
        (uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
    city_time_t ct = city_clock();

    /* ρ = λ/μ. λ 是输出汇点的到达率 (所有出站行都从这里过), μ 是通道自己
     * 报的限速上限. 当前只有 BLE NUS 一个通道, 取它而不是串口: 现场消费端
     * 就是手机, 串口只在台架上接. ρ>100 表示结构上发不完, 队列必然堆满
     * 并开始挤掉最旧的. */
    unsigned lam_x10 = out_rate_x10();
    out_stats_t st;
    out_stats(&st);
    int ev_cap = st.capacity_per_s;
    unsigned ev_rho = ev_cap > 0 ? (unsigned)((uint64_t)lam_x10 * 10 / (unsigned)ev_cap) : 0;

    if (cli_json_mode()) {
        printf("{\"ok\":true,\"heap_total\":%u,\"heap_min\":%u,\"internal_free\":%u,"
               "\"internal_largest\":%u,\"psram_free\":%u,\"psram_largest\":%u,"
               "\"tasks\":%u,\"zbsniff\":%s,\"logring\":%u,\"events\":%u,"
               "\"ev_pub\":%u,\"ev_dropped\":%u,\"ev_ble_drop\":%u,"
               "\"out_rate_x10\":%u,\"ev_rho_pct\":%u,"
               "\"jobs_active\":%d,\"jobs_aux\":%d,\"jobs_peak\":%d,\"jobs_cap\":%d,"
               "\"jobs_rejected\":%u,\"jobs_rej_name\":\"%s\","
               "\"cap_seg\":%d,\"cap_segs\":%d,"
               "\"internal_blocks\":%u,\"internal_free_blocks\":%u,\"internal_frag\":%u,"
               "\"cli_stack_min\":%u,\"init_stack_min\":%u,"
               "\"boot_count\":%u,\"monotonic_ms\":%u,\"wallclock_s\":%u}\n",
               (unsigned)total_free, (unsigned)min_free, (unsigned)int_free,
               (unsigned)int_largest, (unsigned)ps_free, (unsigned)ps_largest,
               (unsigned)uxTaskGetNumberOfTasks(), zbsniff_is_on() ? "\"run\"" : "\"idle\"",
               (unsigned)logring_used(), event_total(),
               event_published(), event_dropped(), st.dropped,
               lam_x10, ev_rho,
               job_active(), job_aux(), job_peak(), job_capacity(), job_rejected(),
               job_last_rejected(),
               cap_segment_index(), cap_segment_count(),
               (unsigned)mi.total_blocks, (unsigned)mi.free_blocks, frag,
               (unsigned)cli_stack_min, (unsigned)g_init_stack_min,
               (unsigned)ct.boot_count, (unsigned)ct.monotonic_ms,
               (unsigned)ct.wallclock_s);
        fflush(stdout);
        return 0;
    }

    printf("=== HEALTH ===\n");
    printf("heap total_free : %u bytes\n", (unsigned)total_free);
    printf("heap min_free   : %u bytes (low-water)\n", (unsigned)min_free);
    printf("internal free   : %u bytes (largest %u)\n", (unsigned)int_free, (unsigned)int_largest);
    printf("internal blocks : %u total, %u free, frag %u%%\n",
           (unsigned)mi.total_blocks, (unsigned)mi.free_blocks, frag);
    printf("psram    free   : %u bytes (largest %u)\n", (unsigned)ps_free, (unsigned)ps_largest);

    printf("tasks           : %u\n", (unsigned)uxTaskGetNumberOfTasks());
    printf("cli stack left  : %u bytes (low-water)\n", (unsigned)cli_stack_min);
    printf("init stack left : %u bytes (low-water, 任务已退出)\n", (unsigned)g_init_stack_min);

    printf("zbsniff         : %s\n", zbsniff_is_on() ? "RUNNING" : "idle");
    printf("logring         : %u bytes buffered\n", (unsigned)logring_used());
    printf("events pub/drop : %u / %u (BLE queue 挤掉 %u)\n",
           event_published(), event_dropped(), st.dropped);
    printf("out rate        : %u.%u /s, rho %u%% of BLE %d /s\n",
           lam_x10 / 10, lam_x10 % 10, ev_rho, ev_cap);
    printf("jobs            : %d active (%d aux), peak %d, cap %d, rejected %u%s%s\n",
           job_active(), job_aux(), job_peak(), job_capacity(), job_rejected(),
           job_rejected() ? " last " : "", job_last_rejected());

    if (int_largest < 8192) {
        printf("WARN: internal largest block %u B < 8KB, 新的 AP/HTTP 会话可能起不来\n",
               (unsigned)int_largest);
    } else {
        printf("OK: internal contiguous %u B\n", (unsigned)int_largest);
    }
    fflush(stdout);
    return 0;
}
