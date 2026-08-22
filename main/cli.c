/*
 * cli.c — 极简 fgets+dispatch REPL 实现 (彻底绕过 esp_console 栈溢出)
 *
 * 设计原则:
 *   1. 零额外任务: 直接在调用者任务 (cli_task) 中跑 REPL 循环
 *   2. 零重型依赖: 不用 esp_console / linenoise / uart_driver_install
 *      UART0 已由 IDF stdio 初始化 (fgets/fputs 直接用), 省 10+KB 栈
 *   3. 保留 argtable3: 各命令参数解析逻辑完全复用, 行为不变
 *   4. 栈可预测: 最深调用 = fgets + split + arg_parse + cmd_xxx, 估算 < 8KB
 *      (cli_task 给 32KB 有 4 倍余量)
 *
 * 输出约定 (与 test_commands.py 对齐):
 *   REPL 提示符: "rftool> "
 *   help 输出:   "Commands:\n  <name>  <help>\n..."
 */
#include "cli.h"
#include "wifi_attack.h"
#include "radio_common.h"
#include "rgb_led.h"
#include "wifi_db.h"
#include "http_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "argtable3/argtable3.h"


/* ===================== REPL 基础工具 ===================== */

#define MAX_CMDLINE   256
#define MAX_ARGC      32

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

/* ===================== 命令定义 ===================== */

typedef int (*cmd_func_t)(int argc, char **argv);

typedef struct {
    const char *name;
    const char *help;
    const char *hint;
    cmd_func_t  func;
    void      (*arg_reset)(void);
} cli_cmd_t;

/* ---------- sniff ---------- */
static struct {
    arg_int_t *channel;
    arg_int_t *count;
    arg_int_t *dwell;
    arg_end_t *end;
} sniff_args;

static void sniff_arg_reset(void)
{
    if (sniff_args.channel) arg_freetable((void **)&sniff_args.channel, 4);
    sniff_args.channel = arg_int1(NULL, NULL, "<1-14|auto>", "channel 1..14 or 'auto' for rotate");
    sniff_args.count   = arg_int0("n", "count", "<n>", "stop after N packets (0=forever)");
    sniff_args.dwell   = arg_int0("d", "dwell", "<ms>", "auto mode: ms per channel (default 1000)");
    sniff_args.end     = arg_end(3);
}

static int cmd_sniff(int argc, char **argv)
{
    /* 检测 auto 子命令: argv[1] == "auto" */
    if (argc >= 2 && strcmp(argv[1], "auto") == 0) {
        /* "auto" 不是合法 int，手动解析 [--dwell N] [-n N] */
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
            } else {
                printf("META,WIFI,ERR,msg,bad_option,%s\n", a);
                fflush(stdout);
                return 1;
            }
        }
        esp_err_t e = wifi_attack_sniff_auto_start(dwell);
        if (e != ESP_OK) {
            printf("META,WIFI,ERR,code,%d,msg,sniff_auto_start_failed\n", e);
            fflush(stdout);
            return 1;
        }
        (void)cnt;
        return 0;
    }
    int nerrors = arg_parse(argc, argv, (void **)&sniff_args);
    if (nerrors) {
        arg_print_errors(stderr, sniff_args.end, argv[0]);
        return 1;
    }
    int ch_raw = sniff_args.channel->ival[0];
    if (ch_raw < 1 || ch_raw > 14) {
        printf("META,WIFI,ERR,msg,bad_channel (1-14 or 'auto')\n"); fflush(stdout); return 1;
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

/* ---------- stop ---------- */
static int cmd_stop(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (wifi_attack_inject_stop() == ESP_OK) return 0;
    if (wifi_attack_sniff_stop()    == ESP_OK) return 0;
    printf("META,WIFI,ERR,msg,nothing_running\n");
    fflush(stdout);
    return 1;
}

/* ---------- deauth ---------- */
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
    int nerrors = arg_parse(argc, argv, (void **)&deauth_args);
    if (nerrors) {
        arg_print_errors(stderr, deauth_args.end, argv[0]);
        return 1;
    }
    uint8_t b[6], s[6] = {0};
    if (!parse_mac(deauth_args.bssid->sval[0], b)) {
        printf("META,WIFI,ERR,msg,bad_bssid\n"); fflush(stdout); return 1;
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

/* ---------- beaconflood ---------- */
static struct {
    arg_str_t *prefix;
    arg_int_t *count;
    arg_int_t *interval;
    arg_end_t *end;
} beacon_args;

static void beacon_arg_reset(void)
{
    if (beacon_args.prefix) arg_freetable((void **)&beacon_args.prefix, 4);
    beacon_args.prefix   = arg_str1("p", "prefix", "<str>",   "SSID prefix");
    beacon_args.count    = arg_int0("n", "count", "<n>",     "count (0=forever)");
    beacon_args.interval = arg_int0("i", "interval", "<ms>", "interval ms (default 0=fastest)");
    beacon_args.end      = arg_end(4);
}

static int cmd_beaconflood(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&beacon_args);
    if (nerrors) { arg_print_errors(stderr, beacon_args.end, argv[0]); return 1; }
    uint32_t cnt  = beacon_args.count->count ? (uint32_t)beacon_args.count->ival[0] : 0;
    uint32_t intv = beacon_args.interval->count ? (uint32_t)beacon_args.interval->ival[0] : 0;
    esp_err_t e = wifi_attack_beacon_flood_start(beacon_args.prefix->sval[0], cnt, intv);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,beacon_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}

/* ---------- probeflood ---------- */
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
    int nerrors = arg_parse(argc, argv, (void **)&probe_args);
    if (nerrors) { arg_print_errors(stderr, probe_args.end, argv[0]); return 1; }
    uint32_t cnt  = probe_args.count->count ? (uint32_t)probe_args.count->ival[0] : 0;
    uint32_t intv = probe_args.interval->count ? (uint32_t)probe_args.interval->ival[0] : 0;
    esp_err_t e = wifi_attack_probe_flood_start(cnt, intv);
    if (e != ESP_OK) {
        printf("META,WIFI,ERR,code,%d,msg,probe_start_failed\n", e); fflush(stdout); return 1;
    }
    return 0;
}


/* ---------- http ---------- */
static struct {
    arg_str_t *subcmd;
    arg_str_t *ssid;
    arg_str_t *pass;
    arg_end_t *end;
} http_args;

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
    if (nerrors) { arg_print_errors(stderr, http_args.end, argv[0]); return 1; }
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

/* ---------- export ---------- */
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
    if (nerrors) { arg_print_errors(stderr, export_args.end, argv[0]); return 1; }
    const char *fmt = export_args.format->sval[0];
    if (strcmp(fmt, "csv") == 0) {
        wifi_db_export_csv();
    } else if (strcmp(fmt, "json") == 0) {
        wifi_db_export_json();
    } else {
        printf("META,WIFI,ERR,msg,bad_format (csv or json)\n"); fflush(stdout); return 1;
    }
    return 0;
}

/* ---------- dump ---------- */
static struct {
    arg_str_t *what;
    arg_end_t *end;
} dump_args;

static void dump_arg_reset(void)
{
    if (dump_args.what) arg_freetable((void **)&dump_args.what, 2);
    dump_args.what = arg_str1(NULL, NULL, "<aps|clients|eapols|all>", "what to dump");
    dump_args.end  = arg_end(2);
}

static int cmd_dump(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&dump_args);
    if (nerrors) { arg_print_errors(stderr, dump_args.end, argv[0]); return 1; }
    const char *w = dump_args.what->sval[0];
    if (strcmp(w, "aps") == 0 || strcmp(w, "all") == 0) wifi_db_dump_aps();
    if (strcmp(w, "clients") == 0 || strcmp(w, "all") == 0) wifi_db_dump_clients();
    if (strcmp(w, "eapols") == 0 || strcmp(w, "all") == 0) wifi_db_dump_eapols();
    if (strcmp(w, "aps") && strcmp(w, "clients") && strcmp(w, "eapols") && strcmp(w, "all")) {
        printf("META,WIFI,ERR,msg,bad_target (aps|clients|eapols|all)\n"); fflush(stdout); return 1;
    }
    return 0;
}

/* ---------- status ---------- */
static int cmd_status(int argc, char **argv)
{
    (void)argc; (void)argv;
    wifi_attack_status();
    return 0;
}

/* ---------- help ---------- */
static const cli_cmd_t g_cmds[];

static int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    fputs(
        "Commands:\n"
        "  help         Show this help\n"
        "  status       Show current state and counters\n"
        "  sniff        Start Wi-Fi promiscuous sniff (output PKT/HEX lines)\n"
        "                  Usage: sniff <1-14|auto> [opts]\n"
        "  stop         Stop current sniff/inject\n"
        "  deauth       Deauth frame inject (authorized use only)\n"
        "                  Usage: deauth -b <bssid> [-s <station>] [opts]\n"
        "  beaconflood  Fake beacon flood (authorized use only)\n"
        "                  Usage: beaconflood -p <prefix> [opts]\n"
        "  probeflood   Probe request flood\n"
        "                  Usage: probeflood [opts]\n"
        "  export       Export tracked tables (CSV or JSON)\n"
        "                  Usage: export <csv|json>\n"
        "  dump         Dump tracked tables to console\n"
        "                  Usage: dump <aps|clients|eapols|all>\n"
        "  http         HTTP REST API remote control\n"
        "                  Usage: http <start|stop|status> [opts]\n"
        "\n"
        "  Type '<cmd> --help' for detailed options.\n"
        , stdout);
    fflush(stdout);
    return 0;
}

/* ===================== 命令表 ===================== */

static const cli_cmd_t g_cmds[] = {
    { "help",        "Show command list",    NULL,                   cmd_help,        NULL },
    { "status",      "Show state/counters",  NULL,                   cmd_status,      NULL },
    { "sniff",       "Start promisc sniff",  "<1-14|auto> [opts]", cmd_sniff,       sniff_arg_reset },
    { "stop",        "Stop sniff/inject",    NULL,                   cmd_stop,        NULL },
    { "deauth",      "Deauth inject",        "-b <bssid> [opts]",    cmd_deauth,      deauth_arg_reset },
    { "beaconflood", "Beacon flood",         "-p <prefix> [opts]",   cmd_beaconflood, beacon_arg_reset },
    { "probeflood",  "Probe req flood",      "[opts]",               cmd_probeflood,  probe_arg_reset },
    { "http",        "HTTP REST API",        "<start|stop|status>",  cmd_http,        http_arg_reset },
    { "export",      "Export data",          "<csv|json>",           cmd_export,      export_arg_reset },
    { "dump",        "Dump tables",          "<aps|clients|eapols|all>", cmd_dump,   dump_arg_reset },
};
#define NUM_CMDS  (sizeof(g_cmds) / sizeof(g_cmds[0]))

static const cli_cmd_t *find_cmd(const char *name)
{
    for (size_t i = 0; i < NUM_CMDS; i++) {
        if (strcmp(g_cmds[i].name, name) == 0) return &g_cmds[i];
    }
    return NULL;
}

/* ===================== 执行一行命令 ===================== */

static int exec_line(char *line)
{
    static char *argv[MAX_ARGC];

    char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return 0;

    int argc = split_args(line, argv, MAX_ARGC);
    if (argc == 0) return 0;

    const cli_cmd_t *c = find_cmd(argv[0]);
    if (!c) {
        printf("Unknown command: %s  (type 'help')\n", argv[0]);
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
            
            if (at && n > 0) arg_print_glossary(stdout, at, "  %-30s %s\n");
        }
        fflush(stdout);
        return 0;
    }

    if (c->arg_reset) c->arg_reset();
    return c->func(argc, argv);
}

/* ===================== REPL 主循环 ===================== */

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

    static char line[MAX_CMDLINE];

    while (1) {
        fputs("rftool> ", stdout);
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }

        exec_line(line);
    }

    return ESP_OK;
}
