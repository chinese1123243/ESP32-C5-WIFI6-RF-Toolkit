/*
 * ble_adv.c: BLE 广播伪造 (iBeacon / Eddystone-URL)
 *
 * 单实例挂起/恢复: 停 NUS 广播 -> 设伪造数据 -> 启动非连接广播 -> 停止/超时后恢复 NUS.
 * 已建立的 GATT 连接在整个过程中保持, App 可继续收发命令.
 */
#include "ble_adv.h"
#include "ble_cli.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"

#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_uuid.h"

static const char *TAG = "BLEADV";


static volatile bool           s_active = false;
static volatile bleadv_type_t  s_type   = BLEADV_NONE;
static volatile int            s_remain = 0;     /* 剩余秒数, 0 = 无限 */
static volatile int            s_dur    = 0;     /* 总时长 */

/* 超时任务: 等待停止信号或超时, 超时则自动恢复 NUS. */
static TaskHandle_t      s_timeout_task = NULL;
static SemaphoreHandle_t s_stop_sem     = NULL;

/* 当前参数 (status 回显用) */
static char     s_ibeacon_uuid[40] = {0};
static uint16_t s_ibeacon_major = 0;
static uint16_t s_ibeacon_minor = 0;
static char     s_eddystone_url[128] = {0};

/* 工具: UUID 解析 */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* uuid: 32 hex chars (dashes ignored). 输出 16 字节到 out. 返回 0 成功. */
static int parse_uuid16(const char *uuid, uint8_t out[16])
{
    if (!uuid) return -1;
    int hi = -1, idx = 0;
    for (const char *p = uuid; *p && idx < 16; p++) {
        if (*p == '-') continue;
        int v = hexval(*p);
        if (v < 0) return -1;
        if (hi < 0) { hi = v; }
        else { out[idx++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    return (idx == 16 && hi < 0) ? 0 : -1;
}

/* 工具: Eddystone URL 编码
 * 把 "https://example.com/path" 编成 [scheme_prefix][encoded_body].
 * scheme: 0=http://www. 1=https://www. 2=http:// 3=https://
 * body 中可替换的后缀用压缩码 (0x00-0x0d), 其余 ASCII 直传.
 * 最大输出长度由调用方保证 (Eddystone-URL 总长受 31 字节广播限制). */

static const char *s_schemes[] = {
    "http://www.",   /* 0x00 */
    "https://www.",  /* 0x01 */
    "http://",       /* 0x02 */
    "https://",      /* 0x03 */
};

static const char *s_suffixes[] = {
    ".com/",  ".org/",  ".edu/",  ".net/",
    ".info/", ".biz/",  ".gov/",  ".com",
    ".org",   ".edu",   ".net",   ".info",
    ".biz",   ".gov",
};

/* 编码 URL 到 out, 返回编码后字节数 (不含 scheme 字节? 含).
 * out 第 0 字节为 scheme prefix, 后续为编码后的 body. */
static int eddystone_encode_url(const char *url, uint8_t *out, int out_max)
{
    if (!url || !out || out_max < 2) return -1;

    const char *body = url;
    uint8_t scheme = 0x02; /* default http:// */
    for (int i = 0; i < 4; i++) {
        size_t slen = strlen(s_schemes[i]);
        if (strncasecmp(url, s_schemes[i], slen) == 0) {
            scheme = (uint8_t)i;
            body = url + slen;
            break;
        }
    }

    int n = 0;
    out[n++] = scheme;
    while (*body && n < out_max) {
        int matched = -1, mlen = 0;
        for (int i = 0; i < (int)(sizeof(s_suffixes)/sizeof(s_suffixes[0])); i++) {
            size_t sl = strlen(s_suffixes[i]);
            if (strncmp(body, s_suffixes[i], sl) == 0) {
                matched = i;
                mlen = (int)sl;
                break;
            }
        }
        if (matched >= 0) {
            out[n++] = (uint8_t)matched;
            body += mlen;
        } else {
            unsigned char c = (unsigned char)*body;
            if (c < 0x20 || c > 0x7e) {
                /* 非可打印 ASCII, 用 '.' 代替 */
                out[n++] = '.';
            } else {
                out[n++] = c;
            }
            body++;
        }
    }
    return n;
}

/* GAP 回调 (伪造广播专用)
 * 与 NUS 的 gap_event_cb 不同: 伪造广播为非连接, 不会收到 CONNECT/DISCONNECT.
 * ADV_COMPLETE 时不自动重启 (由超时任务或 stop 命令恢复 NUS). */
static int bleadv_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "forged adv complete (reason=%d)", event->adv_complete.reason);
        break;
    default:
        break;
    }
    return 0;
}

/* 核心: 启动伪造广播 */

/* 公共前置: 挂起 NUS, 清 rsp fields (避免 NUS 的 scan response 残留). */
static int forged_adv_begin(void)
{
    int rc = ble_cli_adv_suspend();
    if (rc != 0) return rc;

    /* 清空 scan response (NUS 之前设置了设备名, 伪造广播不需要也不应带) */
    struct ble_hs_adv_fields rsp;
    memset(&rsp, 0, sizeof(rsp));
    ble_gap_adv_rsp_set_fields(&rsp);

    return 0;
}

/* 启动非连接广播, duration_ms = BLE_HS_FOREVER (由我们的超时任务控制时长). */
static int forged_adv_start_nonconn(void)
{
    struct ble_gap_adv_params p;
    memset(&p, 0, sizeof(p));
    p.conn_mode = BLE_GAP_CONN_MODE_NON;
    p.disc_mode = BLE_GAP_DISC_MODE_GEN;
    int rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                               &p, bleadv_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "forged adv_start failed: %d", rc);
    }
    return rc;
}


static void bleadv_timeout_task(void *pv)
{
    int sec = (int)(intptr_t)pv;
    bool expired = true;

    for (int i = 0; i < sec; i++) {
        if (xSemaphoreTake(s_stop_sem, pdMS_TO_TICKS(1000)) == pdTRUE) {
            /* 收到停止信号, 由调用方负责恢复 NUS */
            ESP_LOGI(TAG, "timeout task: stop signal received");
            expired = false;
            break;
        }
        if (s_remain > 0) s_remain--;
    }

    /* 单一出口, 句柄在这里清.
     * 以前"收到停止信号"这条分支是取到信号就 vTaskDelete 走人, 句柄没清空;
     * 之后 start_timeout_task 拿到的就是一块已经删掉的任务句柄, 对它
     * vTaskDelete 删的是别的任务 (FreeRTOS 里句柄本质是 TCB 指针). */
    s_timeout_task = NULL;

    if (expired) {
        ESP_LOGI(TAG, "timeout expired, auto-restore NUS");
        s_active = false;
        s_remain = 0;
        ble_gap_adv_stop();
        ble_cli_adv_resume();
        s_type = BLEADV_NONE;
        /* 通知 App: 超时任务不在 ble_exec_task 上下文, stdout 未被捕获,
         * 必须走 ble_event_post 才能送到手机. */
        ble_event_post("META,BLE,ADV,STOP\n");
    }
    vTaskDelete(NULL);
}

static void start_timeout_task(int sec)
{
    if (sec <= 0) return;  /* 无限模式, 不启动超时任务 */

    /* 让上一个超时任务自己退出, 而不是在这里 vTaskDelete 它:
     * 从外面删时它可能正停在 ble_gap_adv_stop() 里, 一删就把协议栈状态
     * 留在半截. 先请求停止 + 有限等待, 实在不退才兜底强删. */
    if (s_timeout_task) {
        TaskHandle_t old = s_timeout_task;
        if (s_stop_sem) xSemaphoreGive(s_stop_sem);
        for (int i = 0; i < 150 && s_timeout_task == old; i++) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        if (s_timeout_task == old) {
            ESP_LOGW(TAG, "old timeout task did not exit; force delete");
            s_timeout_task = NULL;
            vTaskDelete(old);
        }
    }

    /* 清掉可能残留的停止令牌.
     * 不清的话, 新任务第一次 xSemaphoreTake 就会立刻拿到它并退出:
     * 表现是"明明设了 60 秒, 1 秒不到就自己停了". */
    if (s_stop_sem) xSemaphoreTake(s_stop_sem, 0);

    s_remain = sec;
    s_dur    = sec;
    BaseType_t r = xTaskCreate(bleadv_timeout_task, "bleadv_to", 3072,
                               (void *)(intptr_t)sec, 4, &s_timeout_task);
    if (r != pdPASS) {
        ESP_LOGW(TAG, "timeout task create failed");
        s_timeout_task = NULL;
    }
}

int bleadv_ibeacon(const char *uuid, uint16_t major, uint16_t minor, int sec)
{
    uint8_t uuid16[16];
    if (parse_uuid16(uuid, uuid16) != 0) {
        printf("META,BLE,ADV,ERR,msg,invalid uuid\n");
        fflush(stdout);
        return -1;
    }

    /* 若已在运行, 先停 */
    if (s_active) bleadv_stop();

    int rc = forged_adv_begin();
    if (rc != 0) {
        printf("META,BLE,ADV,ERR,msg,suspend nus failed\n");
        fflush(stdout);
        return rc;
    }

    /* iBeacon Manufacturer Specific Data:
     *   [0..1]  Company ID 0x004C (Apple) 小端 -> 4C 00
     *   [2]     Beacon type 0x02
     *   [3]     Length 0x15 (21 字节)
     *   [4..19] 16-byte UUID
     *   [20..21] Major (大端)
     *   [22..23] Minor (大端)
     *   [24]    TX power (signed dBm, 设为 0xC5 = -59 dBm 标称值) */
    uint8_t mfg[25];
    mfg[0] = 0x4C;  /* Apple company ID LE */
    mfg[1] = 0x00;
    mfg[2] = 0x02;  /* proximity beacon */
    mfg[3] = 0x15;  /* length = 21 */
    memcpy(mfg + 4, uuid16, 16);
    mfg[20] = (uint8_t)(major >> 8);
    mfg[21] = (uint8_t)(major & 0xff);
    mfg[22] = (uint8_t)(minor >> 8);
    mfg[23] = (uint8_t)(minor & 0xff);
    mfg[24] = 0xC5;  /* -59 dBm at 1m (典型 iBeacon 校准值) */

    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.mfg_data = mfg;
    fields.mfg_data_len = sizeof(mfg);
    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ibeacon adv_set_fields: %d", rc);
        ble_cli_adv_resume();
        printf("META,BLE,ADV,ERR,msg,set fields failed\n");
        fflush(stdout);
        return rc;
    }

    rc = forged_adv_start_nonconn();
    if (rc != 0) {
        ble_cli_adv_resume();
        printf("META,BLE,ADV,ERR,msg,adv start failed\n");
        fflush(stdout);
        return rc;
    }

    s_active = true;
    s_type   = BLEADV_IBEACON;
    s_ibeacon_major = major;
    s_ibeacon_minor = minor;
    strncpy(s_ibeacon_uuid, uuid ? uuid : "", sizeof(s_ibeacon_uuid) - 1);
    s_ibeacon_uuid[sizeof(s_ibeacon_uuid) - 1] = 0;

    start_timeout_task(sec);

    /* META 回执: uuid 用原始字符串 */
    printf("META,BLE,ADV,START,type,ibeacon,dur,%d,uuid,%s,major,%u,minor,%u\n",
           sec, s_ibeacon_uuid, (unsigned)major, (unsigned)minor);
    fflush(stdout);
    ESP_LOGI(TAG, "iBeacon started: uuid=%s major=%u minor=%u sec=%d",
             uuid, major, minor, sec);
    return 0;
}

/* Eddystone-URL */

int bleadv_eddystone(const char *url, int sec)
{
    if (!url || !*url) {
        printf("META,BLE,ADV,ERR,msg,empty url\n");
        fflush(stdout);
        return -1;
    }

    if (s_active) bleadv_stop();

    /* 编码 URL */
    uint8_t enc[64];
    int enc_len = eddystone_encode_url(url, enc, sizeof(enc));
    if (enc_len <= 0) {
        printf("META,BLE,ADV,ERR,msg,url encode failed\n");
        fflush(stdout);
        return -1;
    }

    /* 广播包预算 (31 字节):
     *   Flags:        3
     *   SVC UUID16:   4  (03 03 AA FE)
     *   SVC Data:     2 (len+type) + 2 (uuid) + enc_len
     * 剩余给 enc_len 的空间 = 31 - 3 - 4 - (2+2) = 20 字节.
     * Eddystone-URL 帧格式: [uuid 0xFEAA LE][frame 0x10][tx_power][scheme][body...]
     * svc_data_uuid16 = [uuid 2B][frame 1B][tx 1B][enc_len]
     * 所以 enc_len 需 <= 31 - 3 - 4 - 2 - 2 - 1 - 1 = 18 字节 */
    if (enc_len > 18) {
        printf("META,BLE,ADV,ERR,msg,url too long for legacy adv\n");
        fflush(stdout);
        return -1;
    }

    int rc = forged_adv_begin();
    if (rc != 0) {
        printf("META,BLE,ADV,ERR,msg,suspend nus failed\n");
        fflush(stdout);
        return rc;
    }

    /* Service UUID 16 列表 (complete): 0xFEAA */
    ble_uuid16_t eddy_uuid = BLE_UUID16_INIT(0xFEAA);

    /* Service Data (type 0x16): [uuid LE 2B][frame type 1B][tx_power 1B][enc_len] */
    uint8_t svc_data[2 + 1 + 1 + 64];
    svc_data[0] = 0xAA;  /* 0xFEAA little-endian */
    svc_data[1] = 0xFE;
    svc_data[2] = 0x10;  /* Eddystone-URL frame type */
    svc_data[3] = 0xC5;  /* TX power -59 dBm */
    memcpy(svc_data + 4, enc, enc_len);
    int svc_len = 4 + enc_len;

    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids16 = &eddy_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    fields.svc_data_uuid16 = svc_data;
    fields.svc_data_uuid16_len = (uint8_t)svc_len;
    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "eddystone adv_set_fields: %d", rc);
        ble_cli_adv_resume();
        printf("META,BLE,ADV,ERR,msg,set fields failed\n");
        fflush(stdout);
        return rc;
    }

    rc = forged_adv_start_nonconn();
    if (rc != 0) {
        ble_cli_adv_resume();
        printf("META,BLE,ADV,ERR,msg,adv start failed\n");
        fflush(stdout);
        return rc;
    }

    s_active = true;
    s_type   = BLEADV_EDDYSTONE;
    strncpy(s_eddystone_url, url, sizeof(s_eddystone_url) - 1);
    s_eddystone_url[sizeof(s_eddystone_url) - 1] = 0;

    start_timeout_task(sec);

    printf("META,BLE,ADV,START,type,eddystone,dur,%d,url,%s\n", sec, url);
    fflush(stdout);
    ESP_LOGI(TAG, "Eddystone-URL started: url=%s sec=%d", url, sec);
    return 0;
}


int bleadv_stop(void)
{
    if (!s_active) {
        /* 即使未在运行, 也确保 NUS 广播已恢复 (防止挂起状态残留) */
        if (ble_cli_adv_is_suspended()) {
            ble_cli_adv_resume();
        }
        return 0;
    }

    /* 通知超时任务停止 (若在运行) */
    if (s_timeout_task) {
        xSemaphoreGive(s_stop_sem);
        s_timeout_task = NULL;  /* 任务会自行 delete */
    }

    s_active = false;
    s_remain = 0;

    ble_gap_adv_stop();
    ble_cli_adv_resume();
    s_type = BLEADV_NONE;

    printf("META,BLE,ADV,STOP\n");
    fflush(stdout);
    ESP_LOGI(TAG, "bleadv stopped, NUS resumed");
    return 0;
}


void bleadv_status(void)
{
    const char *typestr = "none";
    if (s_type == BLEADV_IBEACON)   typestr = "ibeacon";
    else if (s_type == BLEADV_EDDYSTONE) typestr = "eddystone";

    printf("META,BLE,ADV,STATUS,active,%d,type,%s,remain,%d\n",
           s_active ? 1 : 0, typestr, s_remain);
    fflush(stdout);
}

bool bleadv_is_active(void) { return s_active; }
bleadv_type_t bleadv_get_type(void) { return s_type; }
int bleadv_get_remain(void) { return s_remain; }

/* 初始化 (由 main 调用一次) */

void bleadv_init(void)
{
    if (!s_stop_sem) {
        s_stop_sem = xSemaphoreCreateBinary();
    }
}
