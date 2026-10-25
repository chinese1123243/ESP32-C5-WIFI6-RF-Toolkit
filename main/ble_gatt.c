/*
 * ble_gatt.c: BLE GATT 枚举实现
 *
 * 所有回调都跑在 NimBLE host 任务上下文, 里面只记录不打印 (打印会拖慢 host
 * 任务, 卡住 BLE 事件处理). 输出由一个轮询任务统一发.
 *
 * 步骤链 (每一步的结束回调里启动下一步):
 *   connect -> disc_all_svcs -> 逐服务 disc_all_chrs -> 逐特征 disc_all_dscs
 *            -> 逐特征 gattc_read -> disconnect
 */
#include "ble_gatt.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "nimble/ble.h"

#include "ble_scan.h"

static const char *TAG = "BTGATT";

/* 16 位 UUID 统一转成 128 位 (蓝牙 Base UUID), 输出时再决定打短形式还是全串 */
static void uuid_to_128(const ble_uuid_any_t *u, uint8_t out[16])
{
    if (u->u.type == BLE_UUID_TYPE_16) {
        memset(out, 0, 16);
        out[0] = (uint8_t)(u->u16.value & 0xFF);
        out[1] = (uint8_t)(u->u16.value >> 8);
        out[6] = 0x10; out[7] = 0x00;
        out[8] = 0x80; out[9] = 0x00;
        out[10] = 0x00; out[11] = 0x80;
        out[12] = 0x5F; out[13] = 0x9B;
        out[14] = 0x34; out[15] = 0xFB;
    } else {
        memcpy(out, u->u128.value, 16);
    }
}

static bool uuid_is_16(const ble_uuid_any_t *u)
{
    return u->u.type == BLE_UUID_TYPE_16;
}

typedef struct {
    uint16_t hstart, hend;
    uint8_t  uuid[16];
    bool     short_uuid;
} bg_svc_t;

typedef struct {
    uint16_t hstart, hend, val_h;
    uint16_t svc;         /* 所属服务下标, 用于算描述符范围 */
    uint8_t  uuid[16];
    bool     short_uuid;
    uint8_t  props;
} bg_chr_t;

typedef struct {
    uint16_t handle;
    uint16_t chr;
    uint8_t  uuid[16];
    bool     short_uuid;
} bg_dsc_t;

typedef struct {
    uint16_t handle;
    uint16_t len;
    uint8_t  data[64];
} bg_val_t;

static bg_svc_t *s_svc = NULL;
static bg_chr_t *s_chr = NULL;
static bg_dsc_t *s_dsc = NULL;
static bg_val_t *s_val = NULL;

static int s_nsvc = 0, s_nchr = 0, s_ndsc = 0, s_nval = 0;

enum { ST_IDLE = 0, ST_CONNECT, ST_SVCS, ST_CHRS, ST_DSCS, ST_READS, ST_OVER };

static _Atomic int      s_step    = ST_IDLE;
static _Atomic int      s_cur_svc = 0;
static _Atomic int      s_cur_chr = 0;
static _Atomic uint16_t s_conn    = 0xFFFF;
static _Atomic bool     s_on      = false;
static _Atomic bool     s_failed  = false;
static _Atomic bool     s_conn_evt = false;   /* 连接结果到了 */
static _Atomic uint32_t s_over_t0  = 0;       /* 进入 ST_OVER 的时刻 */
static _Atomic int      s_last_step = -1;     /* 上一步的 s_step, 用于卡住检测 */
static _Atomic uint32_t s_step_t0   = 0;      /* 当前步骤开始的时刻 */
static _Atomic int      s_stuck     = 0;      /* 连续卡住次数 */
static _Atomic bool     s_conn_ok  = false;
static _Atomic bool     s_disc_evt = false;
static uint8_t          s_addr[6];
static int8_t           s_rssi    = 0;
static uint32_t         s_timeout = 10000;
static _Atomic uint32_t s_t0      = 0;
static TaskHandle_t     s_task    = NULL;

static const char *props_str(uint8_t p)
{
    static char b[16];
    int n = 0;
    if (p & BLE_GATT_CHR_PROP_BROADCAST)     b[n++] = 'B';
    if (p & BLE_GATT_CHR_PROP_READ)          b[n++] = 'R';
    if (p & BLE_GATT_CHR_PROP_WRITE_NO_RSP)  b[n++] = 'w';
    if (p & BLE_GATT_CHR_PROP_WRITE)         b[n++] = 'W';
    if (p & BLE_GATT_CHR_PROP_NOTIFY)        b[n++] = 'N';
    if (p & BLE_GATT_CHR_PROP_INDICATE)      b[n++] = 'I';
    if (p & BLE_GATT_CHR_PROP_AUTH_SIGN_WRITE) b[n++] = 'S';
    if (p & BLE_GATT_CHR_PROP_EXTENDED)      b[n++] = 'E';
    b[n] = '\0';
    if (n == 0) return "-";
    return b;
}

static void print_uuid(const uint8_t u[16], bool short_form)
{
    if (short_form) {
        printf("0x%02x%02x", u[1], u[0]);
    } else {
        for (int i = 15; i >= 0; i--) printf("%02x", u[i]);
    }
}

static void flush_results(void)
{
    char a[18];
    /* s_addr 是 NimBLE 的小端形式, 反着打才是习惯的 MAC 写法 */
    snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
             s_addr[5], s_addr[4], s_addr[3], s_addr[2], s_addr[1], s_addr[0]);
    printf("META,BTGATT,CONN,addr,%s,rssi,%d\n", a, (int)s_rssi);

    for (int i = 0; i < s_nsvc; i++) {
        printf("META,BTGATT,SVC,uuid,");
        print_uuid(s_svc[i].uuid, s_svc[i].short_uuid);
        printf(",hstart,%u,hend,%u\n",
               (unsigned)s_svc[i].hstart, (unsigned)s_svc[i].hend);
    }
    for (int i = 0; i < s_nchr; i++) {
        printf("META,BTGATT,CHR,uuid,");
        print_uuid(s_chr[i].uuid, s_chr[i].short_uuid);
        printf(",hstart,%u,hend,%u,val,%u,props,%s\n",
               (unsigned)s_chr[i].hstart, (unsigned)s_chr[i].hend,
               (unsigned)s_chr[i].val_h, props_str(s_chr[i].props));
    }
    for (int i = 0; i < s_ndsc; i++) {
        printf("META,BTGATT,DSC,uuid,");
        print_uuid(s_dsc[i].uuid, s_dsc[i].short_uuid);
        printf(",handle,%u,chr,%u\n",
               (unsigned)s_dsc[i].handle, (unsigned)s_dsc[i].chr);
    }
    for (int i = 0; i < s_nval; i++) {
        printf("META,BTGATT,VAL,handle,%u,len,%u,hex,",
               (unsigned)s_val[i].handle, (unsigned)s_val[i].len);
        for (int k = 0; k < s_val[i].len; k++) printf("%02x", s_val[i].data[k]);
        printf("\n");
    }
    uint32_t ms = (uint32_t)(esp_timer_get_time() / 1000) - s_t0;
    printf("META,BTGATT,DONE,svcs,%d,chrs,%d,dscs,%d,reads,%d,ms,%u,result,%s\n",
           s_nsvc, s_nchr, s_ndsc, s_nval, (unsigned)ms,
           s_failed ? "FAIL" : "ok");
    fflush(stdout);
}

/* 步骤推进: 每个 GATT 过程的结束回调里调 */

static void kick(void);
static int  bg_on_svc(uint16_t, const struct ble_gatt_error *,
                      const struct ble_gatt_svc *, void *);
static int  bg_on_chr(uint16_t, const struct ble_gatt_error *,
                      const struct ble_gatt_chr *, void *);
static int  bg_on_dsc(uint16_t, const struct ble_gatt_error *, uint16_t,
                      const struct ble_gatt_dsc *, void *);
static int  bg_on_read(uint16_t, const struct ble_gatt_error *,
                       struct ble_gatt_attr *, void *);

static void kick(void)
{
    if (!atomic_load(&s_on)) return;

    switch (atomic_load(&s_step)) {
    case ST_SVCS:
        ble_gattc_disc_all_svcs(s_conn, bg_on_svc, NULL);
        break;

    case ST_CHRS:
        if (atomic_load(&s_cur_svc) < s_nsvc) {
            int i = atomic_load(&s_cur_svc);
            ble_gattc_disc_all_chrs(s_conn, s_svc[i].hstart, s_svc[i].hend,
                                    bg_on_chr, NULL);
        } else {
            atomic_store(&s_cur_chr, 0);
            atomic_store(&s_step, ST_DSCS);
            kick();
        }
        break;

    case ST_DSCS: {
        int i = atomic_load(&s_cur_chr);
        if (i >= s_nchr) {
            atomic_store(&s_step, ST_OVER);
            break;
        }
        uint16_t dstart = s_chr[i].val_h;
        /* 上界取两个约束的较小值: 所属服务的 end_handle, 和下一个特征的
         * def_handle-1. 只取后者会越界摸到下一个服务的声明上 (实测小米体重秤
         * 在 0x1801 的最后一个特征上抓到了 0x1800 的 service declaration). */
        uint16_t svc_end = 0xFFFF;
        for (int k = 0; k < s_nsvc; k++) {
            if (s_chr[i].svc == k) { svc_end = s_svc[k].hend; break; }
        }
        uint16_t next_def = (i + 1 < s_nchr) ? (uint16_t)(s_chr[i + 1].hstart - 1)
                                             : (uint16_t)0xFFFF;
        uint16_t dend = (svc_end < next_def) ? svc_end : next_def;
        if (dend < dstart) dend = dstart;
        s_chr[i].hend = dend;
        ble_gattc_disc_all_dscs(s_conn, dstart, dend, bg_on_dsc, NULL);
        break;
    }

    case ST_READS: {
        int i = atomic_load(&s_cur_chr);
        /* 顺着跳过没有 READ 位的特征. 直接对不可读的特征发 read, 设备回
         * ATT error 之后 NimBLE 不一定还会调回调, 状态机就卡死到总超时
         * (实测小米体重秤 16 个特征里 13 个不可读, 全卡住). */
        while (i < s_nchr && !(s_chr[i].props & BLE_GATT_CHR_PROP_READ)) i++;
        atomic_store(&s_cur_chr, i);
        if (i >= s_nchr) {
            atomic_store(&s_step, ST_OVER);
            break;
        }
        /* 描述符发现被看门狗跳过时 hend 还是 0, 这里补一个保守值,
         * 至少输出里不会一半是 0. */
        if (s_chr[i].hend == 0) s_chr[i].hend = s_chr[i].val_h;
        ble_gattc_read(s_conn, s_chr[i].val_h, bg_on_read, NULL);
        break;
    }

    case ST_OVER:
        /* 主动断开, 断开事件由轮询任务收尾 (见 gatt_task 的 2 秒兜底) */
        atomic_store(&s_over_t0, (uint32_t)(esp_timer_get_time() / 1000));
        if (s_conn != 0xFFFF) {
            ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
        }
        break;

    default:
        break;
    }
}

/* 步骤看门狗: NimBLE 的某些 GATT 过程不保证回调一定来 (实测对不可读的
 * 特征发 read, 或者对空范围发描述符发现, 回调就再也不出现). 一个步骤超过
 * BG_STEP_STUCK_MS 没动静就按"当前步骤已完成"强行推下一步, 推太多次仍然
 * 没动静才判失败. 没有这个看门狗, 枚举会一直干等到总超时. */
#define BG_STEP_STUCK_MS 1500
#define BG_STUCK_MAX     6

static void force_advance(void)
{
    switch (atomic_load(&s_step)) {
    case ST_SVCS:
        ESP_LOGW(TAG, "svc step stuck, force to chrs");
        atomic_store(&s_cur_svc, 0);
        atomic_store(&s_step, ST_CHRS);
        break;
    case ST_CHRS:
        ESP_LOGW(TAG, "chr step stuck (svc %d), skip", atomic_load(&s_cur_svc));
        atomic_store(&s_cur_svc, atomic_load(&s_cur_svc) + 1);
        if (atomic_load(&s_cur_svc) >= s_nsvc) {
            atomic_store(&s_cur_chr, 0);
            atomic_store(&s_step, ST_DSCS);
        }
        break;
    case ST_DSCS:
        ESP_LOGW(TAG, "dsc step stuck (chr %d), skip", atomic_load(&s_cur_chr));
        atomic_store(&s_step, ST_READS);
        break;
    case ST_READS:
        ESP_LOGW(TAG, "read step stuck (chr %d), skip", atomic_load(&s_cur_chr));
        atomic_store(&s_cur_chr, atomic_load(&s_cur_chr) + 1);
        atomic_store(&s_step, ST_DSCS);
        break;
    default:
        return;
    }
    kick();
}

/* GATT 回调 */

static int bg_on_svc(uint16_t conn_handle, const struct ble_gatt_error *error,
                     const struct ble_gatt_svc *service, void *arg)
{
    (void)conn_handle; (void)arg;
    if (service) {
        if (s_nsvc < BG_MAX_SVC && s_svc) {
            bg_svc_t *d = &s_svc[s_nsvc++];
            d->hstart = service->start_handle;
            d->hend   = service->end_handle;
            d->short_uuid = uuid_is_16(&service->uuid);
            uuid_to_128(&service->uuid, d->uuid);
        }
        return 0;
    }
    /* service == NULL: 过程结束.
     * 不要一见到错误码就停: 设备在句柄末尾回什么码并不统一, 实测小米体重秤
     * 回 0x0e (UNLIKELY) 而不是规范的 0x0a (ATTR_NOT_FOUND), 但四个服务
     * 都已经拿到了. 只要不是连接层面的错误, 就拿着已发现的继续往下走. */
    if (error && error->status != 0 &&
        error->status != BLE_ATT_ERR_ATTR_NOT_FOUND &&
        error->status != BLE_ATT_ERR_UNLIKELY) {
        ESP_LOGW(TAG, "svc discovery failed: status=%d", error->status);
        atomic_store(&s_failed, true);
        atomic_store(&s_step, ST_OVER);
        return 0;
    }
    if (error && error->status != 0) {
        ESP_LOGW(TAG, "svc discovery ended with status=%d, keep %d svcs",
                 error->status, s_nsvc);
    }
    atomic_store(&s_cur_svc, 0);
    atomic_store(&s_step, ST_CHRS);
    kick();
    return 0;
}

static int bg_on_chr(uint16_t conn_handle, const struct ble_gatt_error *error,
                     const struct ble_gatt_chr *chr, void *arg)
{
    (void)conn_handle; (void)arg;
    if (chr) {
        if (s_nchr < BG_MAX_CHR && s_chr) {
            bg_chr_t *d = &s_chr[s_nchr++];
            d->hstart = chr->def_handle;
            d->val_h  = chr->val_handle;
            d->svc    = (uint16_t)atomic_load(&s_cur_svc);
            /* hend 留到 kick 里算: 描述符范围 = val_h .. 下一个特征 def_handle-1,
             * 服务内最后一个特征则收到服务的 end_handle. 结构体本身没有
             * end_handle 字段, 只能这么推. */
            d->props  = chr->properties;
            d->short_uuid = uuid_is_16(&chr->uuid);
            uuid_to_128(&chr->uuid, d->uuid);
        }
        return 0;
    }
    if (error && error->status != 0 &&
        error->status != BLE_ATT_ERR_ATTR_NOT_FOUND &&
        error->status != BLE_ATT_ERR_UNLIKELY) {
        ESP_LOGW(TAG, "chr discovery failed: status=%d", error->status);
        atomic_store(&s_failed, true);
        atomic_store(&s_step, ST_OVER);
        return 0;
    }
    /* 这个服务的特征找完了, 换下一个 */
    int cur = atomic_load(&s_cur_svc) + 1;
    atomic_store(&s_cur_svc, cur);
    if (cur < s_nsvc) {
        atomic_store(&s_step, ST_CHRS);
    } else {
        atomic_store(&s_cur_chr, 0);
        atomic_store(&s_step, ST_DSCS);
    }
    kick();
    return 0;
}

static int bg_on_dsc(uint16_t conn_handle, const struct ble_gatt_error *error,
                     uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc,
                     void *arg)
{
    (void)conn_handle; (void)chr_val_handle; (void)arg;
    if (dsc) {
        if (s_ndsc < BG_MAX_DSC && s_dsc) {
            bg_dsc_t *d = &s_dsc[s_ndsc];
            d->handle = dsc->handle;
            d->chr    = (uint16_t)atomic_load(&s_cur_chr);
            d->short_uuid = uuid_is_16(&dsc->uuid);
            uuid_to_128(&dsc->uuid, d->uuid);
            s_ndsc++;
        }
        return 0;
    }
    if (error && error->status != 0) {
        /* 没有描述符很正常 (status=ATT_ERR_ATTR_NOT_FOUND), 不算失败 */
    }
    atomic_store(&s_step, ST_READS);
    kick();
    return 0;
}

static int bg_on_read(uint16_t conn_handle, const struct ble_gatt_error *error,
                      struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)arg;
    if (attr && attr->om) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        if (len > sizeof(s_val->data)) len = sizeof(s_val->data);
        if (s_nval < BG_MAX_VAL && s_val) {
            bg_val_t *d = &s_val[s_nval];
            d->handle = attr->handle;
            d->len    = len;
            int rc = os_mbuf_copydata(attr->om, 0, len, d->data);
            if (rc == 0) s_nval++;
        }
    } else if (error) {
        /* 读不了 (没权限/不存在) 是常态, 记一笔 debug 就过 */
        ESP_LOGD(TAG, "read status=%d", error->status);
    }
    int cur = atomic_load(&s_cur_chr) + 1;
    atomic_store(&s_cur_chr, cur);
    if (cur < s_nchr) {
        atomic_store(&s_step, ST_DSCS);
    } else {
        atomic_store(&s_step, ST_OVER);
    }
    kick();
    return 0;
}

/* GAP 连接回调 */

static int bg_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        atomic_store(&s_conn_evt, true);
        if (event->connect.status == 0) {
            atomic_store(&s_conn, event->connect.conn_handle);
            atomic_store(&s_conn_ok, true);
            atomic_store(&s_step, ST_SVCS);
            kick();
        } else {
            atomic_store(&s_conn_ok, false);
            atomic_store(&s_failed, true);
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        atomic_store(&s_disc_evt, true);
        atomic_store(&s_conn, 0xFFFF);
        return 0;

    default:
        return 0;
    }
}

/* 轮询任务: 发结果 + 超时看门 */

static void gatt_task(void *pv)
{
    (void)pv;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100));

        if (!atomic_load(&s_on)) break;

        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        bool timeout = (now - atomic_load(&s_t0)) >= s_timeout;

        /* 步骤看门狗 */
        int cur_step = atomic_load(&s_step);
        if (cur_step != atomic_load(&s_last_step)) {
            atomic_store(&s_last_step, cur_step);
            atomic_store(&s_step_t0, now);
            atomic_store(&s_stuck, 0);
        } else if (cur_step != ST_IDLE && cur_step != ST_OVER &&
                   (now - atomic_load(&s_step_t0)) >= BG_STEP_STUCK_MS) {
            int n = atomic_load(&s_stuck) + 1;
            atomic_store(&s_stuck, n);
            atomic_store(&s_step_t0, now);
            if (n >= BG_STUCK_MAX) {
                ESP_LOGW(TAG, "step %d stuck %d times, give up", cur_step, n);
                atomic_store(&s_failed, true);
                atomic_store(&s_step, ST_OVER);
                continue;
            }
            force_advance();
        }

        if (atomic_load(&s_step) == ST_OVER) {
            /* kick 里已经发起 terminate. 等断开事件, 但设备不理会 terminate 时
             * 不能干等满总超时: 进入 OVER 之后最多再给 2 秒. */
            uint32_t over_ms = now - atomic_load(&s_over_t0);
            if (atomic_load(&s_disc_evt) || timeout || over_ms >= 2000) {
                flush_results();
                break;
            }
            continue;
        }

        if (timeout) {
            ESP_LOGW(TAG, "timeout at step=%d", atomic_load(&s_step));
            atomic_store(&s_failed, true);
            if (s_conn != 0xFFFF) {
                ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
                vTaskDelay(pdMS_TO_TICKS(300));
            }
            flush_results();
            break;
        }
    }

    /* 清理 */
    if (s_conn != 0xFFFF) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    atomic_store(&s_on, false);
    atomic_store(&s_step, ST_IDLE);
    s_task = NULL;
    vTaskDelete(NULL);
}

/* 对外接口 */

static bool alloc_tables(void)
{
    if (s_svc && s_chr && s_dsc && s_val) return true;
    if (!s_svc) s_svc = heap_caps_calloc(BG_MAX_SVC, sizeof(bg_svc_t),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_chr) s_chr = heap_caps_calloc(BG_MAX_CHR, sizeof(bg_chr_t),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_dsc) s_dsc = heap_caps_calloc(BG_MAX_DSC, sizeof(bg_dsc_t),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_val) s_val = heap_caps_calloc(BG_MAX_VAL, sizeof(bg_val_t),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_svc) s_svc = calloc(BG_MAX_SVC, sizeof(bg_svc_t));
    if (!s_chr) s_chr = calloc(BG_MAX_CHR, sizeof(bg_chr_t));
    if (!s_dsc) s_dsc = calloc(BG_MAX_DSC, sizeof(bg_dsc_t));
    if (!s_val) s_val = calloc(BG_MAX_VAL, sizeof(bg_val_t));
    return s_svc && s_chr && s_dsc && s_val;
}

esp_err_t gatt_start(const uint8_t addr[6], uint32_t timeout_ms)
{
    if (atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;
    if (!ble_hs_synced()) {
        ESP_LOGW(TAG, "host not synced");
        return ESP_ERR_INVALID_STATE;
    }
    if (!alloc_tables()) return ESP_ERR_NO_MEM;

    /* 扫描与连接不能同时: 先停. 停了之后 ble_scan 表还在, 只是不再更新. */
    if (ble_scan_is_on()) ble_scan_stop();

    memcpy(s_addr, addr, 6);
    s_nsvc = s_nchr = s_ndsc = s_nval = 0;
    atomic_store(&s_failed, false);
    atomic_store(&s_conn_evt, false);
    atomic_store(&s_conn_ok, false);
    atomic_store(&s_disc_evt, false);
    atomic_store(&s_conn, 0xFFFF);
    atomic_store(&s_step, ST_CONNECT);
    atomic_store(&s_t0, (uint32_t)(esp_timer_get_time() / 1000));
    s_timeout = timeout_ms ? timeout_ms : 10000;

    /* 从扫描表里补 RSSI (顺带能把地址类型带上) */
    int n = ble_scan_count();
    for (int i = 0; i < n; i++) {
        uint8_t a[6]; int8_t r; const char *nm;
        if (ble_scan_get(i, a, &r, &nm) && memcmp(a, addr, 6) == 0) {
            s_rssi = r;
            break;
        }
    }

    ble_addr_t peer;
    memcpy(peer.val, addr, 6);
    /* 地址类型默认 public; 随机地址设备连不上时由调用方重试 random */
    peer.type = BLE_ADDR_PUBLIC;

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer, 10000, NULL,
                             bg_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "connect rc=%d", rc);
        return ESP_FAIL;
    }
    atomic_store(&s_on, true);

    if (!s_task) {
        if (xTaskCreate(gatt_task, "btgatt", 4096, NULL, 3, &s_task) != pdPASS) {
            atomic_store(&s_on, false);
            return ESP_ERR_NO_MEM;
        }
    }
    ESP_LOGI(TAG, "enum started");
    return ESP_OK;
}

esp_err_t gatt_stop(void)
{
    if (!atomic_load(&s_on)) return ESP_ERR_INVALID_STATE;
    atomic_store(&s_step, ST_OVER);
    if (s_conn != 0xFFFF) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
    }
    return ESP_OK;
}

bool gatt_is_on(void) { return atomic_load(&s_on); }

void gatt_status(void)
{
    const char *st[] = {"idle", "connect", "svcs", "chrs", "dscs", "reads", "over"};
    int s = atomic_load(&s_step);
    if (s < 0 || s > 6) s = 0;
    printf("META,BTGATT,STATUS,on,%d,step,%s,conn,%u,svcs,%d,chrs,%d,dscs,%d,reads,%d\n",
           gatt_is_on() ? 1 : 0, st[s],
           (unsigned)atomic_load(&s_conn), s_nsvc, s_nchr, s_ndsc, s_nval);
    fflush(stdout);
}
