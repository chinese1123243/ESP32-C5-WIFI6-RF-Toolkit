/*
 * ble_cli.c: BLE GATT 服务实现 (NimBLE host)
 *
 * 流程:
 *   1. ble_cli_start() 初始化 NimBLE controller + host, 注册 GATT service
 *   2. 手机连接后向 RX_CHAR 写入命令 (单行文本)
 *   3. BLE 任务置位 capture 标志, 调用 cli_exec_line()
 *   4. 执行期间所有 stdout 输出被 _write_r 重定向到环形缓冲
 *   5. 执行完毕, 关闭 capture, 将缓冲内容通过 TX_CHAR notify 分帧回传
 */
#include "ble_cli.h"
#include "out_stream.h"
#include "cli.h"
#include "rgb_led.h"
#include "phish.h"
#include "logring.h"   /* 始终捕获 stdout 到环形缓冲 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_heap_caps.h"   /* 广播分配失败时打印内部堆, 现场定位用 */
#include "esp_err.h"
#include "esp_bt.h"   /* esp_ble_tx_power_set() */
#include "nvs_flash.h"

/* NimBLE */
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/ble_gatt.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "BLE";

/* stdout 捕获
 * 覆盖 newlib 的 _write_r (弱符号). 当 s_capture_active 为 true 时,
 * stdout(fd=1) / stderr(fd=2) 的写入被存入 s_cap_buf, 同时也透传到 UART
 * (方便调试). 否则走默认 console 输出. */

/* 捕获缓冲: 命令输出 (dump 列表可达数 KB) 会远超单条 notify 的承载能力.
 * 旧实现把整段输出塞进 8KB 缓冲, 之后一次性 notify, 但 nus_send_msg 会把
 * 单条消息截到 NUS_ASM_MAX(1024B), 于是列表只剩下头部若干行, App 表现为
 * 「扫出来了却没显示」. 现在改成: 攒够 CAP_FLUSH_LEVEL 就立刻发一片并复位,
 * 每片都 <= NUS_ASM_MAX, 任意长度的输出都能完整送到手机.
 * App 侧按 FIRST/LAST 重组 + 行缓冲, 因此分片边界落在行中间也没问题. */
#define CAP_BUF_SIZE    1024
#define CAP_FLUSH_LEVEL 512

static volatile bool  s_capture_active = false;
static char           s_cap_buf[CAP_BUF_SIZE];
static volatile int   s_cap_len = 0;
static SemaphoreHandle_t s_cap_mtx = NULL;

static void ble_notify(const char *data, int len);

/* 默认 VFS 写 (通过 --wrap=_write_r 链接后, 原 _write_r 别名变为 __real__write_r) */
extern ssize_t __real__write_r(struct _reent *r, int fd, const void *data, size_t size);

ssize_t __wrap__write_r(struct _reent *r, int fd, const void *data, size_t size)
{
    /* 始终把 stdout/stderr 推入日志环形缓冲 (无论是否 BLE 捕获) */
    if ((fd == 1 || fd == 2) && data && size > 0) {
        logring_push((const char *)data, size);
    }

    if (s_capture_active && (fd == 1 || fd == 2) && data && size > 0) {
        /* 先透传到 UART 供串口调试 (不持锁, 避免阻塞其它任务) */
        __real__write_r(r, fd, data, size);

        if (s_cap_mtx) xSemaphoreTake(s_cap_mtx, portMAX_DELAY);
        const char *p = (const char *)data;
        size_t remain = size;
        while (remain > 0) {
            int room = CAP_BUF_SIZE - s_cap_len;
            if (room <= 0) {
                /* 缓冲已满: 强制发出, 保证不丢字节 */
                int n = s_cap_len;
                s_cap_len = 0;
                if (s_cap_mtx) xSemaphoreGive(s_cap_mtx);
                ble_notify(s_cap_buf, n);
                if (s_cap_mtx) xSemaphoreTake(s_cap_mtx, portMAX_DELAY);
                room = CAP_BUF_SIZE;
            }
            int n = (int)remain < room ? (int)remain : room;
            memcpy(s_cap_buf + s_cap_len, p, n);
            s_cap_len += n;
            p += n;
            remain -= n;

            /* 攒够一半就流出, 大段输出得以分片抵达手机 */
            if (s_cap_len >= CAP_FLUSH_LEVEL) {
                int fl = s_cap_len;
                s_cap_len = 0;
                if (s_cap_mtx) xSemaphoreGive(s_cap_mtx);
                ble_notify(s_cap_buf, fl);
                if (s_cap_mtx) xSemaphoreTake(s_cap_mtx, portMAX_DELAY);
            }
        }
        if (s_cap_mtx) xSemaphoreGive(s_cap_mtx);
        return (ssize_t)size;
    }
    return __real__write_r(r, fd, data, size);
}


/* Nordic UART Service (NUS) — 标准 128-bit UUID, Flutter/nRF Connect 通用
 *   服务    6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 *   RX 写   6E400002-B5A3-F393-E0A9-E50E24DCCA9E  (手机 -> 板)
 *   TX 通知 6E400003-B5A3-F393-E0A9-E50E24DCCA9E  (板 -> 手机)
 * BLE_UUID128_INIT 需要小端字节序 (等价于手机端字符串的逆序). */
#define NUS_SVC_UUID          0x9E,0xCA,0xDC,0x24,0x00,0xE5,0xA9,0xE0,0x93,0xF3,0xA3,0xB5,0x01,0x00,0x40,0x6E
#define NUS_RX_CHAR_UUID      0x9E,0xCA,0xDC,0x24,0x00,0xE5,0xA9,0xE0,0x93,0xF3,0xA3,0xB5,0x02,0x00,0x40,0x6E
#define NUS_TX_CHAR_UUID      0x9E,0xCA,0xDC,0x24,0x00,0xE5,0xA9,0xE0,0x93,0xF3,0xA3,0xB5,0x03,0x00,0x40,0x6E

static const ble_uuid128_t s_svc_uuid =
    BLE_UUID128_INIT(NUS_SVC_UUID);
static const ble_uuid128_t s_rx_uuid =
    BLE_UUID128_INIT(NUS_RX_CHAR_UUID);
static const ble_uuid128_t s_tx_uuid =
    BLE_UUID128_INIT(NUS_TX_CHAR_UUID);

static uint16_t s_rx_val_handle = 0;
static uint16_t s_tx_val_handle = 0;
static uint16_t s_conn_handle   = BLE_HS_CONN_HANDLE_NONE;
static uint8_t  s_phy_tx = 0;   /* 当前 LE PHY */
static uint16_t s_mtu           = 23;  /* 默认 ATT MTU, 协商后更新 */
/* 串行化 TX 通知: 命令回执 (ble_exec_task) 与异步事件 (ble_evt_task) 是两个任务,
 * 不加锁会让两条消息的分片互相穿插, 手机侧重组出错. */
static SemaphoreHandle_t s_tx_mtx = NULL;

/* NUS 广播挂起标志. 伪造广播运行期间, gap_event_cb 的 DISCONNECT /
 * ADV_COMPLETE 不再自动重启 NUS 广播 (否则会与伪造广播冲突). */
static volatile bool s_nus_adv_suspended = false;

/* 命令队列: RX 写入把命令投递给 BLE 任务执行 */
typedef struct {
    char line[256];
} ble_cmd_t;

static QueueHandle_t s_cmd_q = NULL;
static TaskHandle_t  s_exec_task = NULL;

/* NUS 二进制帧协议 (双向同格式, 便于 Flutter / nRF Connect 复用):
 *   off 0     MAGIC 0xA5
 *       1     TYPE  0x01=CMD(手机->板) 0x02=DATA(板->手机) 0x03=ACK 0x04=ERR
 *       2     FLAGS bit0=FIRST bit1=LAST
 *       3..4  SEQ u16 LE (发送方自增)
 *       5..6  LEN u16 LE (payload 字节数, <= NUS_MAX_PAYLOAD)
 *       7..   PAYLOAD (UTF-8)    7+LEN  CRC8 poly 0x07, 覆盖 TYPE..PAYLOAD
 * 头 7B + 尾 1B; 一条逻辑消息可跨多帧, 按 FLAGS 重组. */
#define NUS_MAGIC        0xA5
#define NUS_T_CMD        0x01
#define NUS_T_DATA       0x02
#define NUS_T_ACK        0x03
#define NUS_T_ERR        0x04
#define NUS_T_FILE       0x10   /* 文件分片: payload = [offset:4 LE][raw bytes] */
#define NUS_T_CHUNK      0x11   /* 二进制回传分片: payload = [offset:4 LE][bytes] */
#define NUS_F_FIRST      0x01
#define NUS_F_LAST       0x02
#define NUS_HDR          7
#define NUS_MAX_PAYLOAD  220
#define NUS_RX_FRAME_MAX (NUS_HDR + NUS_MAX_PAYLOAD + 1)
#define NUS_ASM_MAX      1024

static uint8_t crc8(const uint8_t *d, int len)
{
    uint8_t crc = 0;
    for (int i = 0; i < len; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x07) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

/* RX 字节流重组: 通知/写入都是字节流, 需跨包累积再切帧 */
static uint8_t  s_rx_frame[NUS_RX_FRAME_MAX];
static int      s_rx_frame_len = 0;
static uint8_t  s_rx_asm[NUS_ASM_MAX];
static int      s_rx_asm_len = 0;
static uint8_t  s_rx_asm_type = 0;

static void nus_deliver_msg(const uint8_t *msg, int len)
{
    if (len <= 0) return;

    /* 文件分片: payload = [offset:4 LE][raw bytes] -> 写入门户 HTML 上传缓冲 */
    if (s_rx_asm_type == NUS_T_FILE) {
        if (len < 5) return;
        int off = (int)((uint32_t)msg[0] | ((uint32_t)msg[1] << 8) |
                        ((uint32_t)msg[2] << 16) | ((uint32_t)msg[3] << 24));
        if (phish_html_chunk(off, msg + 4, len - 4) != 0) {
            ESP_LOGW(TAG, "file chunk rejected: off=%d len=%d", off, len - 4);
        }
        return;
    }

    ble_cmd_t cmd = {0};
    int n = len < (int)sizeof(cmd.line) - 1 ? len : (int)sizeof(cmd.line) - 1;
    memcpy(cmd.line, msg, n);
    cmd.line[n] = '\0';
    while (n > 0 && (cmd.line[n-1] == '\n' || cmd.line[n-1] == '\r')) cmd.line[--n] = '\0';
    if (n <= 0) return;
    ESP_LOGI(TAG, "RX cmd: '%s'", cmd.line);
    xQueueSend(s_cmd_q, &cmd, 0);
}

static void nus_rx_bytes(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        /* 空闲态必须见到帧头才开始累积, 便于从错位中恢复 */
        if (s_rx_frame_len == 0 && data[i] != NUS_MAGIC) continue;
        s_rx_frame[s_rx_frame_len++] = data[i];
        if (s_rx_frame_len > NUS_RX_FRAME_MAX) { s_rx_frame_len = 0; continue; }

        if (s_rx_frame_len < NUS_HDR) continue;
        uint16_t plen = (uint16_t)(s_rx_frame[5] | (s_rx_frame[6] << 8));
        if (plen > NUS_MAX_PAYLOAD) { s_rx_frame_len = 0; continue; }
        int total = NUS_HDR + plen + 1;
        if (s_rx_frame_len < total) continue;

        const uint8_t *f = s_rx_frame;
        if (crc8(&f[1], 6 + plen) != f[total - 1]) {
            ESP_LOGW(TAG, "frame crc mismatch, drop");
            s_rx_frame_len = 0;
            continue;
        }
        uint8_t flags = f[2];
        if ((flags & NUS_F_FIRST) && s_rx_asm_len > 0) s_rx_asm_len = 0;  /* 上一消息残缺 */
        if (flags & NUS_F_FIRST) s_rx_asm_type = f[1];
        if (plen) {
            int room = (int)sizeof(s_rx_asm) - s_rx_asm_len;
            int cp = plen < room ? plen : room;
            memcpy(s_rx_asm + s_rx_asm_len, f + NUS_HDR, cp);
            s_rx_asm_len += cp;
        }
        if (flags & NUS_F_LAST) {
            nus_deliver_msg(s_rx_asm, s_rx_asm_len);
            s_rx_asm_len = 0;
        }
        s_rx_frame_len = 0;
    }
}


static int gatt_svc_access(uint16_t conn_handle, uint16_t attr_handle,
                           struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    const ble_uuid_t *uuid;
    int rc;

    uuid = ctxt->chr->uuid;

    if (ble_uuid_cmp(uuid, &s_rx_uuid.u) == 0) {
        /* RX: 手机写入二进制帧 */
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            int n = OS_MBUF_PKTLEN(ctxt->om);
            rgb_led_event(RGB_EV_BLE_CONNECT, 0);  /* 收到写入, 闪灯 */
            if (n > 0 && n <= NUS_RX_FRAME_MAX) {
                uint8_t tmp[NUS_RX_FRAME_MAX];
                rc = os_mbuf_copydata(ctxt->om, 0, n, tmp);
                if (rc == 0) nus_rx_bytes(tmp, n);
            } else if (n > 0) {
                ESP_LOGW(TAG, "RX write too large: %d", n);
            }
            return 0;
        }
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = &s_rx_uuid.u,
                .access_cb = gatt_svc_access,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
                .val_handle = &s_rx_val_handle,
            },
            {
                .uuid = &s_tx_uuid.u,
                .access_cb = gatt_svc_access,
                .flags = BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_tx_val_handle,
            },
            { 0 },
        },
    },
    { 0 },
};

uint16_t ble_cli_mtu(void)        { return s_mtu; }
uint8_t  ble_cli_phy(void)        { return s_phy_tx; }
bool     ble_cli_connected(void)  { return s_conn_handle != BLE_HS_CONN_HANDLE_NONE; }

/* 通知发送 (NUS 组帧) */

static uint16_t s_tx_seq = 0;

/* 把一段文本按 NUS 帧发送; 超过单帧容量时自动分片并置 FIRST/LAST 标志 */
static void nus_send_msg(const char *data, int len, uint8_t type)
{
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        /* 没连接时丢弃通知是**正常路径**: 事件循环每秒都会推一次状态,
         * 用 LOGW 会在串口和 App 的"设备输出"面板里每秒刷一行红字,
         * 把真正有用的日志顶掉. 降到 DEBUG, 需要时开日志级别就能看到. */
        ESP_LOGD(TAG, "notify dropped: no conn");
        return;
    }
    if (s_tx_val_handle == 0) {
        ESP_LOGW(TAG, "notify: tx_val_handle is 0!");
        return;
    }
    if (len <= 0) return;
    if (len > NUS_ASM_MAX) len = NUS_ASM_MAX;

    if (s_tx_mtx) xSemaphoreTake(s_tx_mtx, portMAX_DELAY);

    /* 单次 notify 能承载的字节数 (ATT 负载 = MTU-3) */
    int mtu = (int)s_mtu - 3;
    if (mtu < 23) mtu = 23;

    int off = 0;
    while (off < len) {
        int chunk = len - off;
        if (chunk > NUS_MAX_PAYLOAD) chunk = NUS_MAX_PAYLOAD;

        uint8_t frame[NUS_RX_FRAME_MAX];
        frame[0] = NUS_MAGIC;
        frame[1] = type;
        frame[2] = (uint8_t)((off == 0 ? NUS_F_FIRST : 0) |
                            ((off + chunk >= len) ? NUS_F_LAST : 0));
        frame[3] = (uint8_t)(s_tx_seq & 0xff);
        frame[4] = (uint8_t)((s_tx_seq >> 8) & 0xff);
        frame[5] = (uint8_t)(chunk & 0xff);
        frame[6] = (uint8_t)((chunk >> 8) & 0xff);
        memcpy(frame + NUS_HDR, data + off, chunk);
        int total = NUS_HDR + chunk;
        frame[total] = crc8(&frame[1], 6 + chunk);
        total += 1;
        s_tx_seq++;

        /* 若单帧大于 MTU, 再按 MTU 切片, 接收侧按字节流重组 */
        int fo = 0;
        while (fo < total) {
            int fc = total - fo;
            if (fc > mtu) fc = mtu;
            struct os_mbuf *om = ble_hs_mbuf_from_flat(frame + fo, fc);
            if (om) {
                int rc = ble_gatts_notify_custom(s_conn_handle, s_tx_val_handle, om);
                if (rc != 0) ESP_LOGW(TAG, "notify failed: rc=%d", rc);
            }
            fo += fc;
            /* 只有真正需要分片时才让路. 单帧发完还睡 8ms, 会让每条日志
             * 白等一整个连接间隔. */
            if (fo < total) vTaskDelay(pdMS_TO_TICKS(4));
        }
        off += chunk;
        if (off < len) vTaskDelay(pdMS_TO_TICKS(12));  /* 分片间让路 */
    }

    if (s_tx_mtx) xSemaphoreGive(s_tx_mtx);
}

/* 异步事件推送
 * 命令执行之外的输出 (门户凭据命中 / EAPOL 命中 / 作业进度) 原先只进 UART,
 * 手机端永远看不到, 因为 stdout 捕获仅在 ble_exec_task 执行命令期间开启.
 * 这里给这些事件一条独立通道:
 *   post 侧 (HTTP 任务 / WiFi 驱动任务上下文) 只拷进队列, 不阻塞不分配;
 *   send 侧由独立低优先级任务限速发出, 避免高频作业期间占满 BLE 时隙. */
#define EVT_Q_LEN       24
#define EVT_LINE_MAX    192
#define EVT_MIN_GAP_MS  40

static QueueHandle_t s_evt_q    = NULL;
static TaskHandle_t  s_evt_task = NULL;

bool ble_event_post(const char *line)
{
    if (!s_evt_q || !line || !*line) return false;
    char buf[EVT_LINE_MAX];
    size_t n = strlen(line);
    if (n > sizeof(buf) - 2) n = sizeof(buf) - 2;
    memcpy(buf, line, n);
    if (buf[n - 1] != '\n') buf[n++] = '\n';
    buf[n] = 0;

    if (xQueueSend(s_evt_q, buf, 0) != pdTRUE) {
        char drop[EVT_LINE_MAX];
        xQueueReceive(s_evt_q, drop, 0);      /* 丢最旧的一条, 保证不阻塞调用方 */
        xQueueSend(s_evt_q, buf, 0);
    }
    return true;
}

static void ble_evt_task(void *pv)
{
    (void)pv;
    char line[EVT_LINE_MAX];
    while (1) {
        if (xQueueReceive(s_evt_q, line, portMAX_DELAY) != pdTRUE) continue;
        nus_send_msg(line, (int)strlen(line), NUS_T_DATA);
        vTaskDelay(pdMS_TO_TICKS(EVT_MIN_GAP_MS));
    }
}

/* 兼容旧调用点: 把捕获的 stdout 作为 DATA 帧发出 */
static void ble_notify(const char *data, int len)
{
    nus_send_msg(data, len, NUS_T_DATA);
}

/* 二进制分片回传 (原始帧落盘的分段拉取用).
 * payload = [offset:4 LE][bytes], 手机侧按 offset 拼回完整 pcap.
 * 单帧 <= NUS_MAX_PAYLOAD; 调用方负责切成合适大小. */
void ble_send_chunk(uint32_t off, const uint8_t *data, int len)
{
    if (!data || len <= 0) return;
    uint8_t payload[NUS_MAX_PAYLOAD];
    int max = NUS_MAX_PAYLOAD - 4;
    if (len > max) len = max;
    payload[0] = (uint8_t)(off & 0xff);
    payload[1] = (uint8_t)((off >> 8) & 0xff);
    payload[2] = (uint8_t)((off >> 16) & 0xff);
    payload[3] = (uint8_t)((off >> 24) & 0xff);
    memcpy(payload + 4, data, len);
    nus_send_msg((const char *)payload, 4 + len, NUS_T_CHUNK);
}


static void ble_exec_task(void *pv)
{
    ble_cmd_t cmd;
    while (1) {
        if (xQueueReceive(s_cmd_q, &cmd, portMAX_DELAY) != pdTRUE) continue;

        ESP_LOGI(TAG, "BLE cmd: %s", cmd.line);

        /* 开启 stdout 捕获 */
        if (s_cap_mtx) xSemaphoreTake(s_cap_mtx, portMAX_DELAY);
        s_cap_len = 0;
        s_capture_active = true;
        if (s_cap_mtx) xSemaphoreGive(s_cap_mtx);

        /* 执行命令 */
        int ret = cli_exec_line(cmd.line);
        (void)ret;
        fflush(stdout);

        /* 关闭捕获 */
        s_capture_active = false;

        /* 取走捕获的输出并 notify */
        if (s_cap_mtx) xSemaphoreTake(s_cap_mtx, portMAX_DELAY);
        int out_len = s_cap_len;
        char *out = s_cap_buf;   /* 直接用, notify 期间不再有 capture */
        if (out_len > 0) {
            ble_notify(out, out_len);
        }
        s_cap_len = 0;
        if (s_cap_mtx) xSemaphoreGive(s_cap_mtx);
    }
}

/* 连接参数
 * ESP32-C5 单射频, WiFi + BLE 共存: 高频 RF 作业 (嗅探/注入) 会挤占 BLE 时隙,
 * 默认的窄连接间隔容易被误判为断连. 因此连接后主动请求放宽参数:
 *   连接间隔 30-50ms, 从机延迟 0, 监督超时 5s (2~6s 区间内).
 * 单位: 连接间隔 1.25ms, 监督超时 10ms. */
static void ble_apply_conn_params(uint16_t conn_handle)
{
    struct ble_gap_upd_params p = {
        .itvl_min = 12,               /* 15 ms */
        .itvl_max = 24,               /* 30 ms */
        .latency  = 0,
        .supervision_timeout = 400,   /* 4 s */
        .min_ce_len = 0,
        .max_ce_len = 0,
    };
    int rc = ble_gap_update_params(conn_handle, &p);
    ESP_LOGI(TAG, "conn param update req: rc=%d (itvl 15-30ms, timeout 4s)", rc);
}


/* LE 2M PHY 请求.
 * 同样的连接间隔下, 2M 的空口速率是 1M 的两倍, 一次连接事件能塞进的字节数
 * 翻倍, dump 列表这种几 KB 的输出传输时间直接减半.
 * 由外设发起, 手机端不需要改代码; 不支持 2M 的对端会回 1M, 不是错误. */
static void ble_apply_le_phy(uint16_t conn_handle)
{
    int rc = ble_gap_set_prefered_le_phy(conn_handle,
                                         BLE_GAP_LE_PHY_2M_MASK,  /* TX */
                                         BLE_GAP_LE_PHY_2M_MASK,  /* RX */
                                         BLE_GAP_LE_PHY_CODED_ANY);
    ESP_LOGI(TAG, "le 2m phy req: rc=%d", rc);
}


static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "BLE connected, handle=%d", s_conn_handle);
            rgb_led_event(RGB_EV_BLE_CONNECT, 500);
            ble_apply_conn_params(s_conn_handle);
        } else {
            ESP_LOGW(TAG, "BLE connect failed: %d", event->connect.status);
            s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "BLE disconnected: %d", event->disconnect.reason);
        s_phy_tx = 0;
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        /* 伪造广播期间不自动重启 NUS (由 bleadv 恢复逻辑接管) */
        if (!s_nus_adv_suspended) {
            ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, NULL, gap_event_cb, NULL);
        } else {
            ESP_LOGI(TAG, "nus adv suspended, skip auto-restart");
        }
        break;
    case BLE_GAP_EVENT_CONN_UPDATE:
        if (event->conn_update.status == 0) {
            struct ble_gap_conn_desc d;
            if (ble_gap_conn_find(event->conn_update.conn_handle, &d) == 0) {
                ESP_LOGI(TAG, "conn params now: itvl=%d(%.1fms) latency=%d timeout=%d(%dms)",
                         d.conn_itvl, d.conn_itvl * 1.25, d.conn_latency,
                         d.supervision_timeout, d.supervision_timeout * 10);
            } else {
                ESP_LOGI(TAG, "conn params updated ok");
            }
        } else {
            ESP_LOGW(TAG, "conn param update rejected: %d", event->conn_update.status);
        }
        /* 参数流程收尾后才请求 PHY: 两个流程同时挂着容易被对端拒. */
        ble_apply_le_phy(event->conn_update.conn_handle);
        break;
    case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
        s_phy_tx = event->phy_updated.tx_phy;
        if (event->phy_updated.tx_phy == BLE_GAP_LE_PHY_2M ||
            event->phy_updated.rx_phy == BLE_GAP_LE_PHY_2M) {
            ESP_LOGI(TAG, "le phy: 2M active (tx=%d rx=%d)",
                     event->phy_updated.tx_phy, event->phy_updated.rx_phy);
        } else {
            ESP_LOGI(TAG, "le phy: stays 1M (tx=%d rx=%d)",
                     event->phy_updated.tx_phy, event->phy_updated.rx_phy);
        }
        break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ESP_LOGI(TAG, "BLE adv complete, restart");
        /* 伪造广播期间不自动重启 NUS */
        if (!s_nus_adv_suspended) {
            ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, NULL, gap_event_cb, NULL);
        } else {
            ESP_LOGI(TAG, "nus adv suspended, skip auto-restart");
        }
        break;
    case BLE_GAP_EVENT_MTU:
        s_mtu = event->mtu.value;
        ESP_LOGI(TAG, "BLE MTU updated: %d", s_mtu);
        break;
    default:
        break;
    }
    return 0;
}

/* NimBLE host task */

static void nimble_host_task(void *param)
{
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* NUS 广播 (可挂起/恢复)
 * on_sync 首次启动 + ble_cli_adv_resume 恢复时共用. 只设置 fields / rsp 并
 * 启动 connectable+discoverable 广播, 不重新设功率 (功率已在 adv 启动后设过). */
static inline uint32_t dbg_int_free(void)
{
    return (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
}
static inline uint32_t dbg_int_largest(void)
{
    return (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
}

/* 广播分三级尝试. 控制器在内部 RAM 吃紧时对 HCI_BLE_WRITE_ADV_DATA
 * 返回 0x207 (BLE_ERR_MEM_CAPACITY), 此时牺牲广播内容也比完全没有广播好:
 *   L2 = flags + 128bit UUID (App 能按 service 过滤, 最佳)
 *   L1 = 仅 flags           (App 需按名字过滤, 仍能连)
 * 每级的 rc 都打出来, 便于判断是"数据太长"还是"真没内存". */
static int nus_adv_apply_and_start(void)
{
    struct ble_hs_adv_fields fields;
    struct ble_hs_adv_fields rsp_fields;
    struct ble_gap_adv_params adv_params;
    int rc;
    int level = 2;

    ESP_LOGI(TAG, "adv pre : int_free=%u largest=%u",
             (unsigned)dbg_int_free(), (unsigned)dbg_int_largest());

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = &s_svc_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;
    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_set_fields(L2) rc=%d -> retry L1", rc);
        level = 1;
        memset(&fields, 0, sizeof(fields));
        fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
        rc = ble_gap_adv_set_fields(&fields);
        if (rc != 0) {
            ESP_LOGE(TAG, "adv_set_fields(L1) rc=%d (broadcast content unavailable)", rc);
        }
    }
    ESP_LOGI(TAG, "adv level = L%d", level);

    /* 扫描响应 (SCAN_RSP): 设备名 */
    memset(&rsp_fields, 0, sizeof(rsp_fields));
    const char *name = "rftool-c5";
    rsp_fields.name = (uint8_t *)name;
    rsp_fields.name_len = (uint8_t)strlen(name);
    rsp_fields.name_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) ESP_LOGW(TAG, "adv_rsp_set_fields rc=%d", rc);

    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    /* 显式给间隔: 部分控制器对 0 值会直接拒绝; 100~150ms 兼顾发现速度与功耗 */
    adv_params.itvl_min = BLE_GAP_ADV_ITVL_MS(100);
    adv_params.itvl_max = BLE_GAP_ADV_ITVL_MS(150);

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "nus adv start failed: %d (0x%x)", rc, rc);
        ESP_LOGE(TAG, "adv post: int_free=%u largest=%u",
                 (unsigned)dbg_int_free(), (unsigned)dbg_int_largest());
        return rc;
    }
    ESP_LOGI(TAG, "NUS advertising up (L%d) int_free=%u largest=%u",
             level, (unsigned)dbg_int_free(), (unsigned)dbg_int_largest());
    return 0;
}


static void on_sync(void)
{
    int rc;

    /* 获取特征值句柄 (ble_gatts_add_svcs 在某些版本不自动填充 val_handle) */
    uint16_t svc_handle = 0;
    rc = ble_gatts_find_svc(&s_svc_uuid.u, &svc_handle);
    ESP_LOGI(TAG, "find_svc: rc=%d handle=%d", rc, svc_handle);
    if (rc == 0) {
        rc = ble_gatts_find_chr(&s_svc_uuid.u, &s_rx_uuid.u, NULL, &s_rx_val_handle);
        ESP_LOGI(TAG, "find rx_chr: rc=%d handle=%d", rc, s_rx_val_handle);
        rc = ble_gatts_find_chr(&s_svc_uuid.u, &s_tx_uuid.u, NULL, &s_tx_val_handle);
        ESP_LOGI(TAG, "find tx_chr: rc=%d handle=%d", rc, s_tx_val_handle);
    }

    ble_svc_gap_device_name_set("rftool-c5");

    rc = nus_adv_apply_and_start();
    if (rc != 0) {
        return;
    }
    /* 广播已在跑, 此时设 ADV 功率才生效 (实例未建立前设会失败) */
    {
        esp_err_t pa = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P20);
        if (pa == ESP_OK) ESP_LOGI(TAG, "BLE ADV TX power = +20 dBm");
        else              ESP_LOGW(TAG, "BLE ADV TX power set failed: %s", esp_err_to_name(pa));
    }
    ESP_LOGI(TAG, "BLE advertising as 'rftool-c5' (UUID in ADV, name in SCAN_RSP)");
}

static void on_reset(int reason)
{
    ESP_LOGE(TAG, "NimBLE reset: %d", reason);
}


/* 传输层把自己注册成输出汇点. 领域层从此不用 include 本头文件就能往手机回传. */
static void ble_out_sink(const char *line, void *ctx)
{
    (void)ctx;
    ble_event_post(line);
}

static void ble_link_cb(out_link_t *out)
{
    out->mtu = ble_cli_mtu();
    out->connected = ble_cli_connected();
    out->phy = ble_cli_phy();
}

static void ble_adv_gate_cb(bool hold)
{
    if (hold) ble_cli_adv_suspend();
    else      ble_cli_adv_resume();
}

esp_err_t ble_cli_start(void)
{
    out_stream_init();
    out_sink_add(ble_out_sink, NULL);
    out_adv_gate_set(ble_adv_gate_cb);
    out_link_set(ble_link_cb);
    esp_err_t err;

    /* NVS (NimBLE 可能需要) */
    nvs_flash_init();

    s_cap_mtx = xSemaphoreCreateMutex();
    if (!s_cap_mtx) return ESP_ERR_NO_MEM;

    s_tx_mtx = xSemaphoreCreateMutex();
    if (!s_tx_mtx) return ESP_ERR_NO_MEM;

    s_cmd_q = xQueueCreate(4, sizeof(ble_cmd_t));
    if (!s_cmd_q) return ESP_ERR_NO_MEM;

    s_evt_q = xQueueCreate(EVT_Q_LEN, EVT_LINE_MAX);
    if (!s_evt_q) return ESP_ERR_NO_MEM;

    /* 初始化 NimBLE controller + host */
    err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    /* 首选 ATT MTU 与 sdkconfig 的 256 对齐. 手机端请求 512, 最终取较小值.
     * 不显式设置时部分安卓机停在默认 23, 每帧只能带 20 字节.
     * 必须在 nimble_port_init 之后: 这个调用内部要拿 host 互斥量,
     * host 没起来时互斥量是 NULL, 直接 Load access fault. */
    int rc0 = ble_att_set_preferred_mtu(RFTOOL_ATT_MTU);
    if (rc0 != 0) {
        ESP_LOGW(TAG, "set preferred mtu %d rejected: %d", RFTOOL_ATT_MTU, rc0);
    }

    /* BLE 发射功率拉满 (C5 支持 +20 dBm 高功率模式).
     * 此处只设 DEFAULT(连接) 与 SCAN; ADV 需等广播实例建立后设置,
     * 否则控制器返回 ESP_FAIL (见 on_sync 内 adv_start 之后). */
    {
        esp_err_t p1 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P20);
        esp_err_t p3 = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN,    ESP_PWR_LVL_P20);
        if (p1 == ESP_OK && p3 == ESP_OK) {
            ESP_LOGI(TAG, "BLE TX power = +20 dBm (default/scan)");
        } else {
            ESP_LOGW(TAG, "BLE TX power set: default=%s scan=%s",
                     esp_err_to_name(p1), esp_err_to_name(p3));
        }
    }

    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    /* 安全管理器: 支持 Just Works 配对 (无 PIN, 无 MITM).
     * Android 连接 GATT 时可能自动发起 bonding, 若不配置 SM 会导致
     * 配对失败 → 连接被断开. 配置后允许无密钥配对. */
    ble_hs_cfg.sm_io_cap      = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding     = 1;
    ble_hs_cfg.sm_mitm        = 0;
    ble_hs_cfg.sm_sc          = 1;
    ble_hs_cfg.sm_keypress    = 0;
    ble_hs_cfg.sm_our_key_dist   = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts count cfg failed: %d", rc);
        return ESP_FAIL;
    }
    rc = ble_gatts_add_svcs(gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts add svcs failed: %d", rc);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "svc registered: rx_handle=%d tx_handle=%d", s_rx_val_handle, s_tx_val_handle);

    nimble_port_freertos_init(nimble_host_task);

    /* 命令执行任务 */
    BaseType_t r = xTaskCreate(ble_exec_task, "ble_exec", 8192, NULL, 5, &s_exec_task);
    if (r != pdPASS) return ESP_FAIL;

    /* 异步事件推送任务 (低优先级, 不与 RF 作业抢 CPU) */
    r = xTaskCreate(ble_evt_task, "ble_evt", 4096, NULL, 4, &s_evt_task);
    if (r != pdPASS) ESP_LOGW(TAG, "ble_evt task create failed");

    ESP_LOGI(TAG, "BLE CLI service started");
    return ESP_OK;
}

esp_err_t ble_cli_stop(void)
{
    /* 简化: 不实现完整停止, 保持服务运行 */
    return ESP_OK;
}

/* NUS 广播挂起/恢复
 * 供 bleadv 伪造广播使用. 挂起只停止广播 (不影响已建立的 GATT 连接),
 * 恢复时重设 NUS fields 并重新启动可连接广播. */

int ble_cli_adv_suspend(void)
{
    s_nus_adv_suspended = true;
    int rc = ble_gap_adv_stop();
    /* BLE_HS_EALREADY = 没有正在运行的广播, 也算成功 */
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "adv_suspend: ble_gap_adv_stop rc=%d", rc);
        s_nus_adv_suspended = false;
        return rc;
    }
    ESP_LOGI(TAG, "NUS adv suspended (conn handle=%d still valid)", s_conn_handle);
    return 0;
}

int ble_cli_adv_resume(void)
{
    int rc = nus_adv_apply_and_start();
    if (rc == 0) {
        s_nus_adv_suspended = false;
        /* 恢复广播后重设 ADV 功率 (+20 dBm) */
        esp_err_t pa = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P20);
        if (pa != ESP_OK) {
            ESP_LOGW(TAG, "resume: ADV power set failed: %s", esp_err_to_name(pa));
        }
    }
    return rc;
}

bool ble_cli_adv_is_suspended(void)
{
    return s_nus_adv_suspended;
}
