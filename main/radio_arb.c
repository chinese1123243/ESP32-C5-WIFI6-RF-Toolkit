#include "radio_arb.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_timer.h"

/* 冲突规则数据化, 便于 test_sweep 遍历验证.
 * 比架构文档的五行多一组 TX_INJECT / RES_15_4: cmd_zbsniff 与 cmd_zbtx 都会先
 * 调 wifi_attack_stop_all(), 说明注入与 15.4 实际互斥, 文档漏了这一对. */
typedef struct {
    radio_res_t a;
    radio_res_t b;
    const char *why;
} radio_conflict_t;

static const radio_conflict_t k_conflicts[] = {
    { RES_RX_PROMISC, RES_SOFTAP,      "门户独占射频" },
    { RES_RX_PROMISC, RES_15_4,        "15.4 与 Wi-Fi 分时共用前端" },
    { RES_TX_INJECT,  RES_SOFTAP,      "门户独占射频" },
    { RES_TX_INJECT,  RES_15_4,        "注入与 15.4 共用前端" },
    { RES_15_4,       RES_BLE_CENTRAL, "控制器需交出射频" },
    { RES_RX_PROMISC, RES_BLE_CENTRAL, "枚举需第 2 条连接" },
};

#define RADIO_CASE_MAX 32

typedef enum {
    RCASE_OK = 0,
    RCASE_BUSY = 1,
    RCASE_TIMEOUT = 2,
    RCASE_REL = 3,
} rcase_verdict_t;

typedef struct {
    uint32_t seq;
    uint32_t t_ms;
    uint32_t res;
    /* 存副本不存指针: radio_release 传进来的是栈上拼的缓冲, 存指针会悬垂,
     * 表现出来是判例里 who 为空或乱码 (实测 seq,2 与 seq,4). */
    char who[16];
    char holder[16];
    uint8_t verdict;
} radio_case_t;

static SemaphoreHandle_t s_mtx;
static const char *s_who[RADIO_RES_BITS];

static radio_case_t s_cases[RADIO_CASE_MAX];
static uint32_t s_case_seq;
static uint32_t s_case_wr;

static const char *const k_res_name[RADIO_RES_BITS] = {
    "promisc", "inject", "softap", "154", "ble_central",
};

static void res_str(uint32_t res, char *out, size_t cap)
{
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if (!(res & (1u << i))) continue;
        int n = snprintf(out + used, cap - used, "%s%s",
                         used ? "+" : "", k_res_name[i]);
        if (n < 0 || (size_t)n >= cap - used) break;
        used += (size_t)n;
    }
    if (!out[0]) snprintf(out, cap, "none");
}

static const char *verdict_str(uint8_t v)
{
    switch (v) {
    case RCASE_OK:      return "ok";
    case RCASE_BUSY:    return "busy";
    case RCASE_TIMEOUT: return "timeout";
    case RCASE_REL:     return "release";
    default:            return "?";
    }
}

static void radio_emit(const char *sub, const char *fmt, ...)
{
    char line[192];
    int n = snprintf(line, sizeof(line), "META,RADIO,%s,", sub);
    if (n < 0 || n >= (int)sizeof(line)) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    printf("%s\n", line);
    fflush(stdout);
}

// 调用方需已持有 s_mtx
static void case_add(uint32_t res, const char *who, const char *holder, uint8_t verdict)
{
    radio_case_t *c = &s_cases[s_case_wr];
    c->seq = ++s_case_seq;
    c->t_ms = (uint32_t)(esp_timer_get_time() / 1000);
    c->res = res;
    snprintf(c->who, sizeof(c->who), "%s", who ? who : "-");
    snprintf(c->holder, sizeof(c->holder), "%s", holder ? holder : "-");
    c->verdict = verdict;
    s_case_wr = (s_case_wr + 1) % RADIO_CASE_MAX;
}

esp_err_t radio_init(void)
{
    if (s_mtx) return ESP_OK;
    s_mtx = xSemaphoreCreateMutex();
    return s_mtx ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t radio_acquire(radio_res_t need, const char *owner, uint32_t timeout_ms)
{
    if (!owner || need == 0 || (need & ~RADIO_RES_MASK)) return ESP_ERR_INVALID_ARG;
    if (radio_init() != ESP_OK) return ESP_ERR_NO_MEM;

    TickType_t start = xTaskGetTickCount();
    for (;;) {
        if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(100)) != pdTRUE) continue;

        radio_res_t hit = 0;
        const char *holder = NULL;
        bool same_owner = true;
        for (int i = 0; i < RADIO_RES_BITS; i++) {
            if (!(need & (1u << i)) || !s_who[i]) continue;
            hit |= (1u << i);
            if (!holder) holder = s_who[i];
            if (strcmp(s_who[i], owner) != 0) same_owner = false;
        }

        /* 同一持有者重复申请视为已持有, 不重复记判例 */
        if (hit == 0 || same_owner) {
            for (int i = 0; i < RADIO_RES_BITS; i++) {
                if (need & (1u << i)) s_who[i] = owner;
            }
            if (hit == 0) case_add((uint32_t)need, owner, NULL, RCASE_OK);
            xSemaphoreGive(s_mtx);
            if (hit == 0) {
                char rs[48];
                res_str((uint32_t)need, rs, sizeof(rs));
                radio_emit("ACQ", "owner,%s,res,%s", owner, rs);
            }
            return ESP_OK;
        }

        uint32_t waited = (uint32_t)((xTaskGetTickCount() - start) * portTICK_PERIOD_MS);
        bool give_up = (timeout_ms == 0) || (waited >= timeout_ms);
        if (give_up) {
            case_add((uint32_t)need, owner, holder,
                     timeout_ms == 0 ? RCASE_BUSY : RCASE_TIMEOUT);
            xSemaphoreGive(s_mtx);
            char rs[48];
            res_str((uint32_t)hit, rs, sizeof(rs));
            radio_emit("BUSY", "owner,%s,res,%s,by,%s", owner, rs, holder);
            return ESP_ERR_INVALID_STATE;
        }
        xSemaphoreGive(s_mtx);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void radio_release(radio_res_t held)
{
    if (!s_mtx || held == 0) return;
    if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(100)) != pdTRUE) return;

    char names[80];
    names[0] = '\0';
    size_t used = 0;
    uint32_t freed = 0;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if (!(held & (1u << i)) || !s_who[i]) continue;
        const char *who = s_who[i];
        s_who[i] = NULL;
        freed |= (1u << i);
        if (!strstr(names, who)) {
            int n = snprintf(names + used, sizeof(names) - used, "%s%s",
                             used ? "+" : "", who);
            if (n > 0 && (size_t)n < sizeof(names) - used) used += (size_t)n;
        }
    }
    if (freed) case_add(freed, names, NULL, RCASE_REL);
    xSemaphoreGive(s_mtx);

    if (freed) {
        char rs[48];
        res_str(freed, rs, sizeof(rs));
        radio_emit("REL", "owner,%s,res,%s", names, rs);
    }
}

const char *radio_owner(void)
{
    static char buf[80];
    if (!s_mtx || xSemaphoreTake(s_mtx, pdMS_TO_TICKS(50)) != pdTRUE) return "idle";
    buf[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if (!s_who[i] || strstr(buf, s_who[i])) continue;
        int n = snprintf(buf + used, sizeof(buf) - used, "%s%s",
                         used ? "," : "", s_who[i]);
        if (n < 0 || (size_t)n >= sizeof(buf) - used) break;
        used += (size_t)n;
    }
    xSemaphoreGive(s_mtx);
    return buf[0] ? buf : "idle";
}

bool radio_held(radio_res_t res)
{
    if (!s_mtx) return false;
    if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(50)) != pdTRUE) return false;
    bool any = false;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if ((res & (1u << i)) && s_who[i]) { any = true; break; }
    }
    xSemaphoreGive(s_mtx);
    return any;
}

uint32_t radio_held_mask(void)
{
    if (!s_mtx) return 0;
    if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(50)) != pdTRUE) return 0;
    uint32_t held = 0;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if (s_who[i]) held |= (1u << i);
    }
    xSemaphoreGive(s_mtx);
    return held;
}

const char *radio_res_str(uint32_t res)
{
    static char buf[48];
    res_str(res, buf, sizeof(buf));
    return buf;
}

radio_res_t radio_conflict(radio_res_t need)
{
    if (!s_mtx) return 0;
    if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(50)) != pdTRUE) return 0;
    /* 不能在这里调 radio_held: 它会二次获取 s_mtx. 本函数已持锁, 直接查表 */
    uint32_t held = 0;
    for (int i = 0; i < RADIO_RES_BITS; i++) {
        if (s_who[i]) held |= (1u << i);
    }
    radio_res_t hit = 0;
    for (size_t k = 0; k < sizeof(k_conflicts) / sizeof(k_conflicts[0]); k++) {
        radio_res_t a = k_conflicts[k].a;
        radio_res_t b = k_conflicts[k].b;
        if ((need & a) && (held & b)) hit |= b;
        if ((need & b) && (held & a)) hit |= a;
    }
    xSemaphoreGive(s_mtx);
    return hit;
}

const char *radio_conflict_reason(radio_res_t a, radio_res_t b)
{
    for (size_t k = 0; k < sizeof(k_conflicts) / sizeof(k_conflicts[0]); k++) {
        radio_res_t x = k_conflicts[k].a;
        radio_res_t y = k_conflicts[k].b;
        if ((a & x && b & y) || (a & y && b & x)) return k_conflicts[k].why;
    }
    return NULL;
}

int radio_case_dump(int n)
{
    if (!s_mtx || n <= 0) return 0;
    if (n > RADIO_CASE_MAX) n = RADIO_CASE_MAX;
    if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(100)) != pdTRUE) return 0;

    uint32_t have = s_case_seq < RADIO_CASE_MAX ? s_case_seq : RADIO_CASE_MAX;
    if ((uint32_t)n > have) n = (int)have;

    int out = 0;
    for (int i = n - 1; i >= 0; i--) {
        uint32_t idx = (s_case_wr + RADIO_CASE_MAX - 1 - (uint32_t)i) % RADIO_CASE_MAX;
        const radio_case_t *c = &s_cases[idx];
        char rs[48];
        res_str(c->res, rs, sizeof(rs));
        printf("META,RADIO,LOG,seq,%u,t_ms,%u,res,%s,who,%s,verdict,%s,by,%s\n",
               (unsigned)c->seq, (unsigned)c->t_ms, rs, c->who,
               verdict_str(c->verdict), c->holder);
        out++;
    }
    fflush(stdout);
    xSemaphoreGive(s_mtx);
    return out;
}

int radio_case_capacity(void) { return RADIO_CASE_MAX; }
uint32_t radio_case_total(void) { return s_case_seq; }
