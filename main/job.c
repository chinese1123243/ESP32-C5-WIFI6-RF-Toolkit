#include "job.h"

#include <string.h>

#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* 槽位表用临界区保护, 不用互斥量: 表只有 4 项, 临界区里只做几次比较和自增,
 * 而 xTaskCreate 必须在临界区外调用 (它内部要拿堆锁), 所以拆成"先占位, 再创建".
 * 单核上 xTaskCreate 不会让出 CPU, 新任务在 job_spawn 返回前不会跑, 占位与
 * 创建之间没有竞态. */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    bool      used;
    job_def_t def;
} job_slot_t;

/* 槽位比名额多 2: 外部作业占满 4 个时, 内部辅助任务仍要有地方放 */
#define JOB_SLOTS (JOB_MAX + 2)
static job_slot_t s_slots[JOB_SLOTS];
static int      s_active;      /* 含内部辅助 */
static int      s_aux;
static int      s_peak;
static unsigned s_rej;

static void job_trampoline(void *pv)
{
    job_slot_t *s = (job_slot_t *)pv;
    void (*fn)(void *) = s->def.fn;
    void *arg = s->def.arg;

    fn(arg);

    /* 出口只在这里. 任务函数自己 vTaskDelete 的话这行永远不执行, 槽位泄漏. */
    portENTER_CRITICAL(&s_mux);
    s->used = false;
    s_active--;
    if (s->def.flags & JOB_F_INTERNAL) s_aux--;
    portEXIT_CRITICAL(&s_mux);
    vTaskDelete(NULL);
}

esp_err_t job_spawn(const job_def_t *def, TaskHandle_t *out)
{
    if (!def || !def->fn) return ESP_ERR_INVALID_ARG;

    /* 名额只数非内部作业: 内部辅助任务是别人的从属, 不该挤掉别人的名额 */
    bool internal = (def->flags & JOB_F_INTERNAL) != 0;
    int idx = -1;
    portENTER_CRITICAL(&s_mux);
    int external = s_active - s_aux;
    if (internal || external < JOB_MAX) {
        for (int i = 0; i < JOB_MAX; i++) {
            if (!s_slots[i].used) { idx = i; break; }
        }
    }
    if (idx >= 0) {
        s_slots[idx].used = true;
        s_active++;
        if (internal) s_aux++;
        if (s_active > s_peak) s_peak = s_active;
    } else {
        s_rej++;
    }
    portEXIT_CRITICAL(&s_mux);

    if (idx < 0) return ESP_ERR_NO_MEM;

    s_slots[idx].def = *def;

    BaseType_t r = xTaskCreate(job_trampoline, def->name, def->stack,
                               &s_slots[idx], def->prio, out);
    if (r != pdPASS) {
        portENTER_CRITICAL(&s_mux);
        s_slots[idx].used = false;
        s_active--;
        if (internal) s_aux--;
        portEXIT_CRITICAL(&s_mux);
        return ESP_FAIL;
    }
    return ESP_OK;
}

int      job_active(void)   { return s_active; }
int      job_aux(void)      { return s_aux; }
int      job_peak(void)     { return s_peak; }
int      job_capacity(void) { return JOB_MAX; }
unsigned job_rejected(void) { return s_rej; }
