#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 临时作业的户籍.
 *
 * 为什么要有: 13 个临时作业各自 xTaskCreate / 各自 delete, 活跃数无从查询.
 * 并发不设上限时, 每个作业按 worst case 预留栈, 堆被切碎, 最大连续块掉得比
 * 剩余总量快. 仿真给的数字 (heap_4 first-fit, 288KB): 动态不限时最低最大可用块
 * 166.2KB, 户籍 K=4 时 195.6KB, 而池化方案常驻占 32.8KB 且堆降到 80KB 就起不来.
 *
 * 不做池化: 栈仍按需分配, 户籍只管"同时最多几个", 以及把活跃数变成可读的量.
 * 被拒的作业可以重试, 堆被打穿不能.
 *
 * 约束: 迁进来的作业函数**不许自己 vTaskDelete(NULL)**, 出口只有 job_trampoline.
 * 自己删的话槽位永远不释放, 户籍数只增不减.
 */
#define JOB_MAX 4

/* 内部辅助任务: 计入活跃数, 不占并发名额.
 *
 * 为什么需要: sniff 的进度任务与轮转任务是"停→立刻再开"时成对重建的,
 * 旧任务靠会话号退出, 最多再活一秒; 这一秒里新旧同时占位, 名额被自己人挤掉,
 * 于是新一轮 sniff 拿不到轮转任务, 表现为"嗅探不动"却不报错.
 * 这两个任务永远跟着一个用户作业走, 不构成额外的并发风险. */
#define JOB_F_INTERNAL 0x1u

typedef struct {
    const char *name;        /* 传给 xTaskCreate, FreeRTOS 会拷进 TCB */
    void (*fn)(void *arg);   /* 正常 return 即退出, 不要自己 vTaskDelete */
    void *arg;
    uint32_t stack;          /* 字节. 按 uxTaskGetStackHighWaterMark 实测定, 不靠估 */
    UBaseType_t prio;
    uint32_t flags;          /* JOB_F_INTERNAL */
} job_def_t;

/* 登记并启动. 满员返回 ESP_ERR_NO_MEM (可重试), 建任务失败返回 ESP_FAIL.
 * out 可为 NULL. 返回的句柄只能用来查状态, 不要拿去 vTaskDelete. */
esp_err_t job_spawn(const job_def_t *def, TaskHandle_t *out);

int      job_active(void);
int      job_aux(void);
int      job_peak(void);
int      job_capacity(void);
unsigned job_rejected(void);
/* 最近一次因名额被挡回的作业名, 空串表示还没有过. */
const char *job_last_rejected(void);

#ifdef __cplusplus
}
#endif
