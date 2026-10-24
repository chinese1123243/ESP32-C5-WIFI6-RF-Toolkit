/*
 * logring.c: 日志环形缓冲
 *
 * 环形缓冲放 PSRAM (8MB), 不占内部 RAM.
 * 设计: 头指针 head + 有效长度 used; 满则覆盖最旧数据.
 */
#include "logring.h"

#include <string.h>
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define LOGRING_SIZE  (16 * 1024)   /* 16KB 最近日志 */

static char  *s_buf = NULL;
static size_t s_head = 0;          /* 下一个写入位置 */
static size_t s_used = 0;          /* 有效字节数 (≤ LOGRING_SIZE) */
static SemaphoreHandle_t s_mtx = NULL;

void logring_push(const char *data, size_t len)
{
    if (!data || len == 0 || !s_buf) return;
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);

    /* 若 len > 缓冲大小, 只保留最后 LOGRING_SIZE 字节 */
    if (len > LOGRING_SIZE) {
        data += len - LOGRING_SIZE;
        len = LOGRING_SIZE;
    }

    size_t first = LOGRING_SIZE - s_head;
    if (len <= first) {
        memcpy(s_buf + s_head, data, len);
    } else {
        memcpy(s_buf + s_head, data, first);
        memcpy(s_buf, data + first, len - first);
    }
    s_head = (s_head + len) % LOGRING_SIZE;
    s_used += len;
    if (s_used > LOGRING_SIZE) s_used = LOGRING_SIZE;

    if (s_mtx) xSemaphoreGive(s_mtx);
}

int logring_dump(FILE *out)
{
    if (!out || !s_buf) return 0;
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);

    int total = 0;
    if (s_used > 0) {
        size_t start = (s_head + LOGRING_SIZE - s_used) % LOGRING_SIZE;
        size_t first = LOGRING_SIZE - start;
        if (s_used <= first) {
            total = (int)fwrite(s_buf + start, 1, s_used, out);
        } else {
            total = (int)fwrite(s_buf + start, 1, first, out);
            total += (int)fwrite(s_buf, 1, s_used - first, out);
        }
    }
    fflush(out);
    if (s_mtx) xSemaphoreGive(s_mtx);
    return total;
}

void logring_clear(void)
{
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_head = 0;
    s_used = 0;
    if (s_mtx) xSemaphoreGive(s_mtx);
}

size_t logring_used(void)
{
    return s_used;
}

/* 构造函数式初始化: 用 __attribute__((constructor)) 让缓冲在 main 之前就位,
 * 这样早期日志也能被捕获. PSRAM 在 boot 时已初始化 (CONFIG_SPIRAM_BOOT_INIT). */
__attribute__((constructor))
static void logring_ctor(void)
{
    s_buf = heap_caps_malloc(LOGRING_SIZE, MALLOC_CAP_SPIRAM);
    if (!s_buf) {
        /* PSRAM 不可用时降级到内部 RAM (小一点) */
        s_buf = heap_caps_malloc(4096, MALLOC_CAP_INTERNAL);
    }
    s_mtx = xSemaphoreCreateMutex();
}
