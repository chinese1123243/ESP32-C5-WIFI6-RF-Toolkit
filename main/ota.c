/*
 * ota.c: 双区 OTA 升级实现
 *
 * 三条落地路径:
 *   1) App -> SoftAP -> POST /api/ota  (流式, 分块 esp_ota_write, 最实用)
 *   2) ota url <http(s)://...>        (设备自行出网时)
 *   3) 串口/CLI ota status|confirm|rollback|reboot
 *
 * 回滚模型 (与 IDF 官方一致):
 *   新固件首次启动后处于 ESP_OTA_IMG_PENDING_VERIFY. 若在窗口期内崩溃 -> 重启后
 *   引导器自动回到旧分区; 若稳定运行满窗口 (默认 45s) 或人工 `ota confirm`
 *   -> 标记 VALID, 从此不再回滚.
 */
#include "ota.h"
#include "config.h"
#include "event_bus.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strcasecmp: SHA-256 摘要大小写不敏感比较 */
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_http_client.h"

#include "mbedtls/sha256.h"

static const char *TAG = "OTA";

/* 新固件自检窗口: 45s 内不崩溃即认为可用 */
#define OTA_VERIFY_WINDOW_US  (45LL * 1000 * 1000)

static esp_ota_handle_t       s_handle  = 0;
static const esp_partition_t *s_update  = NULL;
static size_t                 s_written = 0;
static size_t                 s_total   = 0;
static bool                   s_busy    = false;
static mbedtls_sha256_context s_sha;
static bool                   s_sha_on  = false;
static char                   s_sha_expect[65];
static char                   s_err[80] = {0};
static SemaphoreHandle_t      s_mtx     = NULL;

static void set_err(const char *msg)
{
    snprintf(s_err, sizeof(s_err), "%s", msg ? msg : "err");
}

const char *ota_last_error(void) { return s_err; }
size_t ota_upload_written(void)  { return s_written; }
bool   ota_upload_busy(void)     { return s_busy; }


static const char *img_state_str(esp_ota_img_states_t st)
{
    switch (st) {
    case ESP_OTA_IMG_NEW:            return "NEW";
    case ESP_OTA_IMG_PENDING_VERIFY: return "PENDING_VERIFY";
    case ESP_OTA_IMG_VALID:          return "VALID";
    case ESP_OTA_IMG_INVALID:        return "INVALID";
    case ESP_OTA_IMG_ABORTED:        return "ABORTED";
    case ESP_OTA_IMG_UNDEFINED:      return "UNDEFINED";
    default:                         return "?";
    }
}

void ota_status(void)
{
    const esp_partition_t *run  = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    esp_ota_img_states_t   st   = ESP_OTA_IMG_UNDEFINED;
    if (run) esp_ota_get_state_partition(run, &st);

    const esp_app_desc_t *app = esp_app_get_description();
    const char *rs = run  ? run->label  : "?";
    const char *bs = boot ? boot->label : "?";

    printf("META,OTA,STATUS,running,%s,boot,%s,state,%s,version,%s,project,%s,"
           "rollback_enabled,%d,slot_size,%u,written,%u,busy,%d\n",
           rs, bs, img_state_str(st),
           app ? app->version : "?",
           app ? app->project_name : "?",
           CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE ? 1 : 0,
           (unsigned)(run ? run->size : 0),
           (unsigned)s_written,
           s_busy ? 1 : 0);
    fflush(stdout);
}


int ota_confirm(void)
{
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    if (e != ESP_OK) {
        printf("META,OTA,ERR,msg,confirm_failed,%s\n", esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }
    printf("META,OTA,CONFIRM,ok,1\n");
    fflush(stdout);
    return 0;
#else
    printf("META,OTA,CONFIRM,ok,0,msg,rollback_disabled\n");
    fflush(stdout);
    return 1;
#endif
}

int ota_rollback(void)
{
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    printf("META,OTA,ROLLBACK,start,1\n");
    fflush(stdout);
    /* 成功则直接重启, 不会返回; 返回即失败 */
    esp_err_t e = esp_ota_mark_app_invalid_rollback_and_reboot();
    printf("META,OTA,ERR,msg,rollback_failed,%s\n", esp_err_to_name(e));
    fflush(stdout);
    return 1;
#else
    printf("META,OTA,ERR,msg,rollback_disabled\n");
    fflush(stdout);
    return 1;
#endif
}


static void verify_timer_cb(void *arg)
{
    (void)arg;
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    if (e == ESP_OK) {
        ESP_LOGI(TAG, "new image confirmed after %llds uptime", OTA_VERIFY_WINDOW_US / 1000000);
    } else {
        ESP_LOGW(TAG, "auto-confirm failed: %s", esp_err_to_name(e));
    }
#endif
}

esp_err_t ota_init(void)
{
    if (!s_mtx) s_mtx = xSemaphoreCreateMutex();

    const esp_partition_t *run = esp_ota_get_running_partition();
    if (!run) return ESP_ERR_NOT_FOUND;

    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    if (esp_ota_get_state_partition(run, &st) != ESP_OK) st = ESP_OTA_IMG_UNDEFINED;

    ESP_LOGI(TAG, "running=%s state=%s", run->label, img_state_str(st));

    if (st == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGW(TAG, "image pending verify, %llds window before auto-confirm",
                 OTA_VERIFY_WINDOW_US / 1000000);
        const esp_timer_create_args_t args = {
            .callback = verify_timer_cb,
            .name = "ota_verify",
        };
        esp_timer_handle_t t = NULL;
        if (esp_timer_create(&args, &t) == ESP_OK) {
            esp_timer_start_once(t, OTA_VERIFY_WINDOW_US);
        }
    }
    return ESP_OK;
}


esp_err_t ota_upload_begin(size_t total_len, const char *sha256_hex)
{
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    esp_err_t err = ESP_OK;

    if (s_busy) { set_err("busy"); err = ESP_ERR_INVALID_STATE; goto out; }

    s_update = esp_ota_get_next_update_partition(NULL);
    if (!s_update) { set_err("no_ota_partition"); err = ESP_ERR_NOT_FOUND; goto out; }

    if (total_len && total_len > s_update->size) {
        set_err("image_too_large");
        err = ESP_ERR_INVALID_SIZE;
        goto out;
    }

    err = esp_ota_begin(s_update, total_len ? total_len : OTA_SIZE_UNKNOWN, &s_handle);
    if (err != ESP_OK) { set_err("ota_begin_failed"); goto out; }

    s_written = 0;
    s_total   = total_len;
    s_sha_on  = false;
    s_sha_expect[0] = '\0';
    s_err[0] = '\0';

    if (sha256_hex && strlen(sha256_hex) == 64) {
        strlcpy(s_sha_expect, sha256_hex, sizeof(s_sha_expect));
        mbedtls_sha256_init(&s_sha);
        mbedtls_sha256_starts(&s_sha, 0);
        s_sha_on = true;
    }
    s_busy = true;

out:
    if (s_mtx) xSemaphoreGive(s_mtx);
    return err;
}

esp_err_t ota_upload_write(const void *data, size_t len)
{
    if (!s_busy || s_handle == 0) return ESP_ERR_INVALID_STATE;
    esp_err_t e = esp_ota_write(s_handle, data, len);
    if (e != ESP_OK) {
        set_err("flash_write_failed");
        return e;
    }
    if (s_sha_on) mbedtls_sha256_update(&s_sha, (const unsigned char *)data, len);
    s_written += len;
    return ESP_OK;
}

esp_err_t ota_upload_end(bool commit)
{
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
    esp_err_t err = ESP_OK;

    if (!s_busy) { err = ESP_ERR_INVALID_STATE; goto out; }

    if (!commit) {
        esp_ota_abort(s_handle);
        s_handle = 0;
        s_busy   = false;
        if (s_sha_on) { mbedtls_sha256_free(&s_sha); s_sha_on = false; }
        set_err("aborted");
        err = ESP_ERR_INVALID_STATE;
        goto out;
    }

    /* esp_ota_end 会解包并校验镜像 (magic / checksum / 段完整性).
     * 校验不过的固件不会被设成启动分区. */
    err = esp_ota_end(s_handle);
    s_handle = 0;
    s_busy   = false;

    if (err != ESP_OK) {
        set_err(err == ESP_ERR_OTA_VALIDATE_FAILED ? "image_validate_failed"
                                                   : "ota_end_failed");
        if (s_sha_on) { mbedtls_sha256_free(&s_sha); s_sha_on = false; }
        goto out;
    }

    if (s_sha_on) {
        unsigned char digest[32];
        char got[65];
        mbedtls_sha256_finish(&s_sha, digest);
        mbedtls_sha256_free(&s_sha);
        s_sha_on = false;
        for (int i = 0; i < 32; i++) snprintf(got + i * 2, 3, "%02x", digest[i]);
        if (strcasecmp(got, s_sha_expect) != 0) {
            /* 镜像本身通过 IDF 校验, 但与提供的摘要不符 -> 拒绝切换 */
            set_err("sha256_mismatch");
            err = ESP_ERR_INVALID_CRC;
            goto out;
        }
    }

    err = esp_ota_set_boot_partition(s_update);
    if (err != ESP_OK) {
        set_err("set_boot_partition_failed");
        goto out;
    }

    printf("META,OTA,UPLOAD,DONE,slot,%s,bytes,%u\n",
           s_update ? s_update->label : "?", (unsigned)s_written);
    fflush(stdout);

out:
    if (s_mtx) xSemaphoreGive(s_mtx);
    return err;
}


int ota_url(const char *url)
{
    if (!url || !*url) {
        printf("META,OTA,ERR,msg,need_url\n");
        fflush(stdout);
        return 1;
    }
    if (strncmp(url, "http://", 7) != 0) {
        /* 本版刻意不链 TLS: mbedtls 的静态缓冲会挤掉 NimBLE 需要的内部 RAM,
         * 表现为 BLE 广播 BLE_ERR_MEM_CAPACITY. 局域网升级用 http 即可. */
        printf("META,OTA,ERR,msg,only_http_supported (build without TLS)\n");
        fflush(stdout);
        return 1;
    }

    const esp_partition_t *upd = esp_ota_get_next_update_partition(NULL);
    if (!upd) {
        printf("META,OTA,ERR,msg,no_ota_partition\n");
        fflush(stdout);
        return 1;
    }

    printf("META,OTA,URL,START,slot,%s,url,%s\n", upd->label, url);
    fflush(stdout);
    event_publish("OTA", "url start %s", url);

    esp_ota_handle_t h = 0;
    esp_err_t e = esp_ota_begin(upd, OTA_SIZE_UNKNOWN, &h);
    if (e != ESP_OK) {
        printf("META,OTA,ERR,msg,begin_failed,%s\n", esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = 15000,
        .keep_alive_enable = false,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) {
        esp_ota_abort(h);
        printf("META,OTA,ERR,msg,http_init_failed\n");
        fflush(stdout);
        return 1;
    }

    bool ok = false;
    int total = 0;
    if (esp_http_client_open(c, 0) == ESP_OK) {
        int clen = esp_http_client_fetch_headers(c);       /* <0 表示失败 */
        int status = esp_http_client_get_status_code(c);
        if (status == 200) {
            char buf[1024];
            int r;
            while ((r = esp_http_client_read(c, buf, sizeof(buf))) > 0) {
                if (esp_ota_write(h, buf, (size_t)r) != ESP_OK) { ok = false; total = -1; break; }
                total += r;
            }
            if (total > 0 && r == 0) ok = true;
            (void)clen;
        }
    }

    esp_http_client_close(c);
    esp_http_client_cleanup(c);

    if (!ok) {
        esp_ota_abort(h);
        printf("META,OTA,ERR,msg,download_failed,bytes,%d\n", total);
        fflush(stdout);
        return 1;
    }

    e = esp_ota_end(h);
    if (e != ESP_OK) {
        printf("META,OTA,ERR,msg,validate_failed,%s\n", esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }
    e = esp_ota_set_boot_partition(upd);
    if (e != ESP_OK) {
        printf("META,OTA,ERR,msg,set_boot_failed,%s\n", esp_err_to_name(e));
        fflush(stdout);
        return 1;
    }

    printf("META,OTA,URL,DONE,slot,%s,bytes,%d,msg,reboot_to_apply\n", upd->label, total);
    fflush(stdout);
    event_publish("OTA", "url done %d bytes", total);
    return 0;
}
