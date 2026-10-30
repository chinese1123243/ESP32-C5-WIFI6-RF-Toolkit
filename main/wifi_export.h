#pragma once

#include <stddef.h>

#include "wifi_db.h"

/* 导出的一行. 768 足够: AP 行最长约 150 字节, 客户端行带 16 个 RSSI 约 220.
 * 行布局放在这里而不是 wifi_db.c, 是为了能在主机上比对完整字符串:
 * 列顺序、引号、true/false 这类错误在真机上只能靠肉眼看。 */
#define WIFI_EXPORT_LINE_MAX 512

void wifi_export_csv_ap(const ap_entry_t *e, char *out, size_t cap);
void wifi_export_csv_client(const client_entry_t *c, char *out, size_t cap);
void wifi_export_csv_eapol(const eapol_entry_t *e, char *out, size_t cap);

void wifi_export_json_ap(const ap_entry_t *e, char *out, size_t cap);
void wifi_export_json_client(const client_entry_t *c, char *out, size_t cap);
void wifi_export_json_eapol(const eapol_entry_t *e, char *out, size_t cap);
