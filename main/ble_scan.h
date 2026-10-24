/*
 * ble_scan.h: 板子侧 BLE 近邻扫描 (observer 角色)
 *
 * 注意区分两个不同的"扫描":
 *   · App 里的「扫描设备」是手机扫 BLE, 找 rftool-c5 建立控制链;
 *   · 这里是板子自己当 observer 扫周围, 列出第三方 BLE 设备.
 * 板子的控制广播会一直保持, 扫描与之并存 (NimBLE 支持同时广播+扫描).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#define BLE_SCAN_MAX 48

esp_err_t ble_scan_start(void);
esp_err_t ble_scan_stop(void);
bool      ble_scan_is_on(void);
void      ble_scan_clear(void);
int       ble_scan_count(void);

/* 取第 i 条 (按 RSSI 降序). 出参可为 NULL. 越界返回 false */
bool ble_scan_get(int i, uint8_t addr[6], int8_t *rssi, const char **name);
