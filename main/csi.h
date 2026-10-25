/*
 * csi.h: Wi-Fi CSI 采集与动作检测
 *
 * CSI (Channel State Information) 是每个子载波的复数信道响应. 人走动会改变
 * 多径, 子载波幅度跟着抖动; 静止时只剩噪声. 这里只做幅度域, 相位不做处理
 * (没有校准, 相位随采样时刻旋转, 直接算没有意义).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* 懒初始化: 第一次 start 时分配 PSRAM 环并建任务 */
esp_err_t csi_start(uint8_t ch);
esp_err_t csi_stop(void);
bool      csi_is_on(void);

/* 打印累计统计 (帧数 / 速率 / 子载波数 / 首字无效比例 / 源 MAC 数) */
void csi_stats(void);

/* 合成序列自检: 验证归一化与判定链路, 不验真实人体检出率 */
void csi_selftest(void);

/* 让任务把接下来 n 帧原始 CSI 打成 hex (离线核对幅度用) */
void csi_raw(int n);
