/*
 * version.h: 固件版本单一来源
 *
 * 之前 version 命令里硬编码 "2.1.0", 而 App 已经是 2.3.0, 手机端" 连接信息"
 * 页显示的固件版本与真实镜像对不上, OTA 后也看不出到底切没切过去.
 * 改版本只需要改这里一处.
 *
 * 与之对应: app/app.js 里的 APP_VERSION. 两者不要求相等 (App 可以比固件新),
 * 但固件号必须真实, 否则现场排障时拿到的一手信息就是错的.
 */
#pragma once

#define RFTOOL_VERSION "2.4.6"
