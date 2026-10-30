#pragma once

/* 主机端最小桩: 只为让不依赖 ESP 的纯逻辑文件能编译.
 * 这里只放纯逻辑真正用到的类型与常量, 不放任何实现.
 * 加新符号前先问一句: 这个文件本该依赖 ESP 吗? 该的话应该拆出去, 不要往这儿堆. */

typedef int esp_err_t;

#define ESP_OK   0
#define ESP_FAIL (-1)

#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE  0x104
