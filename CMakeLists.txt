# ESP32-C5 Wi-Fi 无线电攻击工具 (rftool)
# ESP-IDF v5.5.x, target=esp32c5
# 控制台: UART0 (经 H2 口 CH343P 桥接, 避开原生 USB-Serial/JTAG CDC 卡死问题)
cmake_minimum_required(VERSION 3.16)

# 支持 out-of-tree 构建: 自动定位 ESP-IDF
if(NOT IDF_PATH)
    if(DEFINED ENV{IDF_PATH})
        set(IDF_PATH $ENV{IDF_PATH})
    else()
        set(IDF_PATH "D:/Espressif/frameworks/esp-idf-v5.5.3")
    endif()
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(rftool)
