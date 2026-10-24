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

# ===== 编译选项 =====
# 只留 3 个, 理由见下.
#
# 【这 3 个为什么留】
#   实测 (riscv32-esp-elf-gcc 14.2, esp-14.2.0_20251107, 本工程 73 条命令全量构建)
#   带来的收益很小, 但它们都是"少做点事"型开关, 不拖慢编译:
#     -fno-tree-vectorize              关掉向量化 pass
#     -fno-tree-loop-distribute-patterns  关掉循环分布(会展开成 memset/memcpy 调用)
#     -freorder-blocks-algorithm=simple   用简单块重排, 输出更可预测
#
# 【这 3 个为什么单独验证过】
#   逐个喂给 gcc 试过编译期 + 链接期, 全部接受.
#
# 【试过又拿掉, 别再加回来的】
#   -fno-unique-section-names
#       唯一真被这个工具链拒绝的: unrecognized command-line option.
#       省内联重复代码的思路在这条工具链上走不通.
#
#   -Wsuggest-attribute=pure / const / returns_nonnull / malloc / cold / format / noreturn
#   -Wsuggest-final-types / -Wsuggest-final-methods
#       编译器全都接受 (不是被拒, 别记错), 但代价是实测 2 倍编译时间:
#         带这 9 个  : 405.67s
#         去掉这 9 个: 199.20s   (快 2.04 倍)
#       换来的尺寸收益 0.10%, 明显不划算.
#       两个 -Wsuggest-final-* 还额外要求开 LTO 才有意义,
#       而本工程试过 -flto: 链接期 strip 报 no input file / 直接失败, 用不了.
#
#   -fira-region=mixed / -fira-hoist-pressure / -fstdarg-opt / -fipa-sra / -ftree-partial-pre / -fipa-pta
#       这组在实测里最有效 (再压 5.68%, 约 89KB), 但会明显拖慢编译.
#       当前 0x180e80 只占分区 40%, 还远没到要拿编译时间去换空间的时候.
#       真到分区紧张那天, 按上面顺序往上加, 每加一个量一次时间和尺寸.
#
# -fstack-protector 交给另一处单独处理, 这里刻意不写, 免得两处给值打架.
idf_build_set_property(COMPILE_OPTIONS
    "-fno-tree-vectorize"
    "-fno-tree-loop-distribute-patterns"
    "-freorder-blocks-algorithm=simple"
    APPEND
)
