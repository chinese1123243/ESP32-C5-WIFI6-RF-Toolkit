/* 802.15.4 组帧. 只做字节拼装, 不碰射频:
 * 随机 PAN 走 radio_hal, 于是本文件能在主机上编, 用 mock 喂固定随机数. */

#include "zbtx_frame.h"

#include <stddef.h>

#include "radio_hal.h"

static int put_fcf(uint8_t *o, uint16_t fcf)
{
    o[0] = (uint8_t)(fcf & 0xFF);
    o[1] = (uint8_t)(fcf >> 8);
    return 2;
}

int zbtx_build_beacon(uint8_t *out, int cap, uint16_t pan, uint8_t ch, uint8_t seq)
{
    if (cap < 1 + 11 + 15) return 0;
    if (pan == 0) {
        /* 随机数走 HAL: 组帧要在主机上可复现, 不能直调 esp_random */
        uint8_t rb[2];
        radio_hal()->random_bytes(rb, 2);
        pan = (uint16_t)(rb[0] | ((uint16_t)rb[1] << 8));
    }
    if (pan == 0xFFFF) pan = 0xFFFE;      /* 广播 PAN 不能当协调器 */

    /* [0] 留给长度前缀, 内容从 1 开始写 */
    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_BEACON) | FCF_SRC_MODE(AM_SHORT));
    out[n++] = seq;
    out[n++] = (uint8_t)(pan & 0xFF);      /* src PAN (beacon 无 dst, 压缩位必须为 0) */
    out[n++] = (uint8_t)(pan >> 8);
    out[n++] = 0x00;                       /* src short addr = 0 (协调器) */
    out[n++] = 0x00;

    /* superframe: BO=15, SO=15, PAN coord=1, assoc permit=1 */
    out[n++] = 0xFF;
    out[n++] = 0xCF;
    out[n++] = 0x00;                       /* GTS: 无 */
    out[n++] = 0x00;                       /* Pending addr: 无 */

    /* Zigbee NWK beacon payload */
    out[n++] = ZB_PROTO_ID;
    out[n++] = ZB_STACK_PROFILE;
    out[n++] = 0x05;                       /* 容量: depth 1, router cap 1 */
    for (int i = 0; i < 8; i++) out[n++] = (uint8_t)(0x10 + i);   /* 扩展 PAN ID */
    out[n++] = 0x00;                       /* Tx offset (3 字节) */
    out[n++] = 0x00;
    out[n++] = 0x00;
    out[n++] = 0x00;                       /* Update ID */

    out[0] = (uint8_t)(n - 1);             /* 长度不含自身, 不含 FCS */
    (void)ch;
    return n;
}

int zbtx_build_beacon_req(uint8_t *out, int cap, uint16_t pan, uint8_t seq)
{
    if (cap < 1 + 10) return 0;

    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_MAC_CMD) | FCF_DST_MODE(AM_SHORT) |
                            FCF_SRC_MODE(AM_SHORT) | FCF_PAN_COMP);
    out[n++] = seq;
    /* dst PAN 用 0xFFFF (广播), 压缩位为 1 意味着 src PAN 与 dst 相同, 不再重复 */
    out[n++] = 0xFF;
    out[n++] = 0xFF;
    out[n++] = 0xFF;                       /* dst short = 广播 */
    out[n++] = 0xFF;
    out[n++] = 0x34;                       /* src short (随便给一个) */
    out[n++] = 0x12;
    out[n++] = 0x07;                       /* cmd id 7 = Beacon Request */

    out[0] = (uint8_t)(n - 1);
    (void)pan;
    return n;
}

int zbtx_build_data(uint8_t *out, int cap, uint16_t dst_pan, uint16_t dst,
                    uint16_t src_pan, uint16_t src,
                    const uint8_t *payload, int plen, uint8_t seq)
{
    if (cap < 1 + 9 + plen) return 0;
    if (plen < 0) plen = 0;
    if (plen > ZBTX_FRAME_MAX - 10) plen = ZBTX_FRAME_MAX - 10;

    int n = 1;
    n += put_fcf(out + n, FCF_TYPE(FT_DATA) | FCF_DST_MODE(AM_SHORT) |
                            FCF_SRC_MODE(AM_SHORT) | FCF_PAN_COMP);
    out[n++] = seq;
    out[n++] = (uint8_t)(dst_pan & 0xFF);
    out[n++] = (uint8_t)(dst_pan >> 8);
    out[n++] = (uint8_t)(dst & 0xFF);
    out[n++] = (uint8_t)(dst >> 8);
    out[n++] = (uint8_t)(src & 0xFF);      /* 压缩位为 1: src PAN 省略, 视为与 dst 相同 */
    out[n++] = (uint8_t)(src >> 8);
    (void)src_pan;
    for (int i = 0; i < plen; i++) out[n++] = payload[i];

    out[0] = (uint8_t)(n - 1);
    return n;
}

