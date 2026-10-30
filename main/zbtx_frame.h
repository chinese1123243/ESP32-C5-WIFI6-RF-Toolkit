#pragma once

#include <stdint.h>
#include "zbtx.h"

/* FCF 位, 802.15.4-2003 (Zigbee 用的版本 0) */
#define FCF_TYPE(t)       ((uint16_t)((t) & 0x7))
#define FCF_DST_MODE(m)   ((uint16_t)(((m) & 0x3) << 10))
#define FCF_SRC_MODE(m)   ((uint16_t)(((m) & 0x3) << 14))
#define FCF_PAN_COMP      (1u << 6)

#define FT_BEACON     0
#define FT_DATA       1
#define FT_MAC_CMD    3

#define AM_NONE   0
#define AM_SHORT  2
#define AM_EXT    3

/* Zigbee NWK beacon payload: 协议ID + 版本/Profile + 容量 + 扩展PAN + TxOffset + UpdateId */
#define ZB_PROTO_ID        0x00
#define ZB_STACK_PROFILE   0x12   /* 版本 2, profile 1 (Zigbee) */

int zbtx_build_beacon(uint8_t *out, int cap, uint16_t pan, uint8_t ch, uint8_t seq);
int zbtx_build_beacon_req(uint8_t *out, int cap, uint16_t pan, uint8_t seq);
int zbtx_build_data(uint8_t *out, int cap, uint16_t dst_pan, uint16_t dst,
                    uint16_t src_pan, uint16_t src,
                    const uint8_t *payload, int plen, uint8_t seq);
