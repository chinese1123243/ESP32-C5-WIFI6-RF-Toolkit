#pragma once

#include <stdbool.h>
#include <stdint.h>

/* EAPOL-Key KeyInfo 位 (802.11-2016 图 12-32).
 * 注意 0x0008 是 Key Type (pairwise=1/group=0), 不是 MIC.
 * 历史上这里错过一次: MIC 被写成 0x0008, 真实 M1 一直被当成 M3. */
#define EAPOL_KI_KEYTYPE 0x0008
#define EAPOL_KI_ACK     0x0080
#define EAPOL_KI_MIC     0x0100
#define EAPOL_KI_SECURE  0x0200

/* EAPOL 头 4 字节 + EAPOL-Key 固定部分 95 字节, Key Data 从这里开始 */
#define EAPOL_KD_OFF 99

/* KeyInfo -> 消息号 1/2/3/4; 认不出返回 0.
 * M1: ACK 且无 MIC (只带 ANonce)
 * M3: ACK 且带 MIC
 * M2: 带 MIC 且未置 SECURE
 * M4: 带 MIC 且置 SECURE */
int eapol_msg_no(uint16_t keyinfo);

/* 在 EAPOL-Key 的 Key Data 里找 PMKID KDE (DD 00 0F AC 04), 找到拷 16 字节到 out.
 * 越界一律返回 false, 不做部分拷贝. */
bool eapol_extract_pmkid(const uint8_t *eapol, int len, uint8_t out[16]);
