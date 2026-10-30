/* EAPOL-Key 的纯解析部分. 不依赖 ESP-IDF, 主机端可直接编译测试.
 * 抓包回调里调用的东西必须能在 PC 上复现, 否则 KeyInfo 位这种错只能靠上板碰运气. */

#include "eapol_core.h"

#include <string.h>

int eapol_msg_no(uint16_t ki)
{
    bool ack = (ki & EAPOL_KI_ACK) != 0;
    bool mic = (ki & EAPOL_KI_MIC) != 0;
    bool sec = (ki & EAPOL_KI_SECURE) != 0;

    if (ack && !mic) return 1;   /* M1: AP->STA, 只带 ANonce */
    if (ack && mic)  return 3;   /* M3: AP->STA, 带 MIC */
    if (mic && !sec) return 2;   /* M2: STA->AP, 带 SNonce + MIC */
    if (mic && sec)  return 4;   /* M4: STA->AP, 确认 */
    return 0;
}

bool eapol_extract_pmkid(const uint8_t *eapol, int len, uint8_t out[16])
{
    if (!eapol || !out || len <= EAPOL_KD_OFF) return false;

    int p = EAPOL_KD_OFF;
    while (p + 2 <= len) {
        uint8_t t = eapol[p], l = eapol[p + 1];
        if (p + 2 + l > len) break;          /* 长度谎报, 不越界 */
        if (t == 0xDD && l >= 20 &&
            eapol[p + 2] == 0x00 && eapol[p + 3] == 0x0F &&
            eapol[p + 4] == 0xAC && eapol[p + 5] == 0x04) {
            memcpy(out, eapol + p + 6, 16);
            return true;
        }
        p += 2 + l;
    }
    return false;
}
