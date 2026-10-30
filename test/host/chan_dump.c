#include <stdio.h>

#include "chan_sched.h"

/* 把 chan_dwell_psd 在给定网格上的输出打成 CSV, 供 chan_cross.py 与
 * chan_sim.py 的公式逐点比对. 只覆盖 found>0 的正常分配段:
 * visits==0 的"首轮给 base"是固件的检出率保护, 仿真器没有对应分支. */
int main(void)
{
    const unsigned bases[] = {150, 300, 600, 1000, 1500};
    const unsigned n = 41;

    printf("base,found,total,n,dwell\n");
    for (unsigned bi = 0; bi < sizeof(bases) / sizeof(bases[0]); bi++) {
        unsigned base = bases[bi];
        for (unsigned found = 1; found <= 50; found++) {
            unsigned totals[] = {found * n, 410, 820};
            for (unsigned ti = 0; ti < 3; ti++) {
                unsigned total = totals[ti];
                if (total == 0) continue;
                unsigned d = chan_dwell_psd(base, found, total, 1, n);
                printf("%u,%u,%u,%u,%u\n", base, found, total, n, d);
            }
        }
    }
    return 0;
}
